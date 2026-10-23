using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;

namespace VpnKeeper
{
    // A small HTTP proxy for browsers: CONNECT for https, absolute URLs for
    // plain http. Names are resolved here, on the VPN side, so internal names
    // work. It only serves the 'clients' networks and only reaches the
    // 'allow' list, so it is not an open door into the company network.
    //
    // Requests to the proxy itself:
    //   /proxy.pac   browser auto-configuration
    //   /health      VPN state, last login, version
    class Proxy
    {
        readonly Rules clients;
        readonly Rules allow;
        readonly IPEndPoint endpoint;
        readonly Func<string> health;
        TcpListener listener;

        public Proxy(string listen, Rules clients, Rules allow, Func<string> health)
        {
            this.clients = clients;
            this.allow = allow;
            this.health = health;
            endpoint = ParseEndpoint(listen);
        }

        public int Port { get { return ((IPEndPoint)listener.LocalEndpoint).Port; } }

        public void Start()
        {
            listener = new TcpListener(endpoint);
            listener.Start(64);
            Log.Info("proxy listening on " + listener.LocalEndpoint + ", clients " + string.Join(" ", clients.Source.ToArray())
                + ", allowed " + string.Join(" ", allow.Source.ToArray()));
            Thread t = new Thread(AcceptLoop) { IsBackground = true, Name = "proxy-accept" };
            t.Start();
        }

        public void Stop()
        {
            if (listener != null) listener.Stop();
        }

        void AcceptLoop()
        {
            while (true)
            {
                TcpClient c;
                try { c = listener.AcceptTcpClient(); }
                catch (SocketException) { return; }
                catch (ObjectDisposedException) { return; }
                catch (InvalidOperationException) { return; }   // stopped before this thread got here
                Thread t = new Thread(delegate() { Serve(c); }) { IsBackground = true, Name = "proxy-conn" };
                t.Start();
            }
        }

        void Serve(TcpClient client)
        {
            IPEndPoint from = (IPEndPoint)client.Client.RemoteEndPoint;
            localAddress = ((IPEndPoint)client.Client.LocalEndPoint).Address.ToString();
            try
            {
                client.ReceiveTimeout = 30000;
                NetworkStream cs = client.GetStream();
                // Read the request before any reply: closing a socket with unread
                // input resets the connection and the client never sees the reply.
                byte[] buf = new byte[65536];
                int len = ReadHead(cs, buf);
                if (len <= 0) return;
                if (!clients.AllowsAddress(from.Address))
                {
                    Log.Warn("proxy: refused client " + from.Address);
                    Reply(cs, 403, "Forbidden", "This client is not in the proxy's 'clients' list.\n");
                    return;
                }
                int headEnd = IndexOf(buf, len, "\r\n\r\n");
                string head = Encoding.ASCII.GetString(buf, 0, headEnd);
                string[] lines = head.Split(new[] { "\r\n" }, StringSplitOptions.None);
                string[] first = lines[0].Split(' ');
                if (first.Length != 3) { Reply(cs, 400, "Bad Request", "Bad request line.\n"); return; }
                string method = first[0], target = first[1], version = first[2];

                if (target.StartsWith("/"))
                {
                    Local(cs, method, target);
                    return;
                }

                string host;
                int port;
                string path;
                if (method == "CONNECT")
                {
                    if (!SplitHostPort(target, 443, out host, out port)) { Reply(cs, 400, "Bad Request", "Bad CONNECT target.\n"); return; }
                    path = null;
                }
                else if (!ParseAbsolute(target, out host, out port, out path))
                {
                    Reply(cs, 400, "Bad Request", "Only http:// URLs and CONNECT are supported.\n");
                    return;
                }

                IPAddress[] addrs;
                if (!allow.AllowsHost(host, out addrs))
                {
                    Log.Info("proxy: " + from.Address + " -> " + host + ":" + port + " not in the allow list");
                    Reply(cs, 403, "Forbidden", host + " is not in the proxy's 'allow' list.\n");
                    return;
                }

                TcpClient upstream = new TcpClient();
                try
                {
                    if (addrs != null) upstream.Connect(addrs, port); else upstream.Connect(host, port);
                }
                catch (SocketException e)
                {
                    Log.Warn("proxy: " + host + ":" + port + " unreachable: " + e.Message);
                    Reply(cs, 502, "Bad Gateway", host + ":" + port + " is unreachable (is the VPN up?)\n");
                    upstream.Close();
                    return;
                }

                using (upstream)
                {
                    NetworkStream us = upstream.GetStream();
                    if (method == "CONNECT")
                    {
                        byte[] ok = Encoding.ASCII.GetBytes(version + " 200 Connection established\r\n\r\n");
                        cs.Write(ok, 0, ok.Length);
                        // Anything the client sent after the CONNECT head (TLS hello) goes up too.
                        if (len > headEnd + 4) us.Write(buf, headEnd + 4, len - headEnd - 4);
                    }
                    else
                    {
                        // Origin-form request line, no proxy headers, one request per connection.
                        StringBuilder sb = new StringBuilder();
                        sb.Append(method).Append(' ').Append(path).Append(' ').Append(version).Append("\r\n");
                        for (int i = 1; i < lines.Length; i++)
                        {
                            string l = lines[i].ToLowerInvariant();
                            if (l.StartsWith("proxy-connection:") || l.StartsWith("proxy-authorization:") || l.StartsWith("connection:")
                                || l.StartsWith("keep-alive:")) continue;
                            sb.Append(lines[i]).Append("\r\n");
                        }
                        sb.Append("Connection: close\r\n\r\n");
                        byte[] h = Encoding.ASCII.GetBytes(sb.ToString());
                        us.Write(h, 0, h.Length);
                        if (len > headEnd + 4) us.Write(buf, headEnd + 4, len - headEnd - 4);
                    }
                    client.ReceiveTimeout = 0;
                    Pump(cs, us);
                }
            }
            catch (IOException) { }
            catch (SocketException) { }
            catch (ObjectDisposedException) { }
            finally
            {
                client.Close();
            }
        }

        void Local(NetworkStream cs, string method, string target)
        {
            string path = target.Split('?')[0];
            if (method != "GET" && method != "HEAD") { Reply(cs, 405, "Method Not Allowed", "GET only.\n"); return; }
            if (path == "/proxy.pac" || path == "/wpad.dat")
            {
                string me = HostForPac();
                Reply(cs, 200, "OK", allow.Pac(me), "application/x-ns-proxy-autoconfig");
            }
            else if (path == "/health" || path == "/")
            {
                Reply(cs, 200, "OK", "vpn-keeper\n" + health());
            }
            else Reply(cs, 404, "Not Found", "Try /proxy.pac or /health.\n");
        }

        // The PAC must name an address the browser can reach: the one this
        // request arrived on is the safest guess.
        [ThreadStatic] static string localAddress;

        string HostForPac()
        {
            return (localAddress ?? endpoint.Address.ToString()) + ":" + Port;
        }

        static void Pump(NetworkStream a, NetworkStream b)
        {
            Thread up = new Thread(delegate() { Copy(a, b); }) { IsBackground = true, Name = "proxy-up" };
            up.Start();
            Copy(b, a);
            up.Join(30000);
        }

        static void Copy(NetworkStream from, NetworkStream to)
        {
            byte[] buf = new byte[32768];
            try
            {
                int n;
                while ((n = from.Read(buf, 0, buf.Length)) > 0) to.Write(buf, 0, n);
            }
            catch (IOException) { }
            catch (ObjectDisposedException) { }
            // Half-close so the other direction sees the end too.
            try { to.Close(); } catch (IOException) { }
            try { from.Close(); } catch (IOException) { }
        }

        // Reads until the end of the request head; returns bytes read (head plus
        // anything already following it), 0 on EOF, -1 if the head is too large.
        static int ReadHead(NetworkStream s, byte[] buf)
        {
            int len = 0;
            while (len < buf.Length)
            {
                int n = s.Read(buf, len, buf.Length - len);
                if (n <= 0) return 0;
                len += n;
                if (IndexOf(buf, len, "\r\n\r\n") >= 0) return len;
            }
            return -1;
        }

        static int IndexOf(byte[] buf, int len, string pattern)
        {
            for (int i = 0; i + pattern.Length <= len; i++)
            {
                int j = 0;
                while (j < pattern.Length && buf[i + j] == pattern[j]) j++;
                if (j == pattern.Length) return i;
            }
            return -1;
        }

        static void Reply(NetworkStream s, int code, string reason, string body, string type = "text/plain; charset=utf-8")
        {
            byte[] b = Encoding.UTF8.GetBytes(body);
            byte[] h = Encoding.ASCII.GetBytes("HTTP/1.1 " + code + " " + reason + "\r\nContent-Type: " + type
                + "\r\nContent-Length: " + b.Length + "\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n");
            s.Write(h, 0, h.Length);
            s.Write(b, 0, b.Length);
        }

        public static bool SplitHostPort(string s, int defaultPort, out string host, out int port)
        {
            host = s;
            port = defaultPort;
            if (s.StartsWith("["))
            {
                int close = s.IndexOf(']');
                if (close < 0) return false;
                host = s.Substring(1, close - 1);
                string rest = s.Substring(close + 1);
                if (rest.Length == 0) return true;
                return rest.StartsWith(":") && int.TryParse(rest.Substring(1), out port) && port >= 0 && port < 65536;
            }
            int colon = s.LastIndexOf(':');
            if (colon >= 0)
            {
                host = s.Substring(0, colon);
                if (!int.TryParse(s.Substring(colon + 1), out port) || port < 0 || port > 65535) return false;   // 0 = any free port
            }
            return host.Length > 0;
        }

        public static bool ParseAbsolute(string url, out string host, out int port, out string path)
        {
            host = null;
            port = 80;
            path = "/";
            if (!url.StartsWith("http://", StringComparison.OrdinalIgnoreCase)) return false;
            string rest = url.Substring(7);
            int slash = rest.IndexOf('/');
            string authority = slash < 0 ? rest : rest.Substring(0, slash);
            path = slash < 0 ? "/" : rest.Substring(slash);
            int at = authority.LastIndexOf('@');
            if (at >= 0) authority = authority.Substring(at + 1);
            return SplitHostPort(authority, 80, out host, out port);
        }

        static IPEndPoint ParseEndpoint(string s)
        {
            string host;
            int port;
            if (!SplitHostPort(s, 8080, out host, out port)) throw new FormatException("bad listen address '" + s + "'");
            IPAddress ip;
            if (host == "*" || host == "") ip = IPAddress.Any;
            else if (!IPAddress.TryParse(host, out ip)) throw new FormatException("listen must be an IP:port, got '" + s + "'");
            return new IPEndPoint(ip, port);
        }
    }
}
