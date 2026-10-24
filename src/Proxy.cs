using System;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;

namespace VpnKeeper
{
    // A small HTTP proxy for browsers: CONNECT for https, absolute URLs for
    // http. Names are resolved here, on the VPN side, so internal names work.
    // It serves only the 'clients' networks and reaches only the 'allow' list,
    // so it is not an open door into the company network.
    //
    //   /proxy.pac   browser auto-configuration, generated from 'allow'
    //   /health      VPN state, last login, last error
    class Proxy
    {
        readonly int port;
        readonly Rules clients, allow;
        readonly Func<string> health;
        TcpListener listener;
        volatile bool stopped;

        public Proxy(int port, Rules clients, Rules allow, Func<string> health)
        {
            this.port = port;
            this.clients = clients;
            this.allow = allow;
            this.health = health;
        }

        public int Port { get { return ((IPEndPoint)listener.LocalEndpoint).Port; } }

        // Binds now (so a taken port is reported at once), then keeps the
        // listener alive: if it ever fails it is re-created.
        public void Start(string address = "0.0.0.0")
        {
            listener = new TcpListener(IPAddress.Parse(address), port);
            listener.Start(64);
            Log.Info("proxy on " + listener.LocalEndpoint + "; clients " + clients + "; allow " + allow);
            new Thread(AcceptLoop) { IsBackground = true, Name = "proxy" }.Start();
        }

        public void Stop()
        {
            stopped = true;
            listener.Stop();
        }

        void AcceptLoop()
        {
            while (!stopped)
            {
                try
                {
                    TcpClient c = listener.AcceptTcpClient();
                    new Thread(delegate() { Serve(c); }) { IsBackground = true, Name = "proxy-conn" }.Start();
                }
                catch (Exception e)
                {
                    if (stopped) return;
                    Log.Warn("proxy listener failed (" + e.Message + "); restarting it in 5 s");
                    Thread.Sleep(5000);
                    try
                    {
                        listener.Stop();
                        listener = new TcpListener(((IPEndPoint)listener.LocalEndpoint).Address, port);
                        listener.Start(64);
                    }
                    catch (Exception again) { Log.Warn("proxy restart failed: " + again.Message); }
                }
            }
        }

        void Serve(TcpClient client)
        {
            try { Handle(client); }
            catch (Exception e)
            {
                if (!(e is IOException || e is SocketException || e is ObjectDisposedException)) Log.Debug("proxy: " + e);
            }
            finally { client.Close(); }
        }

        void Handle(TcpClient client)
        {
            IPEndPoint from = (IPEndPoint)client.Client.RemoteEndPoint;
            string me = ((IPEndPoint)client.Client.LocalEndPoint).Address + ":" + Port;
            client.ReceiveTimeout = 30000;
            NetworkStream cs = client.GetStream();

            // Read the request first: closing a socket with unread input resets
            // it, and the client would never see the reply.
            byte[] buf = new byte[65536];
            int len = ReadHead(cs, buf);
            if (len <= 0) return;
            if (!clients.AllowsAddress(from.Address))
            {
                Log.Warn("proxy: refused client " + from.Address + " (not in 'clients')");
                Reply(cs, 403, "This client is not in the proxy's 'clients' list.\n");
                return;
            }
            int headEnd = IndexOf(buf, len, "\r\n\r\n");
            string[] lines = Encoding.ASCII.GetString(buf, 0, headEnd).Split(new[] { "\r\n" }, StringSplitOptions.None);
            string[] first = lines[0].Split(' ');
            if (first.Length != 3) { Reply(cs, 400, "Bad request line.\n"); return; }
            string method = first[0], target = first[1], version = first[2];

            if (target.StartsWith("/")) { Local(cs, method, target, me); return; }

            string host, path = null;
            int port;
            bool ok = method == "CONNECT" ? SplitHostPort(target, 443, out host, out port) : ParseAbsolute(target, out host, out port, out path);
            if (!ok) { Reply(cs, 400, "Only http:// URLs and CONNECT are supported.\n"); return; }

            IPAddress[] addrs;
            if (!allow.AllowsHost(host, out addrs))
            {
                Log.Info("proxy: " + host + " is not in 'allow'");
                Reply(cs, 403, host + " is not in the proxy's 'allow' list.\n");
                return;
            }

            using (TcpClient upstream = new TcpClient())
            {
                try
                {
                    if (addrs != null) upstream.Connect(addrs, port); else upstream.Connect(host, port);
                }
                catch (SocketException e)
                {
                    Log.Warn("proxy: " + host + ":" + port + " unreachable: " + e.Message);
                    Reply(cs, 502, host + ":" + port + " is unreachable (is the VPN up?)\n");
                    return;
                }
                NetworkStream us = upstream.GetStream();
                if (method == "CONNECT")
                {
                    Send(cs, version + " 200 Connection established\r\n\r\n");
                }
                else
                {
                    // Origin-form request line, proxy headers dropped, one request per connection.
                    StringBuilder sb = new StringBuilder(method + " " + path + " " + version + "\r\n");
                    for (int i = 1; i < lines.Length; i++)
                    {
                        string l = lines[i].ToLowerInvariant();
                        if (l.StartsWith("proxy-") || l.StartsWith("connection:") || l.StartsWith("keep-alive:")) continue;
                        sb.Append(lines[i]).Append("\r\n");
                    }
                    Send(us, sb.Append("Connection: close\r\n\r\n").ToString());
                }
                // Whatever followed the head (a TLS hello, a request body) goes up too.
                if (len > headEnd + 4) us.Write(buf, headEnd + 4, len - headEnd - 4);
                client.ReceiveTimeout = 0;
                Pump(cs, us);
            }
        }

        void Local(NetworkStream cs, string method, string target, string me)
        {
            string path = target.Split('?')[0];
            if (path == "/proxy.pac") Reply(cs, 200, allow.Pac(me), "application/x-ns-proxy-autoconfig");
            else if (path == "/health" || path == "/") Reply(cs, 200, "vpn-keeper\n" + health());
            else Reply(cs, 404, "Try /proxy.pac or /health.\n");
        }

        static void Pump(NetworkStream client, NetworkStream upstream)
        {
            Thread up = new Thread(delegate() { Copy(client, upstream); }) { IsBackground = true, Name = "proxy-up" };
            up.Start();
            Copy(upstream, client);
            up.Join(30000);
        }

        // Copies until either side closes, then closes both so the other copy ends too.
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
            to.Close();
            from.Close();
        }

        // Bytes read up to and past the end of the request head; 0 on EOF or a head over 64 KB.
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
            return 0;
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

        static void Reply(NetworkStream s, int code, string body, string type = "text/plain; charset=utf-8")
        {
            string reason = code == 200 ? "OK" : code == 400 ? "Bad Request" : code == 403 ? "Forbidden" : code == 404 ? "Not Found" : "Bad Gateway";
            byte[] b = Encoding.UTF8.GetBytes(body);
            Send(s, "HTTP/1.1 " + code + " " + reason + "\r\nContent-Type: " + type + "\r\nContent-Length: " + b.Length
                + "\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n");
            s.Write(b, 0, b.Length);
        }

        static void Send(Stream s, string text)
        {
            byte[] b = Encoding.ASCII.GetBytes(text);
            s.Write(b, 0, b.Length);
        }

        public static bool SplitHostPort(string s, int defaultPort, out string host, out int port)
        {
            host = s;
            port = defaultPort;
            string rest = "";
            if (s.StartsWith("["))
            {
                int close = s.IndexOf(']');
                if (close < 0) return false;
                host = s.Substring(1, close - 1);
                rest = s.Substring(close + 1);
            }
            else
            {
                int colon = s.LastIndexOf(':');
                if (colon >= 0) { host = s.Substring(0, colon); rest = s.Substring(colon); }
            }
            if (rest.Length > 0 && !(rest.StartsWith(":") && int.TryParse(rest.Substring(1), out port) && port > 0 && port < 65536)) return false;
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
            if (slash >= 0) path = rest.Substring(slash);
            int at = authority.LastIndexOf('@');
            if (at >= 0) authority = authority.Substring(at + 1);
            return SplitHostPort(authority, 80, out host, out port);
        }
    }
}
