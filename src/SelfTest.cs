using System;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;

namespace VpnKeeper
{
    // vpn-keeper.exe selftest [<fake SnwlConnect.exe>]
    // Without the fake client only the offline tests run, so it is safe on the
    // real laptop. CI passes the fake (tests/FakeSnwlConnect.cs) to also test
    // the login against windows shaped like the real ones.
    static class SelfTest
    {
        static int failed, passed;

        public static int Run(string fakeClient = null)
        {
            Console.WriteLine("vpn-keeper " + BuildInfo.Version + " self-test");
            Section("TOTP", TestTotp);
            Section("status captions", TestClassify);
            Section("allow lists and PAC", TestRules);
            Section("request parsing", TestParsing);
            Section("config file", TestConfig);
            Section("proxy over real sockets", TestProxy);
            if (fakeClient != null) Section("login against the fake Connect Tunnel", delegate { TestLogin(fakeClient); });
            else Console.WriteLine("(login test skipped: pass the fake SnwlConnect.exe to run it)");
            Console.WriteLine(passed + " passed, " + failed + " failed");
            return failed == 0 ? 0 : 1;
        }

        static void Section(string name, Action body)
        {
            Console.WriteLine("== " + name);
            try { body(); }
            catch (Exception e) { Fail("threw " + e); }
        }

        static void Check(bool ok, string what)
        {
            if (ok) passed++; else Fail(what);
        }

        static void Equal(object expected, object actual, string what)
        {
            if (Equals(expected, actual)) passed++;
            else Fail(what + ": expected <" + expected + "> got <" + actual + ">");
        }

        static void Fail(string what)
        {
            failed++;
            Console.WriteLine("  FAIL " + what);
        }

        static void TestTotp()
        {
            // RFC 6238 appendix B, SHA-1, 8 digits.
            byte[] key = Encoding.ASCII.GetBytes("12345678901234567890");
            long[] times = { 59, 1111111109, 1111111111, 1234567890, 2000000000, 20000000000 };
            string[] codes = { "94287082", "07081804", "14050471", "89005924", "69279037", "65353130" };
            for (int i = 0; i < times.Length; i++)
                Equal(codes[i], Totp.Code(key, times[i] / 30, 8), "RFC 6238 T=" + times[i]);
            Equal("287082", Totp.Code(key, 59 / 30, 6), "6 digits");

            Equal(Encoding.ASCII.GetString(key), Encoding.ASCII.GetString(Totp.Base32Decode("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ")), "base32");
            Equal(Encoding.ASCII.GetString(key), Encoding.ASCII.GetString(Totp.Base32Decode("gezd gnbv gy3t qojq gezd gnbv gy3t qojq")), "base32 spaced lower");
            Equal("Hello!Þ­¾ï", Encoding.GetEncoding(28591).GetString(Totp.Base32Decode("JBSWY3DPEHPK3PXP")), "base32 classic");
            Check(Throws(delegate { Totp.Base32Decode("not base32!"); }), "bad base32 rejected");
            Check(Throws(delegate { Totp.Base32Decode("  "); }), "empty seed rejected");

            DateTime t = new DateTime(2026, 1, 1, 0, 0, 25, DateTimeKind.Utc);
            Equal(5, Totp.SecondsLeft(t, 30), "seconds left");
        }

        static void TestClassify()
        {
            Equal(VpnState.Up, Tunnel.Classify("Connected"), "Connected");
            Equal(VpnState.Down, Tunnel.Classify("Disconnected"), "Disconnected");
            Equal(VpnState.Busy, Tunnel.Classify("Connecting..."), "Connecting...");
            Equal(VpnState.Busy, Tunnel.Classify("Reconnecting..."), "Reconnecting...");
            Equal(VpnState.Busy, Tunnel.Classify("Disconnecting..."), "Disconnecting...");
            Equal(VpnState.Up, Tunnel.Classify("Conectado"), "Conectado");
            Equal(VpnState.Down, Tunnel.Classify("Desconectado"), "Desconectado");
            Equal(VpnState.NoWindow, Tunnel.Classify("Status:"), "label 'Status:'");
            Equal(VpnState.NoWindow, Tunnel.Classify("Configuration:"), "label 'Configuration:'");
        }

        static void TestRules()
        {
            Rules r = new Rules(Config.Split("10.20.30.0/24 *.corp.example intranet 10.1.2.3"));
            IPAddress[] a;
            Check(r.AllowsHost("10.20.30.40", out a), "IP inside /24");
            Check(!r.AllowsHost("10.20.31.1", out a), "IP outside /24");
            Check(r.AllowsHost("10.1.2.3", out a), "single IP");
            Check(!r.AllowsHost("10.1.2.4", out a), "next IP");
            Check(r.AllowsName("app.corp.example"), "wildcard subdomain");
            Check(r.AllowsName("APP.Corp.Example."), "case and trailing dot");
            Check(r.AllowsName("corp.example"), "wildcard apex");
            Check(!r.AllowsName("evilcorp.example"), "suffix without dot");
            Check(!r.AllowsName("corp.example.evil.com"), "suffix in the middle");
            Check(r.AllowsName("intranet"), "exact name");
            Check(!r.AllowsName("intranet2"), "other name");

            Rules everything = new Rules(Config.Split("0.0.0.0/0"));
            Check(everything.AllowsAddress(IPAddress.Parse("8.8.8.8")), "/0 matches all");
            Rules nothing = new Rules(new string[0]);
            Check(!nothing.AllowsHost("10.20.30.40", out a), "empty list allows nothing");
            Check(!new Rules(Config.Split("10")).AllowsAddress(IPAddress.Parse("0.0.0.10")), "'10' is not an IP");

            string pac = r.Pac("192.168.1.50:8080");
            Check(pac.Contains("PROXY 192.168.1.50:8080"), "PAC names the proxy");
            Check(pac.Contains("dnsDomainIs(host, \".corp.example\")"), "PAC has the domain");
            Check(pac.Contains("isInNet(host, \"10.20.30.0\", \"255.255.255.0\")"), "PAC has the network");
            Check(pac.Contains("host == \"intranet\""), "PAC has the name");
            Check(pac.TrimEnd().EndsWith("return \"DIRECT\";\n}".TrimEnd()), "PAC defaults to DIRECT");
        }

        static void TestParsing()
        {
            string host, path;
            int port;
            Check(Proxy.ParseAbsolute("http://10.20.30.40/login.do?x=1", out host, out port, out path)
                && host == "10.20.30.40" && port == 80 && path == "/login.do?x=1", "absolute URL");
            Check(Proxy.ParseAbsolute("http://user:pw@example.com:8081", out host, out port, out path)
                && host == "example.com" && port == 8081 && path == "/", "userinfo, port, no path");
            Check(!Proxy.ParseAbsolute("ftp://example.com/", out host, out port, out path), "ftp refused");
            Check(Proxy.SplitHostPort("app.corp.example:443", 80, out host, out port) && host == "app.corp.example" && port == 443, "CONNECT target");
            Check(Proxy.SplitHostPort("[::1]:8443", 80, out host, out port) && host == "::1" && port == 8443, "IPv6 target");
            Check(!Proxy.SplitHostPort("host:99999", 80, out host, out port), "port out of range");
            Check(!Proxy.SplitHostPort("host:abc", 80, out host, out port), "port not a number");
        }

        static void TestConfig()
        {
            string f = Path.GetTempFileName();
            try
            {
                File.WriteAllText(f, "# comment\nprofile = VPN Test  # trailing\nallow = 10.0.0.0/8, *.example.com\ncheck_interval=45\nkeep_awake = no\n");
                Config c = Config.Load(f);
                Equal("VPN Test", c.Profile, "profile");
                Equal(2, c.Allow.Count, "allow list");
                Equal(45, c.CheckInterval, "check_interval");
                Equal(false, c.KeepAwake, "keep_awake");
                Equal("0.0.0.0:8080", c.Listen, "default listen");
                File.WriteAllText(f, "check_interval = 1\n");
                Check(Throws(delegate { Config.Load(f); }), "out of range rejected");
                File.WriteAllText(f, "colour = blue\n");
                Check(Throws(delegate { Config.Load(f); }), "unknown key rejected");
                Check(Config.Load(f + ".missing").Profile == "", "missing file = defaults");
            }
            finally { File.Delete(f); }
        }

        static void TestProxy()
        {
            // A tiny origin server answering every request with its request line.
            TcpListener origin = new TcpListener(IPAddress.Loopback, 0);
            origin.Start();
            int originPort = ((IPEndPoint)origin.LocalEndpoint).Port;
            Thread server = new Thread(delegate()
            {
                while (true)
                {
                    TcpClient c;
                    try { c = origin.AcceptTcpClient(); } catch (SocketException) { return; }
                    using (c)
                    {
                        NetworkStream s = c.GetStream();
                        StreamReader rd = new StreamReader(s, Encoding.ASCII);
                        string first = rd.ReadLine();
                        string line;
                        while (!string.IsNullOrEmpty(line = rd.ReadLine())) { }
                        byte[] body = Encoding.ASCII.GetBytes("origin saw: " + first);
                        byte[] head = Encoding.ASCII.GetBytes("HTTP/1.1 200 OK\r\nContent-Length: " + body.Length + "\r\nConnection: close\r\n\r\n");
                        s.Write(head, 0, head.Length);
                        s.Write(body, 0, body.Length);
                    }
                }
            }) { IsBackground = true };
            server.Start();

            Proxy p = new Proxy("127.0.0.1:0", new Rules(Config.Split("127.0.0.0/8")), new Rules(Config.Split("127.0.0.1/32")),
                delegate { return "vpn: Up\n"; });
            p.Start();
            try
            {
                // Plain http through the proxy; the origin must get origin-form.
                int code;
                string body = Raw(p.Port, "GET http://127.0.0.1:" + originPort + "/a/b?c=d HTTP/1.1", out code);
                Equal("origin saw: GET /a/b?c=d HTTP/1.1", body, "http via proxy");

                // CONNECT, then a request inside the tunnel.
                using (TcpClient c = new TcpClient("127.0.0.1", p.Port))
                {
                    NetworkStream s = c.GetStream();
                    Send(s, "CONNECT 127.0.0.1:" + originPort + " HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n");
                    string resp = ReadAll(s, "\r\n\r\n");
                    Check(resp.StartsWith("HTTP/1.1 200"), "CONNECT accepted: " + resp.Trim());
                    Send(s, "GET /tunnel HTTP/1.1\r\nHost: x\r\n\r\n");
                    Check(ReadAll(s, null).EndsWith("origin saw: GET /tunnel HTTP/1.1"), "request inside the tunnel");
                }

                Raw(p.Port, "GET http://127.0.0.2:" + originPort + "/ HTTP/1.1", out code);
                Equal(403, code, "destination outside the allow list");
                Raw(p.Port, "GET http://example.invalid/ HTTP/1.1", out code);
                Equal(403, code, "name outside the allow list");
                Raw(p.Port, "GET http://127.0.0.1:1/ HTTP/1.1", out code);
                Equal(502, code, "unreachable destination");

                string pac = Raw(p.Port, "GET /proxy.pac HTTP/1.1", out code);
                Check(code == 200 && pac.Contains("FindProxyForURL") && pac.Contains("PROXY 127.0.0.1:" + p.Port), "PAC served with the right address");
                Check(Raw(p.Port, "GET /health HTTP/1.1", out code).Contains("vpn: Up"), "health page");
                Raw(p.Port, "GET /nope HTTP/1.1", out code);
                Equal(404, code, "unknown local path");
            }
            finally { p.Stop(); }

            // A proxy whose clients list excludes us must refuse.
            Proxy closed = new Proxy("127.0.0.1:0", new Rules(Config.Split("10.0.0.0/8")), new Rules(Config.Split("127.0.0.1/32")),
                delegate { return ""; });
            closed.Start();
            try
            {
                int code;
                Raw(closed.Port, "GET http://127.0.0.1:" + originPort + "/ HTTP/1.1", out code);
                Equal(403, code, "client outside the clients list");
            }
            finally { closed.Stop(); origin.Stop(); }
        }

        static void TestLogin(string fakeExe)
        {
            const string Password = "s3cret pass!";
            const string Seed = "JBSWY3DPEHPK3PXP";
            foreach (Process old in Process.GetProcessesByName("SnwlConnect"))
            {
                Fail("a real or stale SnwlConnect is running (pid " + old.Id + "); refusing to run the login test");
                return;
            }
            Watchdog.ReadCredential = delegate(string target, out string user, out string secret)
            {
                user = target.EndsWith("otp") ? "otp" : "test.user";
                secret = target.EndsWith("otp") ? Seed : Password;
                return true;
            };
            Config cfg = new Config();
            cfg.ClientExe = fakeExe;
            cfg.Profile = "VPN Example";
            cfg.CheckUrl = "http://127.0.0.1:1/";   // never used while the fake says Connected
            Process fake = Process.Start(new ProcessStartInfo(fakeExe, "\"" + Password + "\" " + Seed + " 6") { UseShellExecute = false });
            try
            {
                Snapshot snap = WaitFor(delegate(Snapshot s) { return s.State == VpnState.Down; }, 20);
                Equal(VpnState.Down, snap.State, "fake client found and Disconnected");
                Check(snap.Profile != null && snap.Profile.Text == "VPN Example", "profile read from the combo box");
                Check(snap.MainButton != null && snap.MainButton.Text == "Connect", "Connect button found");

                Check(Watchdog.LoginOnce(cfg), "first login (Connect, password, code)");
                Equal(VpnState.Up, Tunnel.Take().State, "Connected after login");

                // The fake expires the session after 6 s and asks again, like the
                // real 8h re-authentication; the agent loop must answer it. The new
                // code has to wait for the next 30 s window, so allow ~90 s.
                snap = WaitFor(delegate(Snapshot s) { return s.PasswordDialog != null; }, 20);
                Check(snap.PasswordDialog != null, "re-authentication prompt appeared");
                DateTime until = DateTime.Now.AddSeconds(90);
                while (DateTime.Now < until && !(Tunnel.Take().State == VpnState.Up && Tunnel.Take().PasswordDialog == null))
                    Thread.Sleep(Watchdog.Tick(cfg) * 100);
                Equal(VpnState.Up, Tunnel.Take().State, "Connected again after re-authentication");
            }
            finally
            {
                if (!fake.HasExited) fake.Kill();
                fake.Dispose();
                Watchdog.ReadCredential = Credentials.TryRead;
            }
        }

        delegate bool SnapCondition(Snapshot s);

        static Snapshot WaitFor(SnapCondition cond, int seconds)
        {
            Snapshot s = Tunnel.Take();
            for (int i = 0; i < seconds * 4 && !cond(s); i++)
            {
                Thread.Sleep(250);
                s = Tunnel.Take();
            }
            return s;
        }

        static bool Throws(Action a)
        {
            try { a(); return false; }
            catch (Exception) { return true; }
        }

        // One request through the proxy over a raw socket. (.NET's own client
        // never sends loopback addresses through a proxy.) Returns the body.
        static string Raw(int proxyPort, string requestLine, out int status)
        {
            using (TcpClient c = new TcpClient("127.0.0.1", proxyPort))
            {
                NetworkStream s = c.GetStream();
                Send(s, requestLine + "\r\nHost: selftest\r\n\r\n");
                string resp = ReadAll(s, null);
                status = resp.Length >= 12 ? int.Parse(resp.Substring(9, 3)) : -1;
                int body = resp.IndexOf("\r\n\r\n");
                return body < 0 ? "" : resp.Substring(body + 4);
            }
        }

        static void Send(NetworkStream s, string text)
        {
            byte[] b = Encoding.ASCII.GetBytes(text);
            s.Write(b, 0, b.Length);
        }

        // Reads until the marker (or EOF when marker is null).
        static string ReadAll(NetworkStream s, string marker)
        {
            s.ReadTimeout = 10000;
            StringBuilder sb = new StringBuilder();
            byte[] buf = new byte[4096];
            while (marker == null || !sb.ToString().Contains(marker))
            {
                int n = s.Read(buf, 0, buf.Length);
                if (n <= 0) break;
                sb.Append(Encoding.ASCII.GetString(buf, 0, n));
            }
            return sb.ToString();
        }
    }
}
