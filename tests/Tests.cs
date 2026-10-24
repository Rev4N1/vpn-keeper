// The test suite. Built into its own tests.exe (the shipped vpn-keeper.exe
// carries no test code) from the src files plus this one. CI runs it on every
// push, passing the fake SnwlConnect.exe so the login is tested for real.
//
//   tests.exe [<fake SnwlConnect.exe>]

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;

namespace VpnKeeper
{
    static class Tests
    {
        static int failed, passed;

        static int Main(string[] args)
        {
            Console.WriteLine("vpn-keeper " + BuildInfo.Version + " tests");
            Section("TOTP", Totp_);
            Section("status captions", Captions);
            Section("allow lists and PAC", RulesTests);
            Section("request parsing", Parsing);
            Section("admin routes", AdminRoutes);
            Section("schedule", ScheduleTests);
            Section("config file", ConfigFile);
            Section("proxy over real sockets", ProxyTest);
            if (args.Length > 0) Section("login against the fake Connect Tunnel", delegate { Login(args[0]); });
            else Console.WriteLine("(login test skipped: pass the fake SnwlConnect.exe to run it)");
            Console.WriteLine(passed + " passed, " + failed + " failed");
            return failed == 0 ? 0 : 1;
        }

        static void Totp_()
        {
            // RFC 6238 appendix B (SHA-1, 8 digits).
            byte[] k = Encoding.ASCII.GetBytes("12345678901234567890");
            long[] t = { 59, 1111111109, 1111111111, 1234567890, 2000000000, 20000000000 };
            string[] c = { "94287082", "07081804", "14050471", "89005924", "69279037", "65353130" };
            for (int i = 0; i < t.Length; i++) Eq(c[i], Totp.Code(k, t[i] / 30, 8), "RFC 6238 T=" + t[i]);
            Eq("287082", Totp.Code(k, 59 / 30, 6), "6 digits");
            Eq("ABC", Ascii(Totp.Base32Decode("IFBEG===")), "base32 padded");
            Eq(Ascii(k), Ascii(Totp.Base32Decode("gezd gnbv gy3t qojq gezd gnbv gy3t qojq")), "base32 spaced lower");
            Yes(Throws(delegate { Totp.Base32Decode("not base32!"); }), "bad base32 rejected");
            Yes(Throws(delegate { Totp.Base32Decode("  "); }), "empty seed rejected");
            Eq(5, Totp.SecondsLeft(new DateTime(2026, 1, 1, 0, 0, 25, DateTimeKind.Utc), 30), "seconds left");
        }

        static void Captions()
        {
            Eq(VpnState.Up, Tunnel.Classify("Connected"), "Connected");
            Eq(VpnState.Down, Tunnel.Classify("Disconnected"), "Disconnected");
            Eq(VpnState.Down, Tunnel.Classify("&Disconnected"), "mnemonic in a status");
            Eq(VpnState.Busy, Tunnel.Classify("Connecting..."), "Connecting...");
            Eq(VpnState.Busy, Tunnel.Classify("Reconnecting..."), "Reconnecting...");
            Eq(VpnState.Up, Tunnel.Classify("Conectado"), "Conectado");
            Eq(VpnState.Down, Tunnel.Classify("Desconectado"), "Desconectado");
            Eq(VpnState.NoWindow, Tunnel.Classify("Status:"), "label 'Status:'");
            Eq("Connect", Tunnel.StripMnemonic("&Connect"), "mnemonic stripped");
            Eq("Save & Exit", Tunnel.StripMnemonic("Save && E&xit"), "literal && kept");
        }

        static void RulesTests()
        {
            Rules r = new Rules(Config.Split("10.20.30.0/24 *.corp.example intranet 10.1.2.3"));
            IPAddress[] a;
            Yes(r.AllowsHost("10.20.30.40", out a), "IP inside /24");
            No(r.AllowsHost("10.20.31.1", out a), "IP outside /24");
            Yes(r.AllowsHost("10.1.2.3", out a), "single IP");
            Yes(r.AllowsName("app.corp.example"), "wildcard subdomain");
            Yes(r.AllowsName("APP.Corp.Example."), "case and trailing dot");
            Yes(r.AllowsName("corp.example"), "wildcard apex");
            No(r.AllowsName("evilcorp.example"), "suffix without dot");
            No(r.AllowsName("corp.example.evil.com"), "suffix in the middle");
            Yes(r.AllowsName("intranet"), "exact name");
            No(r.AllowsName("intranet2"), "other name");
            Yes(new Rules(Config.Split("0.0.0.0/0")).AllowsAddress(IPAddress.Parse("8.8.8.8")), "/0 matches all");
            No(new Rules(new string[0]).AllowsHost("10.20.30.40", out a), "empty allows nothing");
            No(new Rules(Config.Split("10")).AllowsAddress(IPAddress.Parse("0.0.0.10")), "'10' is not an IP");

            Yes(Rules.IsCidr("192.168.1.0/24"), "IsCidr yes");
            No(Rules.IsCidr("*.corp.example"), "IsCidr no");
            string net, mask; IPAddress host;
            Yes(Rules.ParseCidr("10.7.0.0/24", out net, out mask, out host) && net == "10.7.0.0" && mask == "255.255.255.0" && host.ToString() == "10.7.0.1", "ParseCidr");

            string pac = r.Pac("192.168.1.50:8080");
            Yes(pac.Contains("PROXY 192.168.1.50:8080"), "PAC names the proxy");
            Yes(pac.Contains("dnsDomainIs(host, \".corp.example\")"), "PAC has the domain");
            Yes(pac.Contains("isInNet(host, \"10.20.30.0\", \"255.255.255.0\")"), "PAC has the network");
            Yes(pac.Contains("host == \"intranet\""), "PAC has the name");
            Yes(pac.TrimEnd().EndsWith("return \"DIRECT\";\n}".TrimEnd()), "PAC defaults to DIRECT");
        }

        static void Parsing()
        {
            string host, path; int port;
            Yes(Proxy.ParseAbsolute("http://10.20.30.40/login?x=1", out host, out port, out path) && host == "10.20.30.40" && port == 80 && path == "/login?x=1", "absolute URL");
            Yes(Proxy.ParseAbsolute("http://user:pw@example.com:8081", out host, out port, out path) && host == "example.com" && port == 8081 && path == "/", "userinfo, port, no path");
            No(Proxy.ParseAbsolute("ftp://example.com/", out host, out port, out path), "ftp refused");
            Yes(Proxy.SplitHostPort("app.corp.example:443", 80, out host, out port) && host == "app.corp.example" && port == 443, "CONNECT target");
            Yes(Proxy.SplitHostPort("[::1]:8443", 80, out host, out port) && host == "::1" && port == 8443, "IPv6 target");
            No(Proxy.SplitHostPort("host:99999", 80, out host, out port), "port out of range");
            No(Proxy.SplitHostPort("host:abc", 80, out host, out port), "port not a number");
        }

        static void AdminRoutes()
        {
            List<string> clients = Config.Split("10.7.0.0/24 192.168.1.0/24 127.0.0.1/32");
            List<string> routes = Admin.RoutesNeeded(clients, "192.168.1.0/24");
            Eq(1, routes.Count, "one route needed");
            Eq("10.7.0.0/24", routes.Count > 0 ? routes[0] : "", "the WireGuard subnet, not the LAN or loopback");
            Eq(0, Admin.RoutesNeeded(Config.Split("192.168.1.0/24"), "192.168.1.0/24").Count, "LAN only = no route");
            Eq(0, Admin.RoutesNeeded(Config.Split("*.corp.example"), "192.168.1.0/24").Count, "names are not routes");
            Eq(1, Admin.CidrClients(Config.Split("10.0.0.0/8 *.x")).Count, "CidrClients keeps only CIDRs");
        }

        // 2026-06-01 is a Monday, so +0..+6 are Mon..Sun.
        static DateTime On(int dayOffset, int h, int m) { return new DateTime(2026, 6, 1 + dayOffset, h, m, 0); }

        static void ScheduleTests()
        {
            Yes(Schedule.Parse("").Always, "empty = always");
            Yes(Schedule.Parse("always").Always, "'always' = always");
            Yes(Schedule.Parse("   ").Active(On(2, 3, 0)), "blank is always active");

            Schedule work = Schedule.Parse("07:30-17:30");   // every day
            No(work.Active(On(0, 7, 29)), "before start");
            Yes(work.Active(On(0, 7, 30)), "at start");
            No(work.Active(On(0, 17, 30)), "at end (exclusive)");
            Yes(work.Active(On(6, 12, 0)), "every day includes Sunday");

            Schedule night = Schedule.Parse("22:00-06:00");
            Yes(night.Active(On(0, 23, 0)), "overnight before midnight");
            Yes(night.Active(On(0, 2, 0)), "overnight after midnight");
            No(night.Active(On(0, 12, 0)), "overnight midday off");

            // The user's schedule: Mon-Thu 07:45-17:00, Fri 07:45-15:00, weekend off.
            Schedule s = Schedule.Parse("Mon-Thu 07:45-17:00, Fri 07:45-15:00");
            No(s.Active(On(0, 7, 44)), "Mon before start");
            Yes(s.Active(On(0, 7, 45)), "Mon at start");
            Yes(s.Active(On(3, 16, 59)), "Thu still on at 16:59");
            No(s.Active(On(3, 17, 0)), "Thu off at 17:00");
            Yes(s.Active(On(4, 14, 59)), "Fri on at 14:59");
            No(s.Active(On(4, 15, 0)), "Fri off at 15:00 (shorter)");
            No(s.Active(On(5, 12, 0)), "Saturday off");
            No(s.Active(On(6, 12, 0)), "Sunday off");

            Yes(Schedule.Parse("Mon,Wed,Fri 09:00-10:00").Active(On(2, 9, 30)), "day list: Wednesday");
            No(Schedule.Parse("Mon,Wed,Fri 09:00-10:00").Active(On(1, 9, 30)), "day list: Tuesday off");
            Yes(Schedule.Parse("7:30-17:30").Active(On(0, 8, 0)), "single-digit hour");
            Yes(Throws(delegate { Schedule.Parse("Mon 7:30"); }), "missing window rejected");
            Yes(Throws(delegate { Schedule.Parse("Xyz 09:00-10:00"); }), "bad day rejected");
            Yes(Throws(delegate { Schedule.Parse("25:00-26:00"); }), "bad time rejected");
        }

        static void ConfigFile()
        {
            string f = Path.GetTempFileName();
            try
            {
                File.WriteAllText(f, "# comment\nprofile = VPN Test  # trailing\nallow = 10.0.0.0/8, *.example.com\nport=9090\n");
                Config c = Config.Load(f);
                Eq("VPN Test", c.Profile, "profile");
                Eq(2, c.Allow.Count, "allow list");
                Eq(9090, c.Port, "port");
                Yes(Throws(delegate { File.WriteAllText(f, "port = 0\n"); Config.Load(f); }), "bad port rejected");
                Yes(Throws(delegate { File.WriteAllText(f, "colour = blue\n"); Config.Load(f); }), "unknown key rejected");
                Eq(0, Config.Load(f + ".missing").Problems().Count == 3 ? 0 : 1, "missing file = empty config");

                Config saved = new Config();
                saved.Profile = "VPN X";
                saved.CheckUrl = "http://10.0.0.1/";
                saved.Allow = Config.Split("10.0.0.0/8");
                saved.Clients = Config.Split("192.168.1.0/24 127.0.0.1/32");
                saved.Save(f);
                Config back = Config.Load(f);
                Eq("VPN X", back.Profile, "round-trip profile");
                Eq(2, back.Clients.Count, "round-trip clients");
                Eq(0, back.Problems().Count, "a full config has no problems");
            }
            finally { File.Delete(f); }
        }

        static void ProxyTest()
        {
            TcpListener origin = new TcpListener(IPAddress.Loopback, 0);
            origin.Start();
            int op = ((IPEndPoint)origin.LocalEndpoint).Port;
            new Thread(delegate()
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
                        while (!string.IsNullOrEmpty(rd.ReadLine())) { }
                        byte[] body = Encoding.ASCII.GetBytes("origin saw: " + first);
                        Write(s, "HTTP/1.1 200 OK\r\nContent-Length: " + body.Length + "\r\nConnection: close\r\n\r\n");
                        s.Write(body, 0, body.Length);
                    }
                }
            }) { IsBackground = true }.Start();

            Proxy p = new Proxy(0, new Rules(Config.Split("127.0.0.0/8")), new Rules(Config.Split("127.0.0.1/32")), delegate { return "vpn: Up\n"; });
            p.Start("127.0.0.1");
            try
            {
                int code;
                Eq("origin saw: GET /a/b?c=d HTTP/1.1", Raw(p.Port, "GET http://127.0.0.1:" + op + "/a/b?c=d HTTP/1.1", out code), "http via proxy");

                using (TcpClient c = new TcpClient("127.0.0.1", p.Port))
                {
                    NetworkStream s = c.GetStream();
                    Write(s, "CONNECT 127.0.0.1:" + op + " HTTP/1.1\r\nHost: x\r\n\r\n");
                    Yes(ReadAll(s, "\r\n\r\n").StartsWith("HTTP/1.1 200"), "CONNECT accepted");
                    Write(s, "GET /tunnel HTTP/1.1\r\nHost: x\r\n\r\n");
                    Yes(ReadAll(s, null).EndsWith("origin saw: GET /tunnel HTTP/1.1"), "request inside the tunnel");
                }

                Raw(p.Port, "GET http://127.0.0.2:" + op + "/ HTTP/1.1", out code); Eq(403, code, "destination not in allow");
                Raw(p.Port, "GET http://example.invalid/ HTTP/1.1", out code); Eq(403, code, "name not in allow");
                Raw(p.Port, "GET http://127.0.0.1:1/ HTTP/1.1", out code); Eq(502, code, "unreachable destination");
                string pac = Raw(p.Port, "GET /proxy.pac HTTP/1.1", out code);
                Yes(code == 200 && pac.Contains("FindProxyForURL") && pac.Contains("PROXY 127.0.0.1:" + p.Port), "PAC served");
                Yes(Raw(p.Port, "GET /health HTTP/1.1", out code).Contains("vpn: Up"), "health page");
                Raw(p.Port, "GET /nope HTTP/1.1", out code); Eq(404, code, "unknown local path");
            }
            finally { p.Stop(); }

            Proxy closed = new Proxy(0, new Rules(Config.Split("10.0.0.0/8")), new Rules(Config.Split("127.0.0.1/32")), delegate { return ""; });
            closed.Start("127.0.0.1");
            try { int code; Raw(closed.Port, "GET http://127.0.0.1:" + op + "/ HTTP/1.1", out code); Eq(403, code, "client not in clients list"); }
            finally { closed.Stop(); origin.Stop(); }
        }

        static void Login(string fakeExe)
        {
            const string Password = "s3cret pass!", Seed = "JBSWY3DPEHPK3PXP";
            foreach (Process old in Process.GetProcessesByName("SnwlConnect")) { Fail("a SnwlConnect is already running (pid " + old.Id + ")"); return; }
            Tunnel.Exe = fakeExe;
            Watchdog.ReadCredential = delegate(string target, out string user, out string secret)
            {
                user = target == Credentials.Otp ? "otp" : "test.user";
                secret = target == Credentials.Otp ? Seed : Password;
                return true;
            };
            Config cfg = new Config();
            cfg.Profile = "VPN Example";
            Process fake = Process.Start(new ProcessStartInfo(fakeExe, "\"" + Password + "\" " + Seed + " 6") { UseShellExecute = false });
            try
            {
                Snapshot snap = WaitFor(VpnState.Down, 20);
                Eq(VpnState.Down, snap.State, "fake found, Disconnected");
                Yes(snap.Profile != null && snap.Profile.Caption == "VPN Example", "profile read from combo box");
                Yes(snap.MainButton != null && snap.MainButton.Caption == "Connect", "Connect button found (text is &Connect)");

                // One agent pass logs in and connects.
                DateTime until = DateTime.Now.AddSeconds(90);
                while (DateTime.Now < until && Tunnel.Take().State != VpnState.Up) Thread.Sleep(Watchdog.Tick(cfg) * 200);
                snap = Tunnel.Take();
                Eq(VpnState.Up, snap.State, "Connected (read from the hidden tray window)");
                Yes(snap.Main != null && !snap.Main.Visible, "the fake hid its window like the real client");

                // The fake expires the session after 6 s and asks again; the loop re-logs in.
                WaitForPrompt(20);
                until = DateTime.Now.AddSeconds(90);
                while (DateTime.Now < until && !(Tunnel.Take().State == VpnState.Up && NoPrompt())) Thread.Sleep(Watchdog.Tick(cfg) * 200);
                Yes(Tunnel.Take().State == VpnState.Up && NoPrompt(), "re-logged in after the session expired");
            }
            finally
            {
                if (!fake.HasExited) fake.Kill();
                fake.Dispose();
                Watchdog.ReadCredential = Credentials.TryRead;
            }
        }

        // ---- helpers ----

        static Snapshot WaitFor(VpnState st, int seconds)
        {
            Snapshot s = Tunnel.Take();
            for (int i = 0; i < seconds * 4 && s.State != st; i++) { Thread.Sleep(250); s = Tunnel.Take(); }
            return s;
        }

        static void WaitForPrompt(int seconds)
        {
            for (int i = 0; i < seconds * 4; i++) { Snapshot s = Tunnel.Take(); if (s.PasswordDialog != null || s.OtpDialog != null) return; Thread.Sleep(250); }
        }

        static bool NoPrompt() { Snapshot s = Tunnel.Take(); return s.PasswordDialog == null && s.OtpDialog == null; }

        static string Raw(int port, string requestLine, out int status)
        {
            using (TcpClient c = new TcpClient("127.0.0.1", port))
            {
                NetworkStream s = c.GetStream();
                Write(s, requestLine + "\r\nHost: tests\r\n\r\n");
                string resp = ReadAll(s, null);
                status = resp.Length >= 12 ? int.Parse(resp.Substring(9, 3)) : -1;
                int body = resp.IndexOf("\r\n\r\n");
                return body < 0 ? "" : resp.Substring(body + 4);
            }
        }

        static void Write(Stream s, string text) { byte[] b = Encoding.ASCII.GetBytes(text); s.Write(b, 0, b.Length); }

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

        static void Section(string name, Action body)
        {
            Console.WriteLine("== " + name);
            try { body(); } catch (Exception e) { Fail("threw " + e); }
        }

        static void Yes(bool ok, string what) { if (ok) passed++; else Fail(what); }
        static void No(bool ok, string what) { Yes(!ok, what); }
        static void Eq(object expected, object actual, string what) { if (Equals(expected, actual)) passed++; else Fail(what + ": expected <" + expected + "> got <" + actual + ">"); }
        static void Fail(string what) { failed++; Console.WriteLine("  FAIL " + what); }
        static bool Throws(Action a) { try { a(); return false; } catch { return true; } }
        static string Ascii(byte[] b) { return Encoding.ASCII.GetString(b); }
    }
}
