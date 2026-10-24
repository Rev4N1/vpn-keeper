using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Text;

namespace VpnKeeper
{
    // The commands a person runs: setup, status, uninstall. setup asks a few
    // questions, saves the secrets and settings, installs autostart, and starts
    // the agent. After that the agent runs on its own and needs no attention.
    static class Setup
    {
        public static int Run()
        {
            Console.WriteLine("vpn-keeper setup\n");

            // 1. Copy the .exe to a stable place, so autostart keeps working
            //    after the download is deleted.
            string here = Assembly.GetExecutingAssembly().Location;
            string target = Config.InstalledExe;
            if (!PathEquals(here, target))
            {
                Directory.CreateDirectory(Config.InstallDir);
                File.Copy(here, target, true);
                Console.WriteLine("installed to " + target);
            }

            Config cfg = Config.Load();   // the current settings, if any

            // 2. The VPN profile.
            Snapshot snap = Tunnel.Take();
            string suggested = cfg.Profile;
            if (suggested.Length == 0 && snap.Profile != null) suggested = snap.Profile.Caption;
            cfg.Profile = Ask("Connect Tunnel configuration name", suggested);

            // 3. A URL only reachable through the VPN, for the health check.
            cfg.CheckUrl = Ask("a URL that only answers through the VPN (e.g. http://10.20.30.40/)", cfg.CheckUrl);

            // 4. What the proxy may reach.
            cfg.Allow = AskList("sites to share, space separated (e.g. 10.20.30.0/24 *.example.com)", cfg.Allow);

            // 5. Who may use the proxy. Default to this PC's LAN plus loopback.
            Lan lan = Lan.Find();
            List<string> clientsDefault = cfg.Clients;
            if (clientsDefault.Count == 0)
            {
                clientsDefault = new List<string>();
                if (lan != null) clientsDefault.Add(lan.Subnet);
                clientsDefault.Add("127.0.0.1/32");
            }
            cfg.Clients = AskList("who may use the proxy (networks, space separated)", clientsDefault);

            cfg.Save(Config.FilePath);
            Console.WriteLine("settings saved to " + Config.FilePath + "\n");

            // 6. The secrets, into Credential Manager.
            SaveSecret("VPN", Credentials.Vpn, true);
            SaveSecret("TOTP seed (the Base32 text, A-Z and 2-7)", Credentials.Otp, false);

            // 7. Autostart at logon, and start now.
            InstallAutostart();
            Restart();

            // 8. Tell them the two things only they can do (both need admin).
            Console.WriteLine();
            PrintManualSteps(cfg, lan);
            Console.WriteLine("\nSetup done. Check it any time with:  vpn-keeper status");
            return 0;
        }

        public static int Status()
        {
            Config cfg = Config.Load();
            Console.WriteLine("vpn-keeper " + BuildInfo.Version);
            Console.WriteLine("installed:   " + (File.Exists(Config.InstalledExe) ? Config.InstalledExe : "NO (run vpn-keeper setup)"));
            Console.WriteLine("autostart:   " + (File.Exists(ShortcutPath) ? "on" : "OFF (run vpn-keeper setup)"));
            Console.WriteLine("agent:       " + (Agent.Running() ? "running" : "NOT running"));
            Console.WriteLine("config:      " + Config.FilePath);

            foreach (string p in cfg.Problems()) Console.WriteLine("  [FAIL] " + p);
            Console.WriteLine("  profile:   " + Show(cfg.Profile));
            Console.WriteLine("  check_url: " + Show(cfg.CheckUrl));
            Console.WriteLine("  allow:     " + Show(string.Join(" ", cfg.Allow.ToArray())));
            Console.WriteLine("  clients:   " + Show(string.Join(" ", cfg.Clients.ToArray())));

            Console.WriteLine("  VPN password:  " + (HasSecret(Credentials.Vpn) ? "saved" : "MISSING (run vpn-keeper setup)"));
            Console.WriteLine("  TOTP seed:     " + TotpStatus());

            Snapshot snap = Tunnel.Take();
            Console.WriteLine("Connect Tunnel: " + snap.State
                + (snap.Profile != null ? ", profile '" + snap.Profile.Caption + "'" : "")
                + (snap.State == VpnState.Down || snap.State == VpnState.NoWindow ? ", buttons: " + snap.ButtonList() : ""));

            Lan lan = Lan.Find();
            if (lan != null)
            {
                Console.WriteLine("this PC: " + lan.Address + " on " + lan.Subnet + " via " + lan.Gateway
                    + "  ->  http://" + lan.Address + ":" + cfg.Port + "/health");
                foreach (string c in cfg.Clients)
                    if (Rules.IsCidr(c) && lan.LosesRepliesTo(c))
                        Console.WriteLine("  [warn] replies to " + c + " would go into the VPN; run (as admin):  " + lan.RouteCommand(c));
            }
            return 0;
        }

        public static int Uninstall()
        {
            if (File.Exists(ShortcutPath)) { File.Delete(ShortcutPath); Console.WriteLine("autostart removed"); }
            foreach (Process p in Process.GetProcessesByName("vpn-keeper"))
                if (p.Id != Process.GetCurrentProcess().Id) { try { p.Kill(); } catch { } }
            Console.WriteLine("agent stopped");
            Credentials.Delete(Credentials.Vpn);
            Credentials.Delete(Credentials.Otp);
            Console.WriteLine("saved VPN password and TOTP seed removed");
            Console.WriteLine("left in place: " + Config.InstallDir + " (delete it by hand to remove the program and its settings)");
            Console.WriteLine("Connect Tunnel itself is untouched.");
            return 0;
        }

        // ---- helpers ----

        static string Ask(string what, string current)
        {
            while (true)
            {
                Console.Write(what + (current.Length > 0 ? " [" + current + "]" : "") + ": ");
                string line = Console.ReadLine();
                if (line == null) return current;
                line = line.Trim();
                if (line.Length > 0) return line;
                if (current.Length > 0) return current;
                Console.WriteLine("  (needed)");
            }
        }

        static List<string> AskList(string what, List<string> current)
        {
            return Config.Split(Ask(what, string.Join(" ", current.ToArray())));
        }

        static void SaveSecret(string label, string target, bool askUser)
        {
            string user = "otp", current;
            bool have = HasSecret(target);
            Console.Write("\n" + label + (have ? " (Enter keeps the saved one): " : ": "));
            if (askUser)
            {
                Console.Write("\n  VPN username" + (TryUser(target, out current) && current.Length > 0 ? " [" + current + "]" : "") + ": ");
                string u = Console.ReadLine();
                if (u != null && u.Trim().Length > 0) user = u.Trim();
                else if (TryUser(target, out current) && current.Length > 0) user = current;
                Console.Write("  password (typing hidden): ");
            }
            string secret = ReadHidden();
            if (secret.Length == 0)
            {
                if (have) { Console.WriteLine("  kept"); return; }
                Console.WriteLine("  (skipped; set it later with vpn-keeper setup)");
                return;
            }
            if (target == Credentials.Otp)
            {
                try { Totp.Base32Decode(secret); }
                catch (FormatException e) { Console.WriteLine("  not saved: " + e.Message); return; }
            }
            Credentials.Write(target, user, secret);
            Console.WriteLine("  saved");
        }

        static bool TryUser(string target, out string user)
        {
            string secret;
            return Credentials.TryRead(target, out user, out secret);
        }

        static string ReadHidden()
        {
            StringBuilder sb = new StringBuilder();
            while (true)
            {
                ConsoleKeyInfo k = Console.ReadKey(true);
                if (k.Key == ConsoleKey.Enter) { Console.WriteLine(); return sb.ToString(); }
                if (k.Key == ConsoleKey.Backspace) { if (sb.Length > 0) sb.Length--; }
                else if (!char.IsControl(k.KeyChar)) sb.Append(k.KeyChar);
            }
        }

        static bool HasSecret(string target)
        {
            string u, s;
            return Credentials.TryRead(target, out u, out s) && s.Length > 0;
        }

        static string TotpStatus()
        {
            string u, seed;
            if (!Credentials.TryRead(Credentials.Otp, out u, out seed) || seed.Length == 0) return "MISSING (run vpn-keeper setup)";
            try
            {
                byte[] key = Totp.Base32Decode(seed);
                DateTime now = DateTime.UtcNow;
                return "saved; current code " + Totp.Code(key, Totp.Step(now, 30), 6) + " (valid " + Totp.SecondsLeft(now, 30) + "s) - compare with your app";
            }
            catch (FormatException e) { return "INVALID: " + e.Message; }
        }

        static void InstallAutostart()
        {
            Type t = Type.GetTypeFromProgID("WScript.Shell");
            object shell = Activator.CreateInstance(t);
            object lnk = t.InvokeMember("CreateShortcut", BindingFlags.InvokeMethod, null, shell, new object[] { ShortcutPath });
            Type lt = lnk.GetType();
            lt.InvokeMember("TargetPath", BindingFlags.SetProperty, null, lnk, new object[] { Config.InstalledExe });
            lt.InvokeMember("Arguments", BindingFlags.SetProperty, null, lnk, new object[] { "start" });
            lt.InvokeMember("WorkingDirectory", BindingFlags.SetProperty, null, lnk, new object[] { Config.InstallDir });
            lt.InvokeMember("WindowStyle", BindingFlags.SetProperty, null, lnk, new object[] { 7 });
            lt.InvokeMember("Description", BindingFlags.SetProperty, null, lnk, new object[] { "Keeps the VPN logged in" });
            lt.InvokeMember("Save", BindingFlags.InvokeMethod, null, lnk, null);
            Console.WriteLine("autostart on (runs at every logon)");
        }

        static void Restart()
        {
            foreach (Process p in Process.GetProcessesByName("vpn-keeper"))
                if (p.Id != Process.GetCurrentProcess().Id) { try { p.Kill(); } catch { } }
            Process.Start(new ProcessStartInfo(ShortcutPath) { UseShellExecute = true });
            Console.WriteLine("agent started");
        }

        static void PrintManualSteps(Config cfg, Lan lan)
        {
            Console.WriteLine("Two things need an administrator, once. Open PowerShell as administrator:");
            Console.WriteLine();
            string clients = lan != null ? lan.Subnet : "192.168.0.0/16";
            Console.WriteLine("  # let the LAN reach the proxy");
            Console.WriteLine("  New-NetFirewallRule -DisplayName 'vpn-keeper' -Direction Inbound -Protocol TCP -LocalPort "
                + cfg.Port + " -RemoteAddress " + clients + " -Action Allow -Profile Any");
            if (lan != null)
                foreach (string c in cfg.Clients)
                    if (Rules.IsCidr(c) && lan.LosesRepliesTo(c))
                    {
                        Console.WriteLine();
                        Console.WriteLine("  # " + c + " clients reach you through the VPN otherwise");
                        Console.WriteLine("  " + lan.RouteCommand(c));
                    }
            if (lan != null)
                Console.WriteLine("\nThen on another PC, set the browser's automatic proxy script to:\n  http://" + lan.Address + ":" + cfg.Port + "/proxy.pac");
        }

        static string ShortcutPath
        {
            get { return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Startup), "vpn-keeper.lnk"); }
        }

        static string Show(string v) { return v.Length == 0 ? "(not set)" : v; }

        static bool PathEquals(string a, string b)
        {
            return string.Equals(Path.GetFullPath(a), Path.GetFullPath(b), StringComparison.OrdinalIgnoreCase);
        }
    }
}
