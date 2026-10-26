using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Reflection;
using System.Text;
using System.Threading;

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
            if (!PathEquals(here, Config.InstalledExe)) Install(here);

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

            // Optional: only keep the VPN connected within a daily time window.
            while (true)
            {
                string h = Ask("hours to keep the VPN on (e.g. 07:30-17:30, or Mon-Thu 07:45-17:00, Fri 07:45-15:00), or 'always'", cfg.Hours.Length == 0 ? "always" : cfg.Hours);
                if (h.Equals("always", StringComparison.OrdinalIgnoreCase)) { cfg.Hours = ""; break; }
                try { Schedule.Parse(h); cfg.Hours = h; break; }
                catch (FormatException e) { Console.WriteLine("  " + e.Message); }
            }

            cfg.Save(Config.FilePath);
            Console.WriteLine("settings saved to " + Config.FilePath + "\n");

            // 6. The secrets, into Credential Manager.
            SaveSecret("VPN", Credentials.Vpn, true);
            SaveSecret("TOTP seed (the Base32 text, A-Z and 2-7)", Credentials.Otp, false);

            // 7. Autostart at logon, and start now.
            InstallAutostart();
            Restart();

            // 8. The firewall rule needs admin. Offer to apply it
            //    through one UAC prompt; always show the manual commands too.
            Console.WriteLine();
            ApplyAdminSteps(cfg, lan);
            Console.WriteLine("\nSetup done. Check it any time with:  vpn-keeper status");
            return 0;
        }

        // Queues a new VPN password (see Watchdog.Store). The running agent reads
        // it at its next login, so nothing needs restarting.
        public static int Password()
        {
            Console.Write("new VPN password (typing hidden): ");
            string p = ReadHidden();
            Console.Write("again, to confirm: ");
            if (p.Length == 0 || ReadHidden() != p) { Console.WriteLine("  empty or they differ; nothing saved"); return 1; }
            Console.Write("Force: reconnect now, so the VPN can ask straight away? [y/N]: ");
            string a = Console.ReadLine();
            string note = Watchdog.Store(p, a != null && a.Trim().ToLowerInvariant().StartsWith("y"), "the command line");
            Console.WriteLine(note);
            return note.StartsWith("Queued", StringComparison.Ordinal) ? 0 : 1;
        }

        // Puts this .exe in place of the installed one, settings and secrets
        // untouched. No questions and no window, so it works over SSH too.
        public static int Update()
        {
            string here = Assembly.GetExecutingAssembly().Location;
            if (PathEquals(here, Config.InstalledExe)) { Console.WriteLine("run update from the new vpn-keeper.exe you downloaded, not the installed one"); return 2; }
            if (!File.Exists(Config.InstalledExe)) { Console.WriteLine("not installed yet; run: vpn-keeper setup"); return 1; }
            Install(here);
            // Over SSH the agent runs in another session, so it can't be seen from here.
            Console.WriteLine("A running vpn-keeper restarts on " + BuildInfo.Version + " within a couple of minutes; check /health."
                + " If none is running, it starts with it at the next logon.");
            // Older supervisors leave a moment with nothing blocking sleep while the
            // agent restarts, and a long-idle PC sleeps at once. Block it from here
            // (it counts for the whole PC) until the restart is surely through.
            Agent.BlockSleep();
            Console.WriteLine("Keeping the PC awake for 90 s while it restarts...");
            Thread.Sleep(90000);
            return 0;
        }

        // A running .exe can't be overwritten but can be renamed: copy the new
        // one beside it first, then move it in. A supervisor or agent that
        // notices the change must never see a half-written .exe.
        static void Install(string from)
        {
            string target = Config.InstalledExe, old = target + ".old", fresh = target + ".new";
            Directory.CreateDirectory(Config.InstallDir);
            try { File.Delete(fresh); } catch (IOException) { } catch (UnauthorizedAccessException) { }
            File.Copy(from, fresh);
            // File.Copy keeps the source's (possibly older) timestamp. The running
            // copies detect an update by this value, so make it unmistakable: a
            // second update to the same-size .exe must still change the stamp.
            DateTime stamp = DateTime.UtcNow;
            try
            {
                if (File.Exists(target))
                {
                    DateTime installed = File.GetLastWriteTimeUtc(target);
                    if (stamp <= installed) stamp = installed.AddSeconds(2);
                }
            }
            catch (IOException) { }
            catch (UnauthorizedAccessException) { }
            File.SetLastWriteTimeUtc(fresh, stamp);
            if (File.Exists(target))
            {
                try { File.Delete(old); } catch (IOException) { } catch (UnauthorizedAccessException) { }   // still running from the last update
                if (File.Exists(old)) old = target + "." + DateTime.Now.ToString("yyyyMMddHHmmss") + ".old";
                File.Move(target, old);
            }
            try
            {
                File.Move(fresh, target);
            }
            catch
            {
                // Put the old .exe back rather than leave the PC with none.
                if (!File.Exists(target) && File.Exists(old))
                    try { File.Move(old, target); } catch (IOException) { } catch (UnauthorizedAccessException) { }
                throw;
            }
            Console.WriteLine("installed " + BuildInfo.Version + " to " + target);
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
            Console.WriteLine("  hours:     " + (cfg.Hours.Length == 0 ? "always" : cfg.Hours + (Schedule.Parse(cfg.Hours).Active(DateTime.Now) ? " (now: on)" : " (now: off)")));

            Console.WriteLine("  VPN password:  " + (HasSecret(Credentials.Vpn) ? "saved" : "MISSING (run vpn-keeper setup)"));
            Console.WriteLine("  TOTP seed:     " + TotpStatus());

            Snapshot snap = Tunnel.Take();
            Console.WriteLine("Connect Tunnel: " + snap.State
                + (snap.Profile != null ? ", profile '" + snap.Profile.Caption + "'" : "")
                + (snap.State == VpnState.Down || snap.State == VpnState.NoWindow ? ", buttons: " + snap.ButtonList() : ""));

            Lan lan = Lan.Find();
            if (lan != null)
                Console.WriteLine("this PC: " + lan.Address + " on " + lan.Subnet
                    + "  ->  http://" + lan.Address + ":" + cfg.Port + "/health");

            // What the running agent knows: last login, last error, last notice.
            try
            {
                using (WebClient w = new WebClient { Proxy = null })
                    Console.Write("agent reports:\n  " + w.DownloadString("http://127.0.0.1:" + cfg.Port + "/health").Trim().Replace("\n", "\n  ") + "\n");
            }
            catch (WebException) { }
            return 0;
        }

        public static int Uninstall()
        {
            if (File.Exists(ShortcutPath)) { File.Delete(ShortcutPath); Console.WriteLine("autostart removed"); }
            Console.WriteLine(StopAll() ? "agent stopped" : "agent may still be running (see Task Manager)");
            Credentials.Delete(Credentials.Vpn);
            Credentials.Delete(Credentials.Otp);
            Credentials.Delete(Credentials.Change);
            Credentials.Delete(Credentials.Held);
            Console.WriteLine("saved VPN password and TOTP seed removed");

            // The firewall rule needs admin to remove, same as to create.
            Console.Write("Remove the firewall rule too? A Windows admin prompt will appear. [Y/n]: ");
            string a = Console.ReadLine();
            if (a == null || a.Trim().Length == 0 || a.Trim().ToLowerInvariant().StartsWith("y"))
            {
                int r = Admin.ElevateRemove();
                Console.WriteLine(r == 0 ? "  firewall rule removed" :
                    r < 0 ? "  admin prompt declined; remove it by hand:  Remove-NetFirewallRule -DisplayName " + Admin.FirewallRule
                          : "  could not remove it (see log); by hand:  Remove-NetFirewallRule -DisplayName " + Admin.FirewallRule);
            }
            else Console.WriteLine("  left the firewall rule; remove it by hand:  Remove-NetFirewallRule -DisplayName " + Admin.FirewallRule);

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

        // Returns false when nothing new was saved.
        static bool SaveSecret(string label, string target, bool askUser)
        {
            string user = "", current;
            bool have = HasSecret(target);
            Console.Write("\n" + label + (have ? " (Enter keeps the saved one): " : ": "));
            if (askUser)
            {
                if (!TryUser(target, out current) || current == null) current = "";
                Console.Write("\n  VPN username" + (current.Length > 0 ? " [" + current + "]" : "") + ": ");
                string u = Console.ReadLine();
                if (u != null && u.Trim().Length > 0) user = u.Trim();
                else user = current;
                Console.Write("  password (typing hidden): ");
            }
            string secret = ReadHidden();
            if (secret.Length == 0)
            {
                if (have) { Console.WriteLine("  kept"); return false; }
                Console.WriteLine("  (skipped; set it later with vpn-keeper setup)");
                return false;
            }
            if (target == Credentials.Otp)
            {
                try { Totp.Base32Decode(secret); }
                catch (FormatException e) { Console.WriteLine("  not saved: " + e.Message); return false; }
            }
            if (askUser)
            {
                // A typo would be typed into the VPN and refused: ask twice.
                Console.Write("  again, to confirm: ");
                if (ReadHidden() != secret) { Console.WriteLine("  they differ; not saved"); return false; }
            }
            Credentials.Write(target, askUser ? user : "otp", secret);
            Console.WriteLine("  saved");
            return true;
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
            StopAll();
            Process.Start(new ProcessStartInfo(ShortcutPath) { UseShellExecute = true });
            Console.WriteLine("agent started");
        }

        // A supervisor that is still alive can restart the agent between two
        // kills, so keep killing until none is left (or give up after 5 s).
        static bool StopAll()
        {
            for (int pass = 0; pass < 20; pass++)
            {
                bool left = false;
                foreach (Process p in Process.GetProcessesByName("vpn-keeper"))
                    using (p)
                    {
                        if (p.Id == Process.GetCurrentProcess().Id) continue;
                        try
                        {
                            if (!p.HasExited) { left = true; p.Kill(); }   // still there if the kill is refused
                        }
                        catch (InvalidOperationException) { }
                        catch (System.ComponentModel.Win32Exception) { }
                    }
                if (!left) return true;
                Thread.Sleep(250);
            }
            return false;
        }

        static void ApplyAdminSteps(Config cfg, Lan lan)
        {
            AdminPlan plan = Admin.Plan(cfg, lan);
            Console.WriteLine("One admin step is left: a firewall rule so your clients can reach the proxy.");
            Console.Write("Apply it now? A Windows admin prompt will appear. [Y/n]: ");
            string a = Console.ReadLine();
            bool yes = a == null || a.Trim().Length == 0 || a.Trim().ToLowerInvariant().StartsWith("y");
            if (yes)
            {
                int r = Admin.Elevate(plan);
                if (r == 0) { Console.WriteLine("  done."); PrintProxyUrl(cfg, lan); return; }
                Console.WriteLine(r < 0 ? "  admin prompt declined." : "  could not apply it all (see the log); do it by hand:");
            }
            PrintManualSteps(plan);
            PrintProxyUrl(cfg, lan);
        }

        static void PrintManualSteps(AdminPlan plan)
        {
            Console.WriteLine("\nRun this in an administrator PowerShell:");
            Console.WriteLine("  New-NetFirewallRule -DisplayName '" + Admin.FirewallRule + "' -Direction Inbound -Protocol TCP -LocalPort "
                + plan.Port + " -RemoteAddress " + plan.RemoteIp + " -Action Allow -Profile Any");
        }

        static void PrintProxyUrl(Config cfg, Lan lan)
        {
            if (lan != null)
                Console.WriteLine("\nOn another PC, set the browser's automatic proxy script to:\n  http://" + lan.Address + ":" + cfg.Port + "/proxy.pac");
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
