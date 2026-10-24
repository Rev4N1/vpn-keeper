using System;
using System.Threading;

namespace VpnKeeper
{
    static class Agent
    {
        public static int Run(Config cfg)
        {
            bool created;
            using (Mutex single = new Mutex(true, @"Local\vpn-keeper", out created))
            {
                if (!created)
                {
                    Log.Warn("another vpn-keeper is already running in this session; exiting");
                    return 3;
                }
                Log.Info("vpn-keeper " + BuildInfo.Version + " starting (config " + Config.DefaultPath() + ")");
                if (cfg.KeepAwake) Awake.Hold();

                Proxy proxy = null;
                try
                {
                    proxy = new Proxy(cfg.Listen, new Rules(cfg.Clients), new Rules(cfg.Allow), Watchdog.Status.Report);
                    proxy.Start();
                }
                catch (Exception e)
                {
                    // The VPN keeper is still useful without the proxy (e.g. port taken).
                    Log.Error("proxy did not start: " + e.Message);
                }

                while (true)
                {
                    int wait;
                    try { wait = Watchdog.Tick(cfg); }
                    catch (Exception e)
                    {
                        Log.Error("watchdog: " + e);
                        wait = 30;
                    }
                    Thread.Sleep(wait * 1000);
                }
            }
        }

        // Read-only checks for setup; prints what is missing.
        public static int Check(Config cfg)
        {
            int problems = 0;
            Console.WriteLine("vpn-keeper " + BuildInfo.Version);
            Console.WriteLine("config: " + Config.DefaultPath() + (System.IO.File.Exists(Config.DefaultPath()) ? "" : " (not found, using defaults)"));

            string user, secret;
            if (Credentials.TryRead(cfg.Credential, out user, out secret) && secret.Length > 0)
                Console.WriteLine("[ ok ] VPN password saved for user '" + user + "' (" + cfg.Credential + ")");
            else { problems++; Console.WriteLine("[FAIL] no VPN password: cmdkey /generic:" + cfg.Credential + " /user:<vpn user> /pass"); }

            if (Credentials.TryRead(cfg.OtpCredential, out user, out secret) && secret.Length > 0)
            {
                try
                {
                    Totp.Base32Decode(secret);
                    Console.WriteLine("[ ok ] OTP seed saved and valid (" + cfg.OtpCredential + "); compare  vpn-keeper.exe otp  with your app");
                }
                catch (FormatException e) { problems++; Console.WriteLine("[FAIL] OTP seed: " + e.Message); }
            }
            else { problems++; Console.WriteLine("[FAIL] no OTP seed: cmdkey /generic:" + cfg.OtpCredential + " /user:otp /pass"); }

            if (cfg.Profile.Length == 0) { problems++; Console.WriteLine("[FAIL] 'profile' is not set (the Connect Tunnel configuration name)"); }
            else Console.WriteLine("[ ok ] profile '" + cfg.Profile + "'");
            if (cfg.CheckUrl.Length == 0) Console.WriteLine("[warn] 'check_url' is not set: a stuck tunnel that still says Connected goes unnoticed");
            else Console.WriteLine("[ ok ] check_url " + cfg.CheckUrl);
            if (cfg.Allow.Count == 0) Console.WriteLine("[warn] 'allow' is empty: the proxy refuses every destination");
            else Console.WriteLine("[ ok ] proxy may reach " + string.Join(" ", cfg.Allow.ToArray()));

            if (System.IO.File.Exists(cfg.ClientExe)) Console.WriteLine("[ ok ] Connect Tunnel at " + cfg.ClientExe);
            else { problems++; Console.WriteLine("[FAIL] Connect Tunnel not found at " + cfg.ClientExe + " (set client_exe)"); }

            Snapshot snap = Tunnel.Take();
            Console.WriteLine("[info] Connect Tunnel state: " + snap.State
                + (snap.Profile != null ? ", profile '" + snap.Profile.Text + "'" : "")
                + (snap.MainButton != null ? ", button '" + snap.MainButton.Text + "'" : ""));
            if (snap.Profile != null && cfg.Profile.Length > 0 && !string.Equals(snap.Profile.Text.Trim(), cfg.Profile, StringComparison.OrdinalIgnoreCase))
            {
                problems++;
                Console.WriteLine("[FAIL] profile '" + snap.Profile.Text + "' selected, expected '" + cfg.Profile + "'");
            }
            Console.WriteLine("[info] proxy will listen on " + cfg.Listen + "; PAC at http://<this laptop>:" + cfg.Listen.Substring(cfg.Listen.LastIndexOf(':') + 1) + "/proxy.pac");
            Console.WriteLine(problems == 0 ? "all good" : problems + " problem(s)");
            return problems == 0 ? 0 : 1;
        }

        // What the agent sees of Connect Tunnel, for diagnosing a client update.
        // Text boxes show only their length, never their contents.
        public static int Dump()
        {
            Snapshot snap = Tunnel.Take();
            Console.WriteLine("Connect Tunnel running: " + snap.Running + ", state: " + snap.State);
            foreach (Win w in snap.Windows)
            {
                string role = w == snap.Main ? "MAIN" : w == snap.PasswordDialog ? "LOGIN PROMPT" : w == snap.OtpDialog ? "CODE PROMPT"
                    : snap.MessageBoxes.Contains(w) ? "MESSAGE BOX" : "other";
                Console.WriteLine();
                Console.WriteLine("[" + role + "] \"" + w.Caption + "\"  class=" + w.Class + (w.Enabled ? "" : "  (disabled)"));
                foreach (Win k in w.Kids)
                {
                    if (k.Kind == "window") continue;
                    string text = k.Kind == "edit" ? "<" + k.Text.Length + " chars>" : "\"" + k.Text + "\"";
                    Console.WriteLine("    " + k.Kind.PadRight(9) + text + (k.Enabled ? "" : "  (disabled)")
                        + (k == snap.StatusLabel ? "  <- status" : k == snap.MainButton ? "  <- main button" : ""));
                }
            }
            return 0;
        }

        public static int PrintOtp(Config cfg)
        {
            string user, seed;
            if (!Credentials.TryRead(cfg.OtpCredential, out user, out seed))
            {
                Console.WriteLine("no OTP seed saved: cmdkey /generic:" + cfg.OtpCredential + " /user:otp /pass");
                return 1;
            }
            DateTime now = DateTime.UtcNow;
            Console.WriteLine(Totp.Code(Totp.Base32Decode(seed), Totp.Step(now, cfg.OtpPeriod), cfg.OtpDigits)
                + "  (valid " + Totp.SecondsLeft(now, cfg.OtpPeriod) + " more seconds)");
            return 0;
        }
    }
}
