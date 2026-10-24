using System;
using System.Collections.Generic;
using System.Net;
using System.Threading;

namespace VpnKeeper
{
    // Decides when the VPN needs logging in, and walks Connect Tunnel through
    // Connect -> password -> one-time code.
    static class Watchdog
    {
        const int CheckEvery = 30;      // seconds between checks while connected
        const int FailedChecks = 3;     // failed checks in a row = dead tunnel
        const int OtpDigits = 6, OtpPeriod = 30;

        public static readonly Status Status = new Status();

        // Swappable so the tests can log in to the fake client.
        public delegate bool CredentialReader(string target, out string user, out string secret);
        public static CredentialReader ReadCredential = Credentials.TryRead;

        static int badChecks;
        static int failedLogins;
        static DateTime nextLogin = DateTime.MinValue;
        static long lastOtpStep = -1;
        static DateTime noWindowSince = DateTime.MaxValue;

        // One pass of the agent loop; returns the seconds until the next.
        public static int Tick(Config cfg)
        {
            Snapshot snap = Tunnel.Take();
            VpnState st = snap.State;
            Status.Set(st);
            if (st != VpnState.NoWindow) noWindowSince = DateTime.MaxValue;

            // A login prompt is open (the server asking again, or a half-done
            // login): answer it, whoever started it.
            if (snap.PasswordDialog != null || snap.OtpDialog != null)
            {
                if (DateTime.Now >= nextLogin) Login(cfg, false);
                return 5;
            }

            switch (st)
            {
                case VpnState.NotRunning:
                    Tunnel.Start();
                    return 15;
                case VpnState.NoWindow:
                    // Running but no readable window (normally a moment while it
                    // opens). If it lasts, starting it again brings the running
                    // copy's window back; Connect Tunnel is single-instance.
                    if (noWindowSince == DateTime.MaxValue) noWindowSince = DateTime.Now;
                    if ((DateTime.Now - noWindowSince).TotalMinutes < 2) return 10;
                    Log.Warn("Connect Tunnel has shown no window for 2 minutes; reopening it");
                    Tunnel.Start();
                    noWindowSince = DateTime.Now;
                    return 15;
                case VpnState.Busy:
                    return 5;
                case VpnState.Down:
                    badChecks = 0;
                    if (DateTime.Now >= nextLogin) Login(cfg, true);
                    return 5;
            }

            // Up. The check also keeps the session from idling out.
            if (cfg.CheckUrl.Length == 0 || Probe(cfg.CheckUrl))
            {
                if (badChecks > 0) Log.Info("check URL answers again");
                badChecks = 0;
                Status.CheckOk();
                return CheckEvery;
            }
            badChecks++;
            Log.Warn("check " + cfg.CheckUrl + " failed (" + badChecks + "/" + FailedChecks + ") while Connect Tunnel says Connected");
            if (badChecks >= FailedChecks)
            {
                badChecks = 0;
                Win b = snap.MainButton;
                if (b != null && Tunnel.Is(b, "Disconnect", "Desconectar"))
                {
                    Log.Warn("tunnel looks dead; disconnecting so it can log in again");
                    Tunnel.Click(b);
                }
            }
            return 10;
        }

        // The whole login, two minutes at most. pressConnect is false when a
        // prompt is already open and only needs answering.
        static bool Login(Config cfg, bool pressConnect)
        {
            if (cfg.Profile.Length == 0) { Fail("no profile set (run vpn-keeper setup)", true); return false; }
            string user, password, otpUser, seed;
            if (!ReadCredential(Credentials.Vpn, out user, out password)) { Fail("no saved VPN password (run vpn-keeper setup)", true); return false; }
            if (!ReadCredential(Credentials.Otp, out otpUser, out seed)) { Fail("no saved TOTP seed (run vpn-keeper setup)", true); return false; }
            byte[] key;
            try { key = Totp.Base32Decode(seed); }
            catch (FormatException e) { Fail(e.Message + " (run vpn-keeper setup)", true); return false; }

            Snapshot snap = Tunnel.Take();
            if (pressConnect)
            {
                Win combo = snap.Profile;
                if (combo != null && !string.Equals(combo.Caption, cfg.Profile, StringComparison.OrdinalIgnoreCase))
                {
                    Fail("Connect Tunnel has '" + combo.Caption + "' selected, not '" + cfg.Profile + "'; select it once in Connect Tunnel", true);
                    return false;
                }
                Win connect = snap.Main == null ? null : snap.Main.Button("Connect", "Conectar");
                if (connect == null || !connect.Enabled)
                {
                    Log.Warn("no enabled Connect button; buttons seen: " + snap.ButtonList() + " (see vpn-keeper status)");
                    return false;
                }
                Log.Info("VPN is down; logging in to '" + cfg.Profile + "'");
                Tunnel.Click(connect);
            }

            HashSet<IntPtr> answered = new HashSet<IntPtr>();
            DateTime started = DateTime.Now;
            int nudges = 0;
            while ((DateTime.Now - started).TotalMinutes < 2)
            {
                Thread.Sleep(1000);
                snap = Tunnel.Take();
                Status.Set(snap.State);

                foreach (Win box in snap.MessageBoxes)
                {
                    Log.Warn("Connect Tunnel says: " + box.Summary());
                    Win b = box.Button("OK", "Aceptar", "Close", "Cerrar");
                    if (b != null) Tunnel.Click(b);
                }

                Win d = snap.PasswordDialog ?? snap.OtpDialog;
                if (d != null)
                {
                    if (answered.Contains(d.Handle))
                    {
                        // Still open after OK: press OK another way, then give up.
                        if (++nudges == 4) Tunnel.Nudge(d);
                        if (nudges > 10)
                        {
                            Fail(d == snap.PasswordDialog ? "the password was not accepted" : "the one-time code was not accepted", false);
                            return false;
                        }
                        continue;
                    }
                    if (d == snap.PasswordDialog)
                    {
                        Win userBox, passBox;
                        Tunnel.PasswordFields(d, out userBox, out passBox);
                        if (!string.IsNullOrEmpty(user) && userBox != null && userBox.Text.Trim() != user) Tunnel.SetText(userBox, user);
                        Tunnel.SetText(passBox, password);
                        Log.Info("password entered");
                    }
                    else
                    {
                        // A code works once: never resend the last one, and don't
                        // send one about to expire.
                        DateTime now = DateTime.UtcNow;
                        long step = Totp.Step(now, OtpPeriod);
                        if (step == lastOtpStep || Totp.SecondsLeft(now, OtpPeriod) < 4) continue;
                        Win box = null;
                        foreach (Win e in d.Of("edit")) box = e;
                        Tunnel.SetText(box, Totp.Code(key, step, OtpDigits));
                        lastOtpStep = step;
                        Log.Info("one-time code entered");
                    }
                    Tunnel.Click(d.Button("OK", "Aceptar"));
                    answered.Add(d.Handle);
                    nudges = 0;
                    continue;
                }

                if (snap.State == VpnState.Up)
                {
                    Log.Info("VPN connected (login took " + (int)(DateTime.Now - started).TotalSeconds + " s)");
                    failedLogins = 0;
                    nextLogin = DateTime.MinValue;
                    Status.LoggedIn();
                    return true;
                }
                if (snap.State == VpnState.Down && (DateTime.Now - started).TotalSeconds > 10)
                {
                    Fail("Connect Tunnel went back to Disconnected", false);
                    return false;
                }
            }
            Fail("login timed out after 2 minutes", false);
            return false;
        }

        // Corporate VPN passwords often belong to accounts that lock after a few
        // failures, so a failed login waits 2 min, then 5, then 60.
        static void Fail(string why, bool setupProblem)
        {
            failedLogins++;
            int minutes = setupProblem ? 5 : failedLogins == 1 ? 2 : failedLogins == 2 ? 5 : 60;
            nextLogin = DateTime.Now.AddMinutes(minutes);
            Log.Error("login failed: " + why + "; next try in " + minutes + " min");
            Status.Failed(why);
        }

        // Any HTTP answer, even an error page, means the path through the VPN works.
        public static bool Probe(string url)
        {
            try
            {
                HttpWebRequest req = (HttpWebRequest)WebRequest.Create(url);
                req.Timeout = 10000;
                req.ReadWriteTimeout = 10000;
                req.AllowAutoRedirect = false;
                req.Proxy = null;
                using (req.GetResponse()) { }
                return true;
            }
            catch (WebException e)
            {
                if (e.Response == null) return false;
                e.Response.Close();
                return true;
            }
            catch (UriFormatException) { return false; }
        }
    }

    // What /health shows.
    class Status
    {
        readonly object gate = new object();
        VpnState state = VpnState.NotRunning;
        DateTime since = DateTime.Now, lastLogin = DateTime.MinValue, lastCheck = DateTime.MinValue;
        string lastError = "";

        public void Set(VpnState s) { lock (gate) { if (s != state) { state = s; since = DateTime.Now; Log.Info("state: " + s); } } }
        public void LoggedIn() { lock (gate) { lastLogin = DateTime.Now; lastError = ""; } }
        public void CheckOk() { lock (gate) { lastCheck = DateTime.Now; } }
        public void Failed(string why) { lock (gate) { lastError = Time(DateTime.Now) + " " + why; } }

        public string Report()
        {
            lock (gate)
            {
                return "vpn: " + state + " since " + Time(since) + "\n"
                    + "last login: " + Time(lastLogin) + "\n"
                    + "last good check: " + Time(lastCheck) + "\n"
                    + "last error: " + (lastError.Length == 0 ? "-" : lastError) + "\n"
                    + "version: " + BuildInfo.Version + "\n";
            }
        }

        static string Time(DateTime t) { return t == DateTime.MinValue ? "-" : t.ToString("yyyy-MM-dd HH:mm:ss"); }
    }
}
