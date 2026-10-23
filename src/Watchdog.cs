using System;
using System.Collections.Generic;
using System.Net;
using System.Threading;

namespace VpnKeeper
{
    // Decides when the VPN needs logging in and walks Connect Tunnel through
    // Connect -> password -> one-time code. A wrong password must never be
    // retried in a tight loop (it is a domain account that can lock), so
    // failures back off: 2 min, 5 min, then 60 min.
    static class Watchdog
    {
        public static readonly Status Status = new Status();

        // Swappable so the self-test can log in to the fake client without
        // touching the Windows Credential Manager.
        public delegate bool CredentialReader(string target, out string user, out string secret);
        public static CredentialReader ReadCredential = Credentials.TryRead;

        static int badChecks;
        static int failedLogins;
        static DateTime nextLogin = DateTime.MinValue;
        static long lastOtpStep = -1;

        // One pass of the agent loop; returns the seconds to wait before the next.
        public static int Tick(Config cfg)
        {
            Snapshot snap = Tunnel.Take();
            VpnState st = snap.State;
            Status.Set(st);

            // A login prompt is up (the 8h re-authentication, or a half-finished
            // login): answer it whether or not we started it.
            if (snap.PasswordDialog != null || snap.OtpDialog != null)
            {
                if (DateTime.Now >= nextLogin) Login(cfg, false);
                return 5;
            }

            switch (st)
            {
                case VpnState.NotRunning:
                    Tunnel.Start(cfg.ClientExe);
                    return 15;
                case VpnState.NoWindow:
                    // Running but no main window (e.g. minimised to the tray):
                    // starting it again brings the existing window back.
                    Log.Warn("Connect Tunnel is running without its window; reopening it");
                    Tunnel.Start(cfg.ClientExe);
                    return 15;
                case VpnState.Busy:
                    return 5;
                case VpnState.Down:
                    badChecks = 0;
                    if (DateTime.Now >= nextLogin) Login(cfg, true);
                    return 5;
            }

            // Up: make sure traffic really flows, not just the label.
            if (cfg.CheckUrl.Length == 0) return cfg.CheckInterval;   // nothing to check against: trust the label
            if (Probe(cfg.CheckUrl))
            {
                if (badChecks > 0) Log.Info("check URL answers again");
                badChecks = 0;
                Status.CheckOk();
                return cfg.CheckInterval;
            }
            badChecks++;
            Log.Warn("check " + cfg.CheckUrl + " failed (" + badChecks + "/" + cfg.FailedChecks + ") while Connect Tunnel says Connected");
            if (badChecks >= cfg.FailedChecks)
            {
                badChecks = 0;
                Win b = snap.MainButton;
                string caption = b == null ? "" : b.Text.Trim().ToLowerInvariant();
                if (caption.StartsWith("disc") || caption.StartsWith("desc"))
                {
                    Log.Warn("tunnel looks dead; disconnecting so it can log in again");
                    Tunnel.Click(b);
                }
            }
            return 10;
        }

        public static bool LoginOnce(Config cfg)
        {
            Snapshot snap = Tunnel.Take();
            if (snap.State == VpnState.NotRunning || snap.State == VpnState.NoWindow)
            {
                Tunnel.Start(cfg.ClientExe);
                for (int i = 0; i < 30 && (snap.State == VpnState.NotRunning || snap.State == VpnState.NoWindow); i++)
                {
                    Thread.Sleep(1000);
                    snap = Tunnel.Take();
                }
            }
            if (snap.State == VpnState.Up && snap.PasswordDialog == null && snap.OtpDialog == null)
            {
                Log.Info("already connected");
                return true;
            }
            return Login(cfg, snap.State == VpnState.Down);
        }

        // Runs the whole login, up to two minutes. pressConnect is false when a
        // prompt is already open and only needs answering.
        static bool Login(Config cfg, bool pressConnect)
        {
            string user, password, otpUser, seed;
            if (cfg.Profile.Length == 0)
            {
                Fail("set 'profile' in " + Config.DefaultPath() + " to the Connect Tunnel configuration to log in to", true);
                return false;
            }
            if (!ReadCredential(cfg.Credential, out user, out password))
            {
                Fail("no saved VPN password: run  cmdkey /generic:" + cfg.Credential + " /user:<vpn user> /pass", true);
                return false;
            }
            if (!ReadCredential(cfg.OtpCredential, out otpUser, out seed))
            {
                Fail("no saved OTP seed: run  cmdkey /generic:" + cfg.OtpCredential + " /user:otp /pass", true);
                return false;
            }
            byte[] key;
            try { key = Totp.Base32Decode(seed); }
            catch (FormatException e) { Fail(e.Message, true); return false; }

            Snapshot snap = Tunnel.Take();
            if (pressConnect)
            {
                Win combo = snap.Profile;
                if (combo != null && !string.Equals(combo.Text.Trim(), cfg.Profile, StringComparison.OrdinalIgnoreCase))
                {
                    Fail("Connect Tunnel has profile '" + combo.Text + "' selected, expected '" + cfg.Profile + "'; select it once by hand", true);
                    return false;
                }
                Win connect = snap.Main == null ? null : snap.Main.Button("Connect", "Conectar");
                if (connect == null || !connect.Enabled)
                {
                    Log.Warn("no enabled Connect button yet");
                    return false;
                }
                Log.Info("VPN is down; logging in to '" + cfg.Profile + "'");
                Tunnel.Click(connect);
            }

            HashSet<IntPtr> answered = new HashSet<IntPtr>();
            DateTime started = DateTime.Now;
            DateTime deadline = started.AddMinutes(2);
            int nudges = 0;
            while (DateTime.Now < deadline)
            {
                Thread.Sleep(1000);
                snap = Tunnel.Take();
                Status.Set(snap.State);

                foreach (Win box in snap.MessageBoxes)
                {
                    Log.Warn("Connect Tunnel says: " + Describe(box));
                    Win b = box.Button("OK", "Aceptar", "Close", "Cerrar");
                    if (b != null) Tunnel.Click(b);
                }

                if (snap.PasswordDialog != null)
                {
                    Win d = snap.PasswordDialog;
                    if (answered.Contains(d.Handle))
                    {
                        // Still open after we pressed OK: nudge it, then give up.
                        if (++nudges == 4) Nudge(d);
                        if (nudges > 10) { Fail("the password dialog did not accept the password", false); return false; }
                        continue;
                    }
                    Win userBox, passBox;
                    PasswordFields(d, out userBox, out passBox);
                    if (!string.IsNullOrEmpty(user) && userBox != null && userBox.Text.Trim() != user) Tunnel.SetText(userBox, user);
                    Tunnel.SetText(passBox, password);
                    Tunnel.Click(d.Button("OK", "Aceptar"));
                    answered.Add(d.Handle);
                    nudges = 0;
                    Log.Info("password entered");
                    continue;
                }

                if (snap.OtpDialog != null)
                {
                    Win d = snap.OtpDialog;
                    if (answered.Contains(d.Handle))
                    {
                        if (++nudges == 4) Nudge(d);
                        if (nudges > 10) { Fail("the one-time code dialog did not accept the code", false); return false; }
                        continue;
                    }
                    // A code is accepted once: never reuse the last one, and don't
                    // send one that expires before the server checks it.
                    DateTime now = DateTime.UtcNow;
                    long step = Totp.Step(now, cfg.OtpPeriod);
                    if (step == lastOtpStep || Totp.SecondsLeft(now, cfg.OtpPeriod) < 4) continue;
                    Win box = null;
                    foreach (Win e in d.Of("edit")) box = e;
                    Tunnel.SetText(box, Totp.Code(key, step, cfg.OtpDigits));
                    Tunnel.Click(d.Button("OK", "Aceptar"));
                    lastOtpStep = step;
                    answered.Add(d.Handle);
                    nudges = 0;
                    Log.Info("one-time code entered");
                    continue;
                }

                VpnState st = snap.State;
                if (st == VpnState.Up)
                {
                    Log.Info("VPN connected (login took " + (int)(DateTime.Now - started).TotalSeconds + " s)");
                    failedLogins = 0;
                    nextLogin = DateTime.MinValue;
                    Status.LoggedIn();
                    return true;
                }
                if (st == VpnState.Down && (DateTime.Now - started).TotalSeconds > 10)
                {
                    Fail("Connect Tunnel went back to Disconnected", false);
                    return false;
                }
            }
            Fail("login timed out after 2 minutes", false);
            return false;
        }

        // The username box comes first; the password box is the one after the
        // "Contraseña"/"Password" label, or the last box.
        static void PasswordFields(Win d, out Win userBox, out Win passBox)
        {
            List<Win> edits = new List<Win>(d.Of("edit"));
            passBox = null;
            bool afterLabel = false;
            foreach (Win k in d.Kids)
            {
                if (k.Kind == "static")
                {
                    string t = k.Text.ToLowerInvariant();
                    afterLabel = t.Contains("contrase") || t.Contains("password");
                }
                else if (k.Kind == "edit" && afterLabel && passBox == null) passBox = k;
            }
            if (passBox == null) passBox = edits[edits.Count - 1];
            userBox = edits.Count > 1 && edits[0] != passBox ? edits[0] : null;
        }

        // If OK was ignored, try a mouse press on OK, then Enter in the last box.
        static void Nudge(Win dialog)
        {
            Log.Warn("dialog still open; pressing OK another way");
            Win ok = dialog.Button("OK", "Aceptar");
            if (ok != null) Tunnel.ClickMouse(ok);
            Win last = null;
            foreach (Win e in dialog.Of("edit")) last = e;
            if (last != null) Tunnel.PressEnter(last);
        }

        static void Fail(string why, bool configProblem)
        {
            failedLogins++;
            int minutes = configProblem ? 5 : failedLogins == 1 ? 2 : failedLogins == 2 ? 5 : 60;
            nextLogin = DateTime.Now.AddMinutes(minutes);
            Log.Error("login failed: " + why + "; next try in " + minutes + " min");
            Status.Failed(why);
        }

        static string Describe(Win w)
        {
            List<string> parts = new List<string>();
            foreach (Win k in w.Kids) if (k.Kind == "static" && k.Text.Trim().Length > 0) parts.Add(k.Text.Trim());
            return w.Text + ": " + string.Join(" | ", parts.ToArray());
        }

        static bool Probe(string url)
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
                // Any HTTP answer, even an error page, means the path works.
                if (e.Response != null) { e.Response.Close(); return true; }
                return false;
            }
        }
    }

    // What /health reports.
    class Status
    {
        readonly object gate = new object();
        VpnState state = VpnState.NotRunning;
        DateTime since = DateTime.Now;
        DateTime lastLogin = DateTime.MinValue;
        DateTime lastCheck = DateTime.MinValue;
        string lastError = "";

        public void Set(VpnState s) { lock (gate) { if (s != state) { state = s; since = DateTime.Now; Log.Info("state: " + s); } } }
        public void LoggedIn() { lock (gate) { lastLogin = DateTime.Now; lastError = ""; } }
        public void CheckOk() { lock (gate) { lastCheck = DateTime.Now; } }
        public void Failed(string why) { lock (gate) { lastError = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss") + " " + why; } }

        public VpnState State { get { lock (gate) return state; } }

        public string Report()
        {
            lock (gate)
            {
                return "vpn: " + state + " since " + since.ToString("yyyy-MM-dd HH:mm:ss") + "\n"
                    + "last login: " + (lastLogin == DateTime.MinValue ? "-" : lastLogin.ToString("yyyy-MM-dd HH:mm:ss")) + "\n"
                    + "last good check: " + (lastCheck == DateTime.MinValue ? "-" : lastCheck.ToString("yyyy-MM-dd HH:mm:ss")) + "\n"
                    + "last error: " + (lastError.Length == 0 ? "-" : lastError) + "\n"
                    + "version: " + BuildInfo.Version + "\n";
            }
        }
    }
}
