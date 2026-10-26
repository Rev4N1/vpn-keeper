using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Security.Cryptography;
using System.Text;
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
        public delegate void CredentialWriter(string target, string user, string secret);
        public static CredentialWriter WriteCredential = Credentials.Write;

        static int badChecks;
        static int failedLogins;
        static DateTime nextLogin = DateTime.MinValue;
        static long lastOtpStep = -1;
        static DateTime noWindowSince = DateTime.MaxValue, busySince = DateTime.MaxValue;
        static string heldPassword;     // the saved password the VPN refused; no login until it changes
        static bool heldLoaded;         // whether the persisted hold above has been read
        static string changeSent;       // the queued password last typed into a change prompt
        static bool oldRefused;         // a notice said the saved password is wrong; switch to the queued one
        static bool forced;             // this login was forced from /password
        static string lastConnectProblem;   // avoid repeating the same warning every pass

        // One pass of the agent loop; returns the seconds until the next.
        public static int Tick(Config cfg)
        {
            LoadHeld();   // a refusal from before a restart must stop the very first login
            Snapshot snap = Tunnel.Take();
            VpnState st = snap.State;
            Status.Set(st);
            if (st != VpnState.NoWindow) noWindowSince = DateTime.MaxValue;
            if (st != VpnState.Busy) busySince = DateTime.MaxValue;

            // A notice left open (the server's idle timeout shows one) keeps the
            // main window modal-blocked, so Connect would never respond: close it first.
            if (Dismiss(snap)) return 2;

            // Outside the allowed hours: keep the VPN down. Cancel any prompt
            // (including a required password change), and disconnect if it is
            // up; never start a login, even with a queued password.
            if (!Schedule.Parse(cfg.Hours).Active(DateTime.Now))
            {
                Win prompt = snap.ChangeDialog ?? snap.PasswordDialog ?? snap.OtpDialog;
                Win cancel = prompt == null ? null : prompt.Button("Cancel", "Cancelar");
                bool acted = false;
                if (cancel != null)
                {
                    Tunnel.Click(cancel);
                    if (prompt == snap.ChangeDialog) Status.Asking("");
                    acted = true;
                }
                Win b = snap.MainButton;
                if (st == VpnState.Up && b != null && Tunnel.Is(b, "Disconnect", "Desconectar"))
                {
                    Log.Info("outside the allowed hours (" + cfg.Hours + "); disconnecting");
                    Tunnel.Click(b);
                    acted = true;
                }
                return acted ? 5 : 60;
            }

            // The VPN asks for a new password. With one queued on /password, the
            // login fills it in. Without, that is the user's to choose: leave the
            // prompt open, stop logging in, and say so.
            if (snap.ChangeDialog != null)
            {
                Dump(snap.ChangeDialog, "change-prompt");
                Status.Asking("the VPN requires a new password now");
                if (QueuedPassword().Length > 0)
                {
                    if (DateTime.Now >= nextLogin) Login(cfg, false);
                    return 5;
                }
                if (heldPassword == null) Hold("the VPN requires a new password");
                else if (SavedPassword() != heldPassword)
                {
                    // A new password was saved (changed elsewhere): drop the prompt and log in with it.
                    Win cancel = snap.ChangeDialog.Button("Cancel", "Cancelar");
                    if (cancel != null) { Log.Info("new password saved; closing the change prompt"); Tunnel.Click(cancel); return 5; }
                }
                return 10;
            }

            // "Force" on /password: reconnect now, so the login gives the VPN its
            // chance to ask for the change instead of waiting for the next one.
            string forceUser, queued;
            if (ReadCredential(Credentials.Change, out forceUser, out queued) && forceUser == "force" && !string.IsNullOrEmpty(queued))
            {
                WriteCredential(Credentials.Change, "", queued);   // once
                forced = true;
                Win b = snap.MainButton;
                if (st == VpnState.Up && b != null && Tunnel.Is(b, "Disconnect", "Desconectar"))
                {
                    Log.Info("forced: reconnecting so the VPN can ask for the password change now");
                    Tunnel.Click(b);
                    return 5;
                }
            }

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
                    // Connecting or reconnecting with no prompt is normally seconds;
                    // stuck for minutes, cancel it so the next pass logs in fresh.
                    if (busySince == DateTime.MaxValue) busySince = DateTime.Now;
                    if ((DateTime.Now - busySince).TotalMinutes < 3) return 5;
                    Win cancelBusy = snap.MainButton;
                    Log.Warn("Connect Tunnel stuck at '" + snap.StatusLabel.Caption + "' for 3 minutes; cancelling");
                    if (cancelBusy != null) Tunnel.Click(cancelBusy);
                    busySince = DateTime.MaxValue;
                    return 5;
                case VpnState.Down:
                    badChecks = 0;
                    if (DateTime.Now >= nextLogin) Login(cfg, true);
                    return 5;
            }

            // Up. (The check does not stop the server's idle timeout; the login after it does the recovering.)
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
            LoadHeld();
            if (cfg.Profile.Length == 0) { Fail("no profile set (run vpn-keeper setup)", true); return false; }
            string user, password, otpUser, seed;
            if (!ReadCredential(Credentials.Vpn, out user, out password)) { Fail("no saved VPN password (run vpn-keeper setup)", true); return false; }
            if (!ReadCredential(Credentials.Otp, out otpUser, out seed)) { Fail("no saved TOTP seed (run vpn-keeper setup)", true); return false; }
            byte[] key;
            try { key = Totp.Base32Decode(seed); }
            catch (FormatException e) { Fail(e.Message + " (run vpn-keeper setup)", true); return false; }
            string queued = QueuedPassword();
            bool changePrompt = Tunnel.Take().ChangeDialog != null;
            if (heldPassword != null || oldRefused)
            {
                // Retrying a refused password could lock the account. A new saved one
                // is used; a queued one fills an open change prompt, or else is
                // switched to (changed elsewhere), once: if refused too, it is held.
                if (heldPassword != null && password != heldPassword)
                {
                    Log.Info("the saved VPN password changed; logging in again");
                    ClearHeld();
                    failedLogins = 0;
                }
                else if (queued.Length > 0 && queued != password && !changePrompt)
                {
                    Promote(queued, "the old password was refused; switching to the new one");
                    password = queued;
                }
                else if (heldPassword != null && !(queued.Length > 0 && changePrompt)) return false;
                oldRefused = false;
            }

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
                    // Another window (a notice with a new layout, a settings box)
                    // can modal-disable Connect. Close the safe button on any such
                    // window and try again in a moment, instead of sitting there.
                    if (snap.Blockers.Count > 0)
                    {
                        bool closed = false;
                        foreach (Win w in snap.Blockers)
                        {
                            Dump(w, "blocking");
                            Win b = w.Button("Close", "Cerrar", "Cancel", "Cancelar", "OK", "Aceptar");
                            string what = w.Summary() + (b == null ? " (no button to close it)" : "; closing it");
                            if (what != lastConnectProblem) Log.Warn("a window is in Connect's way: " + what);
                            lastConnectProblem = what;
                            if (b != null) { Tunnel.Click(b); closed = true; }
                        }
                        Status.Failed(closed ? "Connect was disabled by another window; it was closed"
                            : "Connect is disabled by a window with no button to close it (see dumps)");
                        nextLogin = DateTime.Now.AddSeconds(5);
                        return false;
                    }

                    // Not a failed login (no backoff), but show it on /health and
                    // don't repeat the warning on every pass.
                    string why = "no enabled Connect button; buttons seen: " + snap.ButtonList() + "; on screen: " + snap.OnScreen();
                    if (why != lastConnectProblem) Log.Warn(why + " (see vpn-keeper status)");
                    lastConnectProblem = why;
                    Status.Failed(why);
                    nextLogin = DateTime.Now.AddSeconds(30);
                    return false;
                }
                lastConnectProblem = null;
                Log.Info("VPN is down; logging in to '" + cfg.Profile + "'");
                Tunnel.Click(connect);
            }

            HashSet<IntPtr> answered = new HashSet<IntPtr>();
            DateTime started = DateTime.Now;
            int nudges = 0, passwords = 0;
            bool moved = !pressConnect;   // left Disconnected at least once
            while ((DateTime.Now - started).TotalMinutes < 2)
            {
                Thread.Sleep(1000);
                snap = Tunnel.Take();
                Status.Set(snap.State);

                if (Dismiss(snap) && (heldPassword != null || oldRefused)) return false;   // it said the password is wrong or expired

                Win c = snap.ChangeDialog;
                if (c != null)
                {
                    queued = QueuedPassword();
                    if (queued.Length == 0) return false;   // Tick holds
                    if (answered.Contains(c.Handle))
                    {
                        if (++nudges == 4) Tunnel.Nudge(c);
                        if (nudges <= 10) continue;
                    }
                    else if (changeSent != queued)
                    {
                        Win oldBox, newBox, confirmBox;
                        Tunnel.ChangeFields(c, out oldBox, out newBox, out confirmBox);
                        if (newBox == null)
                        {
                            Dump(c, "change-prompt");
                            Fail("the change-password prompt has no new-password box (see dumps)", false);
                            return false;
                        }
                        if (oldBox != null) Tunnel.SetText(oldBox, password);
                        Tunnel.SetText(newBox, queued);
                        if (confirmBox != null) Tunnel.SetText(confirmBox, queued);
                        Log.Info("password change: new password entered");
                        Win submit = c.Button("OK", "Aceptar", "Change", "Cambiar", "Save", "Guardar", "Submit", "Enviar");
                        if (submit == null)
                        {
                            Dump(c, "change-prompt");
                            Fail("the change-password prompt has no OK button (see dumps)", false);
                            return false;
                        }
                        changeSent = queued;
                        Tunnel.Click(submit);
                        answered.Add(c.Handle);
                        nudges = 0;
                        continue;
                    }
                    // Asked again for the same one, or it stayed open: refused
                    // (too simple, used before...). Drop it; never retype it.
                    WriteCredential(Credentials.Change, "", "");
                    changeSent = null;
                    Log.Error("the VPN did not accept the new password; it was dropped (queue another on /password)");
                    Status.Failed("the VPN did not accept the new password (see last notice); queue another on /password");
                    Win cancel = c.Button("Cancel", "Cancelar");
                    if (cancel != null) Tunnel.Click(cancel);
                    return false;
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
                        // Asked again in the same login: the password was refused.
                        if (passwords++ > 0)
                        {
                            // With a new one queued (changed elsewhere, or a change went
                            // through and the login after it did not finish), switch to it.
                            string q = QueuedPassword();
                            if (q.Length > 0 && q != password) { Promote(q, "the VPN refused the saved password; switching to the new one"); return false; }
                            Hold("the VPN refused the saved password");
                            return false;
                        }
                        Win userBox, passBox;
                        Tunnel.PasswordFields(d, out userBox, out passBox);
                        if (passBox == null)
                        {
                            Dump(d, "login-prompt");
                            Fail("the login prompt has no password box (see dumps)", false);
                            return false;
                        }
                        if (!string.IsNullOrEmpty(user) && userBox != null && userBox.Text.Trim() != user) Tunnel.SetText(userBox, user);
                        Tunnel.SetText(passBox, password);
                        Log.Info("password entered");

                        // Force: tick the prompt's "change password" box, so the VPN asks
                        // for the new one right after this login. Otherwise leave it clear.
                        Dump(d, "login-prompt");
                        bool tick = forced && QueuedPassword().Length > 0;
                        Win box = Tunnel.ChangeBox(d);
                        if (box != null)
                        {
                            Tunnel.SetChecked(box, tick);
                            if (tick) Log.Info("forced: ticked '" + box.Caption + "'");
                        }
                        else if (tick)
                        {
                            Log.Warn("forced, but the login prompt has no change-password box (its layout is in dumps)");
                            Status.Notice("forced: no change-password box in the login prompt; the new password stays queued");
                        }
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
                        if (box == null)
                        {
                            Dump(d, "otp-prompt");
                            Fail("the one-time-code prompt has no box (see dumps)", false);
                            return false;
                        }
                        Tunnel.SetText(box, Totp.Code(key, step, OtpDigits));
                        lastOtpStep = step;
                        Log.Info("one-time code entered");
                    }
                    Win ok = d.Button("OK", "Aceptar");
                    if (ok == null)
                    {
                        Dump(d, "prompt");
                        Fail("the login prompt has no OK button (see dumps)", false);
                        return false;
                    }
                    Tunnel.Click(ok);
                    answered.Add(d.Handle);
                    nudges = 0;
                    continue;
                }

                if (snap.State == VpnState.Up)
                {
                    if (changeSent != null && changeSent == QueuedPassword()) Promote(changeSent, "VPN password changed on the VPN; the new one is now the saved one");
                    if (forced && QueuedPassword().Length > 0) Status.Notice("forced reconnect: the VPN did not ask for a password change; the new password stays queued");
                    forced = false;
                    Log.Info("VPN connected (login took " + (int)(DateTime.Now - started).TotalSeconds + " s)");
                    failedLogins = 0;
                    nextLogin = DateTime.MinValue;
                    Status.LoggedIn();
                    return true;
                }
                if (snap.State != VpnState.Down) moved = true;
                if (snap.State == VpnState.Down && (DateTime.Now - started).TotalSeconds > 10)
                {
                    if (!moved && answered.Count == 0)
                    {
                        // Connect was ignored (something modal in the way): nothing was
                        // sent, so no lockout risk; retry soon instead of backing off.
                        foreach (Win w in snap.Windows) if (w.Visible && w != snap.Main) Dump(w, "blocking");
                        string why = "Connect did nothing; on screen: " + snap.OnScreen();
                        Log.Warn(why);
                        Status.Failed(why);
                        nextLogin = DateTime.Now.AddSeconds(30);
                        return false;
                    }
                    Fail("Connect Tunnel went back to Disconnected", false);
                    return false;
                }
            }
            Fail("login timed out after 2 minutes", false);
            return false;
        }

        // Answers every notice and question on screen; true if there was one.
        static bool Dismiss(Snapshot snap)
        {
            foreach (Win box in snap.MessageBoxes)
            {
                string text = box.Summary();
                Log.Warn("Connect Tunnel says: " + text);
                Status.Notice(text);
                Dump(box, "notice");
                Win yes = box.Button(Tunnel.YesCaptions), no = box.Button(Tunnel.NoCaptions);
                if (no != null && yes != null && Tunnel.OffersPasswordChange(text))
                {
                    // "Your password expires soon; change it now?" Yes only with a
                    // new one queued on /password; otherwise not now, and log in.
                    bool queued = QueuedPassword().Length > 0;
                    Log.Info(queued ? "the VPN offers a password change; accepting (one is queued)" : "the VPN offers a password change; declining (none queued on /password)");
                    Status.Asking(queued ? "the VPN offered a password change; changing to the queued one" : "the VPN offers a password change; declined at each login until you queue a new password");
                    Tunnel.Click(queued ? yes : no);
                    continue;
                }
                Win b = box.Button("OK", "Aceptar", "Close", "Cerrar") ?? no;   // a notice, or an unknown question: the safe answer
                if (b != null) Tunnel.Click(b);
                if (Tunnel.PasswordRefused(text))
                {
                    string lower = text.ToLowerInvariant();
                    if (changeSent != null && (lower.Contains("new password") || lower.Contains("nueva contrase")))
                    {
                        // The change prompt normally reappears; if a notice is the
                        // only answer, do not save (promote) the refused new one.
                        WriteCredential(Credentials.Change, "", "");
                        changeSent = null;
                        Log.Error("the VPN refused the new password; it was dropped (queue another on /password)");
                        Status.Failed("the VPN refused the new password; queue another on /password");
                    }
                    else if (changeSent == null)
                    {
                        // With a new one queued, the next login switches to it; else hold.
                        if (QueuedPassword().Length > 0) oldRefused = true;
                        else if (heldPassword == null) Hold("Connect Tunnel says the password is wrong or expired");
                    }
                }
            }
            return snap.MessageBoxes.Count > 0;
        }

        // Writes a window's full layout (captions, labels, button and box kinds;
        // never what is typed in a box) to dumps\, once per distinct window, so
        // a prompt nobody has seen yet can be studied afterwards.
        static readonly HashSet<string> dumped = new HashSet<string>();
        static void Dump(Win w, string kind)
        {
            string text = Tunnel.Dump(w);
            if (!dumped.Add(text)) return;
            if (dumped.Count > 500) dumped.Clear();   // layouts with changing text over months
            try
            {
                string dir = Path.Combine(Path.GetDirectoryName(Log.FilePath), "dumps");
                Directory.CreateDirectory(dir);
                string file = Path.Combine(dir, DateTime.Now.ToString("yyyyMMdd-HHmmss") + "-" + kind + ".txt");
                File.WriteAllText(file, text);
                Log.Info("window layout saved to " + file);
                string[] all = Directory.GetFiles(dir);   // keep the newest 50; names sort by time
                Array.Sort(all);
                for (int i = 0; i < all.Length - 50; i++) File.Delete(all[i]);
            }
            catch (Exception e) { Log.Warn("could not save the window layout: " + e.Message); }
        }

        static string SavedPassword()
        {
            string user, password;
            return ReadCredential(Credentials.Vpn, out user, out password) ? password : "";
        }

        internal static bool PasswordHeld { get { return heldPassword != null; } }

        // "Never type a refused password twice" must also hold across a restart
        // (a crash, an update, a logoff), or a reboot loop could lock the account.
        // The fingerprint is not the secret itself; it is only compared.
        static string Fingerprint(string password)
        {
            using (SHA256 sha = SHA256.Create())
                return Convert.ToBase64String(sha.ComputeHash(Encoding.UTF8.GetBytes(password ?? "")));
        }

        static void LoadHeld()
        {
            if (heldLoaded) return;
            string saved = SavedPassword();
            if (saved.Length == 0) return;   // not readable yet: try again at the next login
            heldLoaded = true;
            string user, fingerprint;
            if (ReadCredential(Credentials.Held, out user, out fingerprint) && fingerprint == Fingerprint(saved))
            {
                heldPassword = saved;
                Log.Warn("the saved VPN password was refused before the last restart; holding it (queue a new one on /password)");
            }
        }

        static void ClearHeld()
        {
            heldPassword = null;
            // Best effort: the in-memory hold is already gone, and a stale
            // fingerprint is harmless once the saved password changes.
            try { WriteCredential(Credentials.Held, "", ""); }
            catch (Exception e) { Log.Warn("could not clear the saved password-refusal record: " + e.Message); }
        }

        // The new password queued on /password to change to, or "".
        internal static string QueuedPassword()
        {
            string user, password;
            return ReadCredential(Credentials.Change, out user, out password) && password != null ? password : "";
        }

        // The queued password becomes the saved one: the VPN took it in a change,
        // or the old one stopped working.
        static void Promote(string password, string why)
        {
            string user, old;
            if (!ReadCredential(Credentials.Vpn, out user, out old)) user = "";
            WriteCredential(Credentials.Vpn, user ?? "", password);
            WriteCredential(Credentials.Change, "", "");
            changeSent = null;
            ClearHeld();
            oldRefused = false;
            Log.Info(why);
            Status.Notice(why);
            Status.Asking("");
        }

        static void Hold(string why)
        {
            heldPassword = SavedPassword();
            if (heldPassword.Length > 0)
                try { WriteCredential(Credentials.Held, "", Fingerprint(heldPassword)); }
                catch (Exception e) { Log.Warn("could not remember the refused password across restarts: " + e.Message); }
            string msg = why + "; queue the new one on /password (or: vpn-keeper password)";
            Log.Error(msg + " (no more logins until then)");
            Status.Failed(msg);
        }

        static readonly object pageGate = new object();
        static int wrongCodes;
        static DateTime pageLockedUntil = DateTime.MinValue;
        static long lastPageStep = -1;

        // The /password page. Anyone in 'clients' can open it, so it needs a
        // current one-time code (each usable once), and 5 wrong codes lock it
        // for 15 minutes. It only saves the password here (see Store).
        public static string SavePassword(IPAddress from, string code, string password, string confirm, bool force)
        {
            lock (pageGate)
            {
                if (DateTime.Now < pageLockedUntil) return "Too many wrong codes. Try again after " + pageLockedUntil.ToString("HH:mm") + ".";
                // Form mistakes first, so a typo does not use up the code.
                if (password.Length == 0) return "The password is empty; nothing saved.";
                if (password.Length > 256) return "The password is longer than 256 characters; nothing saved.";
                if (password != confirm) return "The two passwords differ; nothing saved.";

                string user, seed;
                byte[] key;
                if (!ReadCredential(Credentials.Otp, out user, out seed)) return "No one-time-code seed is saved on this PC (run vpn-keeper setup).";
                try { key = Totp.Base32Decode(seed); }
                catch (FormatException) { return "The saved one-time-code seed is not valid (run vpn-keeper setup)."; }
                long now = Totp.Step(DateTime.UtcNow, OtpPeriod), hit = -1;
                for (long s = now - 1; s <= now + 1; s++)
                    if (s > lastPageStep && Totp.Code(key, s, OtpDigits) == code.Trim()) hit = s;
                if (hit < 0)
                {
                    Log.Warn("password page: wrong code from " + from);
                    if (++wrongCodes >= 5) { wrongCodes = 0; pageLockedUntil = DateTime.Now.AddMinutes(15); }
                    return "Wrong or already used code; nothing saved.";
                }
                wrongCodes = 0;
                lastPageStep = hit;

                return Store(password, force, "the web page (" + from + ")");
            }
        }

        // Queues a new password. The current one stays in use until the VPN asks
        // for a change (then it is changed to this one) or refuses the current one
        // (changed elsewhere: then this one is used). force: reconnect now, so the
        // VPN gets the chance to ask at once. The agent may be another process,
        // so force travels as the queue entry's user name.
        public static string Store(string password, bool force, string source)
        {
            if (string.IsNullOrEmpty(password)) return "The password is empty; nothing saved.";
            if (password.Length > 256) return "The password is longer than 256 characters; nothing saved.";
            WriteCredential(Credentials.Change, force ? "force" : "", password);
            Log.Info("new VPN password queued from " + source + (force ? "; reconnecting now" : ""));
            if (force) return "Queued. vpn-keeper reconnects now; if the VPN asks for a change, it changes the password to this one. /health shows how it went.";
            return "Queued. It waits: when the VPN next asks for a password change, vpn-keeper changes it to this one; if the current one stops working, it switches to this one." + (heldPassword != null ? " Trying it within seconds." : "");
        }

        // A refused password stops logins altogether (Hold). Other failures are
        // mostly the network or the server, but may still have typed the password,
        // so they wait 2 min, then 5, then 15: a burst cannot hammer the server,
        // and the agent is back within 15 minutes of an outage ending.
        static void Fail(string why, bool setupProblem)
        {
            failedLogins++;
            int minutes = setupProblem ? 5 : failedLogins == 1 ? 2 : failedLogins == 2 ? 5 : 15;
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
                // This only asks "does something answer through the tunnel?", so
                // an internal site's self-signed certificate must not look dead.
                req.ServerCertificateValidationCallback = delegate { return true; };
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
            catch (NotSupportedException) { return false; }
        }
    }

    // What /health shows.
    class Status
    {
        readonly object gate = new object();
        VpnState state = VpnState.NotRunning;
        DateTime since = DateTime.Now, lastLogin = DateTime.MinValue, lastCheck = DateTime.MinValue;
        string lastError = "", lastNotice = "", asking = "";
        DateTime askingSince = DateTime.MinValue;

        public void Set(VpnState s) { lock (gate) { if (s != state) { state = s; since = DateTime.Now; Log.Info("state: " + s); } } }
        public void LoggedIn() { lock (gate) { lastLogin = DateTime.Now; lastError = ""; } }
        public void CheckOk() { lock (gate) { lastCheck = DateTime.Now; } }
        public void Failed(string why) { lock (gate) { lastError = Time(DateTime.Now) + " " + why; } }
        public void Notice(string text) { lock (gate) { lastNotice = Time(DateTime.Now) + " " + text; } }   // e.g. "password expires in 5 days"

        // The VPN is asking for a new password (shown on /password); "" once done.
        public void Asking(string what)
        {
            lock (gate)
            {
                if (what.Length > 0 && asking.Length == 0) askingSince = DateTime.Now;
                asking = what;
            }
        }
        public string Asking() { lock (gate) { return asking.Length == 0 ? "" : asking + " (first seen " + Time(askingSince) + ")"; } }

        public string Report()
        {
            lock (gate)
            {
                return "vpn: " + state + " since " + Time(since) + "\n"
                    + "last login: " + Time(lastLogin) + "\n"
                    + "last good check: " + Time(lastCheck) + "\n"
                    + "last error: " + (lastError.Length == 0 ? "-" : lastError) + "\n"
                    + "last notice: " + (lastNotice.Length == 0 ? "-" : lastNotice) + "\n"
                    + "VPN asking for a new password: " + (asking.Length == 0 ? "no" : asking + " (first seen " + Time(askingSince) + ")") + "\n"
                    + "new password queued: " + (Watchdog.QueuedPassword().Length > 0 ? "yes" : "no") + "\n"
                    + "password held after a refusal: " + (Watchdog.PasswordHeld ? "yes" : "no") + "\n"
                    + "version: " + BuildInfo.Version + "\n";
            }
        }

        static string Time(DateTime t) { return t == DateTime.MinValue ? "-" : t.ToString("yyyy-MM-dd HH:mm:ss"); }
    }
}
