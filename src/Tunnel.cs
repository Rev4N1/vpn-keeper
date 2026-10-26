using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

namespace VpnKeeper
{
    // Reads and drives Connect Tunnel's (SnwlConnect.exe) windows with plain
    // window messages: no mouse, no keyboard focus, so it works with the
    // screen locked. WinForms control ids change on every start, so controls
    // are found by class and caption (docs/design.md has the window map).
    enum VpnState { NotRunning, NoWindow, Down, Busy, Up }

    class Win
    {
        public IntPtr Handle;
        public string Kind;      // button, edit, static, combobox, window
        public string Class;
        public string Text;
        public bool Enabled;
        public bool Visible;     // on screen (a window hidden in the tray is not)
        public List<Win> Kids = new List<Win>();

        // The text as drawn: "&Connect" shows as Connect (& marks the Alt key).
        public string Caption { get { return Tunnel.StripMnemonic(Text).Trim(); } }

        public IEnumerable<Win> Of(string kind)
        {
            foreach (Win k in Kids) if (k.Kind == kind) yield return k;
        }

        public Win Button(params string[] captions)
        {
            foreach (Win b in Of("button")) if (Tunnel.Is(b, captions)) return b;
            return null;
        }

        public string ButtonCaptions()
        {
            List<string> seen = new List<string>();
            foreach (Win b in Of("button")) seen.Add("\"" + b.Caption + "\"");
            return string.Join(", ", seen.ToArray());
        }

        // The window title and its labels, e.g. for an error message box.
        public string Summary()
        {
            List<string> parts = new List<string>();
            foreach (Win k in Of("static")) if (k.Caption.Length > 0) parts.Add(k.Caption);
            return Caption + ": " + string.Join(" | ", parts.ToArray());
        }
    }

    class Snapshot
    {
        public bool Running;
        public List<Win> Windows = new List<Win>();
        public Win Main, StatusLabel, PasswordDialog, OtpDialog, ChangeDialog;
        public List<Win> MessageBoxes = new List<Win>();
        public List<Win> Blockers = new List<Win>();   // visible, not one of the windows above

        public VpnState State
        {
            get
            {
                if (!Running) return VpnState.NotRunning;
                if (StatusLabel == null) return VpnState.NoWindow;
                return Tunnel.Classify(StatusLabel.Text);
            }
        }

        // Its caption follows the state: Connect, Cancel, Disconnect.
        public Win MainButton
        {
            get { return Main == null ? null : Main.Button("Connect", "Disconnect", "Cancel", "Conectar", "Desconectar", "Cancelar"); }
        }

        public Win Profile
        {
            get
            {
                if (Main != null) foreach (Win c in Main.Of("combobox")) return c;
                return null;
            }
        }

        // Every visible window but the main one, for the log.
        public string OnScreen()
        {
            List<string> seen = new List<string>();
            foreach (Win w in Windows) if (w.Visible && w != Main) seen.Add("[" + w.Class + "] " + w.Summary() + " buttons " + w.ButtonCaptions());
            return seen.Count == 0 ? "no other window" : string.Join("; ", seen.ToArray());
        }

        public string ButtonList()
        {
            List<string> seen = new List<string>();
            if (Main != null) foreach (Win b in Main.Of("button")) seen.Add("\"" + b.Caption + "\"" + (b.Enabled ? "" : " (disabled)"));
            return seen.Count == 0 ? "none" : string.Join(", ", seen.ToArray());
        }
    }

    static class Tunnel
    {
        public static string Exe = @"C:\Program Files\SonicWall\Modern Connect Tunnel\SnwlConnect.exe";   // tests use the fake
        const string ProcessName = "SnwlConnect";
        static string foundExe;
        static DateTime nextLookup = DateTime.MinValue, lastStartError = DateTime.MinValue;

        // Status captions, English and Spanish. Order matters: "disconnected"
        // contains "connected", "desconectado" contains "conectado".
        public static VpnState Classify(string status)
        {
            string s = StripMnemonic(status ?? "").Trim().ToLowerInvariant();
            if (s.StartsWith("disconnected") || s.StartsWith("desconectado")) return VpnState.Down;
            if (s.Contains("connecting") || s.Contains("conectando") || s.Contains("disconnecting")
                || s.Contains("desconectando") || s.Contains("reconnect") || s.Contains("reconect")) return VpnState.Busy;
            if (s.StartsWith("connected") || s.StartsWith("conectado")) return VpnState.Up;
            return VpnState.NoWindow;
        }

        // A one-time-code prompt (its title usually says "One Time Password").
        public static bool AsksOtp(Win w)
        {
            string s = w.Summary().ToLowerInvariant();
            foreach (string k in new[] { "one time", "onetime", "otp", "6 digit code", "six digit code", "verification code", "authenticator", "backup code", "code", "token", "código", "codigo" })
                if (s.Contains(k)) return true;
            return false;
        }

        // A prompt for a new password (the old one expired), English or Spanish.
        public static bool AsksNewPassword(Win w)
        {
            string s = w.Summary().ToLowerInvariant();
            foreach (string k in new[] { "new password", "change password", "change your password", "nueva contrase", "cambiar contrase", "cambiar la contrase", "cambio de contrase" })
                if (s.Contains(k)) return true;
            return false;
        }

        // A window's layout for studying later: title, class, and each control's
        // kind, class, caption and state. Box contents are never included.
        public static string Dump(Win w)
        {
            StringBuilder sb = new StringBuilder();
            sb.AppendLine("window \"" + w.Text + "\" class " + w.Class + (w.Visible ? "" : " (hidden)"));
            foreach (Win k in w.Kids)
                sb.AppendLine("  " + k.Kind + " [" + k.Class + "] " + (k.Kind == "edit" ? "(contents not saved)" : "\"" + k.Text + "\"") + (k.Enabled ? "" : " (disabled)"));
            return sb.ToString();
        }

        // The login prompt's "change password" check box, if it has one.
        public static Win ChangeBox(Win d)
        {
            foreach (Win b in d.Of("button"))
            {
                string c = b.Caption.ToLowerInvariant();
                if ((c.Contains("change") || c.Contains("cambiar")) && (c.Contains("password") || c.Contains("contrase"))) return b;
            }
            return null;
        }

        // Ticks or clears a check box. Owner-drawn WinForms boxes don't report
        // their state; a fresh prompt's box starts clear, so a click ticks it.
        public static void SetChecked(Win box, bool on)
        {
            bool? now = null;
            if ((GetWindowLong(box.Handle, GwlStyle) & 0xF) != BsOwnerDraw)
            {
                IntPtr r;
                if (SendMessageTimeout(box.Handle, BmGetCheck, IntPtr.Zero, IntPtr.Zero, SmtoAbortIfHung, 2000, out r) != IntPtr.Zero) now = r == (IntPtr)1;
            }
            if (now == null ? on : now != on) Click(box);
        }

        // Answers to "change your password now?", English and Spanish.
        public static readonly string[] YesCaptions = { "Yes", "Sí", "Si", "Change", "Change Password", "Change now", "Cambiar", "Cambiar contraseña", "Cambiar ahora", "OK", "Aceptar" };
        public static readonly string[] NoCaptions = { "No", "Not now", "Later", "Remind me later", "Skip", "Continue", "Cancel", "Ahora no", "Más tarde", "Recordar más tarde", "Omitir", "Continuar", "Cancelar" };
        public static readonly string[] SubmitCaptions = { "OK", "Aceptar", "Change", "Cambiar", "Save", "Guardar", "Submit", "Enviar" };

        // A question offering to change the password (it is about to expire).
        public static bool OffersPasswordChange(string text)
        {
            string s = text.ToLowerInvariant();
            if (!s.Contains("password") && !s.Contains("contrase")) return false;
            foreach (string k in new[] { "change", "cambi", "expire", "caduc", "venc" })
                if (s.Contains(k)) return true;
            return false;
        }

        // The boxes of a change prompt, by their labels (old/current, new,
        // confirm/again), else by order: the last is confirm, the one before
        // new, the one before that old. A user box, if any, is skipped.
        public static void ChangeFields(Win d, out Win oldBox, out Win newBox, out Win confirmBox)
        {
            oldBox = newBox = confirmBox = null;
            List<Win> unlabelled = new List<Win>();
            string label = "";
            foreach (Win k in d.Kids)
            {
                if (k.Kind == "static") { label = k.Text.ToLowerInvariant(); continue; }
                if (k.Kind != "edit") continue;
                if (label.Contains("user") || label.Contains("usuario")) { }
                else if (confirmBox == null && (label.Contains("confirm") || label.Contains("again") || label.Contains("repe") || label.Contains("verif"))) confirmBox = k;
                else if (newBox == null && (label.Contains("new") || label.Contains("nueva") || label.Contains("nuevo"))) newBox = k;
                else if (oldBox == null && (label.Contains("old") || label.Contains("current") || label.Contains("actual") || label.Contains("anterior") || label.Contains("antigu"))) oldBox = k;
                else unlabelled.Add(k);
                label = "";
            }
            if (confirmBox == null && unlabelled.Count > 0) { confirmBox = unlabelled[unlabelled.Count - 1]; unlabelled.RemoveAt(unlabelled.Count - 1); }
            if (newBox == null && unlabelled.Count > 0) { newBox = unlabelled[unlabelled.Count - 1]; unlabelled.RemoveAt(unlabelled.Count - 1); }
            if (oldBox == null && unlabelled.Count > 0) oldBox = unlabelled[unlabelled.Count - 1];
            if (newBox == null) { newBox = confirmBox; confirmBox = null; }   // a single box
        }

        // A notice saying the password is wrong or has expired. "Will expire in
        // 5 days" is only a warning and does not match.
        public static bool PasswordRefused(string notice)
        {
            string s = notice.ToLowerInvariant();
            if (!s.Contains("password") && !s.Contains("contrase")) return false;
            foreach (string k in new[] { "incorrect", "invalid", "wrong", "expired", "rejected", "denied", "caducad", "expirad", "inválid", "no válid", "rechazad", "denegad" })
                if (s.Contains(k)) return true;
            return false;
        }

        public static string StripMnemonic(string text)
        {
            return text.Replace("&&", "\u0001").Replace("&", "").Replace("\u0001", "&");
        }

        public static bool Is(Win w, params string[] captions)
        {
            foreach (string c in captions) if (string.Equals(w.Caption, c, StringComparison.OrdinalIgnoreCase)) return true;
            return false;
        }

        public static Snapshot Take()
        {
            Snapshot snap = new Snapshot();
            HashSet<uint> pids = new HashSet<uint>();
            int session = Process.GetCurrentProcess().SessionId;
            foreach (Process p in Process.GetProcessesByName(ProcessName))
            {
                try
                {
                    if (p.SessionId == session) pids.Add((uint)p.Id);   // only this desktop's windows can be driven
                }
                catch (InvalidOperationException) { }   // it exited while we looked
                finally { p.Dispose(); }
            }
            snap.Running = pids.Count > 0;
            if (!snap.Running) return snap;

            EnumWindows(delegate(IntPtr h, IntPtr l)
            {
                uint pid;
                GetWindowThreadProcessId(h, out pid);
                // Hidden WinForms windows count too: once connected, Connect Tunnel
                // hides its main window in the tray, and its status is still readable.
                if (pids.Contains(pid) && (IsWindowVisible(h) || ClassOf(h).StartsWith("WindowsForms")))
                    snap.Windows.Add(Describe(h, true));
                return true;
            }, IntPtr.Zero);

            snap.Windows.Sort(delegate(Win a, Win b) { return b.Visible.CompareTo(a.Visible); });   // visible first
            foreach (Win w in snap.Windows)
            {
                Win status = null;
                foreach (Win s in w.Of("static")) if (Classify(s.Text) != VpnState.NoWindow) { status = s; break; }
                int edits = 0;
                foreach (Win e in w.Of("edit")) edits++;
                bool combo = false;
                foreach (Win cb in w.Of("combobox")) { combo = true; break; }
                bool ok = w.Button("OK", "Aceptar") != null;

                // The main window is the one with the configuration combo and a
                // status label. Without the combo, a message box whose text starts
                // with "Disconnected" would look like the main window and never be
                // dismissed.
                if (status != null && snap.Main == null && combo) { snap.Main = w; snap.StatusLabel = status; }
                else if (!w.Visible) continue;   // prompts only count while on screen
                // A notice or question: no boxes, and OK, or Yes and No (a Windows message
                // box, or Connect Tunnel's own, e.g. "session has been idle ... disconnected").
                else if (edits == 0 && (w.Class == "#32770" || w.Button("OK", "Aceptar", "Close", "Cerrar") != null
                    || (w.Button(YesCaptions) != null && w.Button(NoCaptions) != null))) snap.MessageBoxes.Add(w);
                else if (w.Button(SubmitCaptions) != null && (edits >= 3 || (edits != 2 && AsksNewPassword(w)))) snap.ChangeDialog = w;   // old, new, confirm; 2 boxes is the login prompt
                else if (ok && edits == 1)
                {
                    // One box can be the code prompt or a password-only login
                    // prompt. The title/labels decide; guessing either way is bad.
                    if (AsksOtp(w)) snap.OtpDialog = w;
                    else if (AsksNewPassword(w) || w.Summary().ToLowerInvariant().Contains("password") || w.Summary().ToLowerInvariant().Contains("contrase")) snap.PasswordDialog = w;
                    else snap.Blockers.Add(w);
                }
                else if (ok && edits >= 2) snap.PasswordDialog = w;
                else snap.Blockers.Add(w);
            }
            return snap;
        }

        static Win Describe(IntPtr h, bool withKids)
        {
            Win w = new Win();
            w.Handle = h;
            w.Class = ClassOf(h);
            w.Text = TextOf(h);
            w.Enabled = IsWindowEnabled(h);
            w.Visible = IsWindowVisible(h);
            string c = w.Class.ToLowerInvariant();
            w.Kind = c.Contains("button") ? "button" : c.Contains("edit") ? "edit" : c.Contains("static") ? "static"
                : c.Contains("combobox") ? "combobox" : "window";
            if (withKids)
            {
                // Every descendant, in creation order. A control's own visible
                // flag is used: inside a hidden window all of them read as hidden.
                EnumChildWindows(h, delegate(IntPtr k, IntPtr l)
                {
                    if ((GetWindowLong(k, GwlStyle) & WsVisible) != 0) w.Kids.Add(Describe(k, false));
                    return true;
                }, IntPtr.Zero);
            }
            return w;
        }

        // The user box comes first; the password box is the one after a
        // "Password"/"Contraseña" label, else the last box.
        public static void PasswordFields(Win d, out Win userBox, out Win passBox)
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

        // Where Connect Tunnel actually lives. The default path covers the
        // usual install; a 32-bit install or a new version may be elsewhere, so
        // look under both Program Files trees. The walk is bounded and skips
        // folders it may not read (WindowsApps is one), and the result is cached.
        public static string FindExe()
        {
            if (File.Exists(Exe)) return Exe;
            if (foundExe != null && File.Exists(foundExe)) return foundExe;
            if (DateTime.Now < nextLookup) return Exe;
            nextLookup = DateTime.Now.AddMinutes(10);
            foreach (Environment.SpecialFolder root in new[] { Environment.SpecialFolder.ProgramFiles, Environment.SpecialFolder.ProgramFilesX86 })
            {
                string dir = Environment.GetFolderPath(root);
                if (dir.Length == 0 || !Directory.Exists(dir)) continue;
                string hit = FindUnder(dir);
                if (hit != null)
                {
                    foundExe = hit;
                    Log.Info("found Connect Tunnel at " + hit);
                    return hit;
                }
            }
            return Exe;
        }

        // A breadth-first search, a few levels deep. Connect Tunnel sits in its
        // maker's folder (SonicWall\...\SnwlConnect.exe); the whole of Program
        // Files is not crawled, and a folder that cannot be read is skipped
        // without abandoning the rest.
        static string FindUnder(string root)
        {
            Queue<string> dirs = new Queue<string>();
            dirs.Enqueue(root);
            int seen = 0;
            while (dirs.Count > 0 && seen++ < 2000)
            {
                string d = dirs.Dequeue();
                try
                {
                    foreach (string f in Directory.GetFiles(d, ProcessName + ".exe")) return f;
                    foreach (string sub in Directory.GetDirectories(d))
                    {
                        string name = Path.GetFileName(sub).ToLowerInvariant();
                        int depth = sub.Substring(root.Length).Split(new[] { Path.DirectorySeparatorChar }, StringSplitOptions.RemoveEmptyEntries).Length;
                        // The top two levels are cheap to check; deeper ones only
                        // if their name looks like the VPN client's.
                        if (depth < 4 && (depth <= 2 || name.Contains("sonic") || name.Contains("connect") || name.Contains("vpn")))
                            dirs.Enqueue(sub);
                    }
                }
                catch (Exception) { }   // a protected folder; keep looking
            }
            return null;
        }

        public static void Start()
        {
            string exe = FindExe();
            if (!File.Exists(exe))
            {
                // Not installed (or moved). Say it once every ten minutes, not
                // every fifteen seconds, so the log stays readable.
                if (DateTime.Now >= lastStartError.AddMinutes(10))
                {
                    Log.Error("Connect Tunnel is not installed (looked for " + Exe + " and under Program Files)");
                    lastStartError = DateTime.Now;
                }
                return;
            }
            Log.Info("starting Connect Tunnel from " + exe);
            try { Process.Start(new ProcessStartInfo(exe) { UseShellExecute = true }); }
            catch (Exception e)
            {
                if (DateTime.Now >= lastStartError.AddMinutes(10))
                {
                    Log.Error("could not start " + exe + ": " + e.Message);
                    lastStartError = DateTime.Now;
                }
            }
        }

        // Password boxes accept WM_SETTEXT from another process; they only refuse to be read.
        public static void SetText(Win edit, string text)
        {
            IntPtr r;
            SendMessageTimeout(edit.Handle, WmSetText, IntPtr.Zero, text, SmtoAbortIfHung, 3000, out r);
        }

        // Posted, not sent: OK on the login prompt opens the next modal dialog,
        // and SendMessage would wait until that one closed.
        // A button in a window hidden in the tray ignores BM_CLICK; its parent
        // still takes the click notification (WinForms turns it into Click).
        public static void Click(Win button)
        {
            if (IsWindowVisible(button.Handle)) { PostMessage(button.Handle, BmClick, IntPtr.Zero, IntPtr.Zero); return; }
            IntPtr wParam = (IntPtr)((BnClicked << 16) | (GetDlgCtrlID(button.Handle) & 0xFFFF));
            PostMessage(GetParent(button.Handle), WmCommand, wParam, button.Handle);
        }

        // For a dialog that ignored OK: a mouse press on OK, then Enter in its last box.
        public static void Nudge(Win dialog)
        {
            Log.Warn("dialog still open; pressing OK another way");
            Win ok = dialog.Button("OK", "Aceptar");
            if (ok != null)
            {
                IntPtr pos = (IntPtr)((4 << 16) | 4);
                PostMessage(ok.Handle, WmLButtonDown, (IntPtr)1, pos);
                PostMessage(ok.Handle, WmLButtonUp, IntPtr.Zero, pos);
            }
            Win last = null;
            foreach (Win e in dialog.Of("edit")) last = e;
            if (last != null)
            {
                PostMessage(last.Handle, WmKeyDown, (IntPtr)VkReturn, (IntPtr)0x001C0001);
                PostMessage(last.Handle, WmKeyUp, (IntPtr)VkReturn, unchecked((IntPtr)(int)0xC01C0001));
            }
        }

        static string ClassOf(IntPtr h)
        {
            StringBuilder sb = new StringBuilder(256);
            GetClassName(h, sb, sb.Capacity);
            return sb.ToString();
        }

        static string TextOf(IntPtr h)
        {
            IntPtr len;
            if (SendMessageTimeout(h, WmGetTextLength, IntPtr.Zero, IntPtr.Zero, SmtoAbortIfHung, 2000, out len) == IntPtr.Zero)
                return "";
            int n = Math.Min((int)len, 4096) + 1;
            StringBuilder sb = new StringBuilder(n);
            IntPtr r;
            SendMessageTimeout(h, WmGetText, (IntPtr)n, sb, SmtoAbortIfHung, 2000, out r);
            return sb.ToString();
        }

        const uint WmSetText = 0x000C, WmGetText = 0x000D, WmGetTextLength = 0x000E;
        const uint WmKeyDown = 0x0100, WmKeyUp = 0x0101, WmLButtonDown = 0x0201, WmLButtonUp = 0x0202;
        const uint BmClick = 0x00F5, BmGetCheck = 0x00F0, SmtoAbortIfHung = 0x0002, WmCommand = 0x0111;
        const int BnClicked = 0, BsOwnerDraw = 0xB;
        const int VkReturn = 0x0D, GwlStyle = -16, WsVisible = 0x10000000;

        delegate bool EnumProc(IntPtr h, IntPtr l);

        [DllImport("user32.dll")] static extern bool EnumWindows(EnumProc cb, IntPtr l);
        [DllImport("user32.dll")] static extern bool EnumChildWindows(IntPtr parent, EnumProc cb, IntPtr l);
        [DllImport("user32.dll")] static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
        [DllImport("user32.dll")] static extern bool IsWindowVisible(IntPtr h);
        [DllImport("user32.dll")] static extern bool IsWindowEnabled(IntPtr h);
        [DllImport("user32.dll")] static extern IntPtr GetParent(IntPtr h);
        [DllImport("user32.dll")] static extern int GetDlgCtrlID(IntPtr h);
        [DllImport("user32.dll")] static extern int GetWindowLong(IntPtr h, int index);
        [DllImport("user32.dll", CharSet = CharSet.Unicode)] static extern int GetClassName(IntPtr h, StringBuilder sb, int max);
        [DllImport("user32.dll")] static extern bool PostMessage(IntPtr h, uint msg, IntPtr w, IntPtr l);
        [DllImport("user32.dll", CharSet = CharSet.Unicode)]
        static extern IntPtr SendMessageTimeout(IntPtr h, uint msg, IntPtr w, IntPtr l, uint flags, uint timeout, out IntPtr result);
        [DllImport("user32.dll", CharSet = CharSet.Unicode)]
        static extern IntPtr SendMessageTimeout(IntPtr h, uint msg, IntPtr w, StringBuilder l, uint flags, uint timeout, out IntPtr result);
        [DllImport("user32.dll", CharSet = CharSet.Unicode)]
        static extern IntPtr SendMessageTimeout(IntPtr h, uint msg, IntPtr w, string l, uint flags, uint timeout, out IntPtr result);
    }
}
