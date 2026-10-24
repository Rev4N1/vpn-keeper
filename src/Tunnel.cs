using System;
using System.Collections.Generic;
using System.Diagnostics;
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
        public Win Main, StatusLabel, PasswordDialog, OtpDialog;
        public List<Win> MessageBoxes = new List<Win>();

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
                if (p.SessionId == session) pids.Add((uint)p.Id);   // only this desktop's windows can be driven
                p.Dispose();
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
                bool ok = w.Button("OK", "Aceptar") != null;

                if (status != null && snap.Main == null) { snap.Main = w; snap.StatusLabel = status; }
                else if (!w.Visible) continue;   // prompts only count while on screen
                else if (w.Class == "#32770") snap.MessageBoxes.Add(w);
                else if (ok && edits == 1) snap.OtpDialog = w;
                else if (ok && edits >= 2) snap.PasswordDialog = w;
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

        public static void Start()
        {
            Log.Info("starting Connect Tunnel");
            try { Process.Start(new ProcessStartInfo(Exe) { UseShellExecute = true }); }
            catch (Exception e) { Log.Error("could not start " + Exe + ": " + e.Message); }
        }

        // Password boxes accept WM_SETTEXT from another process; they only refuse to be read.
        public static void SetText(Win edit, string text)
        {
            IntPtr r;
            SendMessageTimeout(edit.Handle, WmSetText, IntPtr.Zero, text, SmtoAbortIfHung, 3000, out r);
        }

        // Posted, not sent: OK on the login prompt opens the next modal dialog,
        // and SendMessage would wait until that one closed.
        public static void Click(Win button)
        {
            PostMessage(button.Handle, BmClick, IntPtr.Zero, IntPtr.Zero);
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
        const uint BmClick = 0x00F5, SmtoAbortIfHung = 0x0002;
        const int VkReturn = 0x0D, GwlStyle = -16, WsVisible = 0x10000000;

        delegate bool EnumProc(IntPtr h, IntPtr l);

        [DllImport("user32.dll")] static extern bool EnumWindows(EnumProc cb, IntPtr l);
        [DllImport("user32.dll")] static extern bool EnumChildWindows(IntPtr parent, EnumProc cb, IntPtr l);
        [DllImport("user32.dll")] static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
        [DllImport("user32.dll")] static extern bool IsWindowVisible(IntPtr h);
        [DllImport("user32.dll")] static extern bool IsWindowEnabled(IntPtr h);
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
