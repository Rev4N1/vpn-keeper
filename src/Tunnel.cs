using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;

namespace VpnKeeper
{
    // Reads and drives the Connect Tunnel (SnwlConnect.exe) windows with plain
    // window messages: no mouse, no keyboard focus, so it also works while the
    // screen is locked. WinForms control ids change on every start, so controls
    // are found by their class and caption (see docs/how-it-works.md).
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

        // The text as shown: "&Connect" is drawn as Connect (the & underlines
        // the Alt shortcut), and screen readers report it that way too.
        public string Caption { get { return Tunnel.StripMnemonic(Text).Trim(); } }

        public IEnumerable<Win> Of(string kind)
        {
            foreach (Win k in Kids) if (k.Kind == kind) yield return k;
        }

        public Win Button(params string[] captions)
        {
            foreach (Win b in Of("button"))
                foreach (string c in captions)
                    if (string.Equals(b.Caption, c, StringComparison.OrdinalIgnoreCase)) return b;
            return null;
        }

        public bool HasText(string fragment)
        {
            foreach (Win k in Kids)
                if (k.Caption.IndexOf(fragment, StringComparison.OrdinalIgnoreCase) >= 0) return true;
            return false;
        }

        public override string ToString() { return Kind + " \"" + Caption + "\""; }
    }

    class Snapshot
    {
        public bool Running;
        public List<Win> Windows = new List<Win>();
        public Win Main;
        public Win StatusLabel;
        public Win PasswordDialog;
        public Win OtpDialog;
        public List<Win> MessageBoxes = new List<Win>();

        public VpnState State
        {
            get
            {
                if (!Running) return VpnState.NotRunning;
                if (Main == null || StatusLabel == null) return VpnState.NoWindow;
                return Tunnel.Classify(StatusLabel.Text);
            }
        }

        public Win MainButton
        {
            get
            {
                if (Main == null) return null;
                return Main.Button("Connect", "Disconnect", "Cancel", "Conectar", "Desconectar", "Cancelar");
            }
        }

        public Win Profile
        {
            get
            {
                if (Main == null) return null;
                foreach (Win c in Main.Of("combobox")) return c;
                return null;
            }
        }
    }

    static class Tunnel
    {
        const string ProcessName = "SnwlConnect";

        // Status label captions, English and Spanish. Order matters:
        // "disconnected" contains "connected", "desconectado" contains "conectado".
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
            return text.Replace("&&", "").Replace("&", "").Replace("", "&");
        }

        static bool IsStatusWord(string text)
        {
            return Classify(text) != VpnState.NoWindow;
        }

        public static Snapshot Take()
        {
            Snapshot snap = new Snapshot();
            HashSet<uint> pids = new HashSet<uint>();
            foreach (Process p in Process.GetProcessesByName(ProcessName))
            {
                // Only our own desktop session: the agent cannot drive another user's windows.
                if (p.SessionId == Process.GetCurrentProcess().SessionId) pids.Add((uint)p.Id);
                p.Dispose();
            }
            snap.Running = pids.Count > 0;
            if (!snap.Running) return snap;

            EnumWindows(delegate(IntPtr h, IntPtr l)
            {
                uint pid;
                GetWindowThreadProcessId(h, out pid);
                // Hidden windows count too: Connect Tunnel hides its main window in
                // the tray once connected, and its status can still be read there.
                if (pids.Contains(pid) && (IsWindowVisible(h) || ClassOf(h).StartsWith("WindowsForms")))
                    snap.Windows.Add(Describe(h, true));
                return true;
            }, IntPtr.Zero);

            // A visible main window wins over a hidden one.
            snap.Windows.Sort(delegate(Win a, Win b) { return b.Visible.CompareTo(a.Visible); });
            foreach (Win w in snap.Windows)
            {
                int edits = 0;
                foreach (Win e in w.Of("edit")) edits++;
                Win ok = w.Button("OK", "Aceptar");
                Win status = null;
                foreach (Win s in w.Of("static")) if (IsStatusWord(s.Text)) { status = s; break; }

                if (status != null && snap.Main == null) { snap.Main = w; snap.StatusLabel = status; }
                else if (!w.Visible) continue;   // prompts only count while on screen
                else if (w.Class == "#32770") snap.MessageBoxes.Add(w);
                else if (ok != null && edits == 1) snap.OtpDialog = w;
                else if (ok != null && edits >= 2) snap.PasswordDialog = w;
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
                // EnumChildWindows walks every descendant, in creation (z) order.
                EnumChildWindows(h, delegate(IntPtr k, IntPtr l)
                {
                    // The control's own visibility, not its window's: inside a
                    // hidden main window every control reads as invisible.
                    if ((GetWindowLong(k, GwlStyle) & WsVisible) != 0) w.Kids.Add(Describe(k, false));
                    return true;
                }, IntPtr.Zero);
            }
            return w;
        }

        public static void Start(string exe)
        {
            Log.Info("starting " + exe);
            Process.Start(new ProcessStartInfo(exe) { UseShellExecute = true });
        }

        // Fill a text box. Password boxes accept WM_SETTEXT from another process;
        // they only refuse to be read.
        public static bool SetText(Win edit, string text)
        {
            IntPtr r;
            return SendMessageTimeout(edit.Handle, WmSetText, IntPtr.Zero, text, SmtoAbortIfHung, 3000, out r) != IntPtr.Zero;
        }

        // Posted, not sent: OK on the password dialog opens the next modal
        // dialog, and a SendMessage would block until that one closed.
        public static void Click(Win button)
        {
            PostMessage(button.Handle, BmClick, IntPtr.Zero, IntPtr.Zero);
        }

        // Fallback when BM_CLICK is ignored: a mouse press and release inside the button.
        public static void ClickMouse(Win button)
        {
            IntPtr pos = (IntPtr)((4 << 16) | 4);
            PostMessage(button.Handle, WmLButtonDown, (IntPtr)1, pos);
            PostMessage(button.Handle, WmLButtonUp, IntPtr.Zero, pos);
        }

        // Second fallback: Enter in a text box fires the dialog's default (OK) button.
        public static void PressEnter(Win edit)
        {
            PostMessage(edit.Handle, WmKeyDown, (IntPtr)VkReturn, (IntPtr)0x001C0001);
            PostMessage(edit.Handle, WmKeyUp, (IntPtr)VkReturn, unchecked((IntPtr)(int)0xC01C0001));
        }

        public static bool StillThere(Win w)
        {
            return IsWindow(w.Handle) && IsWindowVisible(w.Handle);
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
        const uint BmClick = 0x00F5;
        const int VkReturn = 0x0D;
        const uint SmtoAbortIfHung = 0x0002;
        const int GwlStyle = -16;
        const int WsVisible = 0x10000000;

        delegate bool EnumProc(IntPtr h, IntPtr l);

        [DllImport("user32.dll")] static extern bool EnumWindows(EnumProc cb, IntPtr l);
        [DllImport("user32.dll")] static extern bool EnumChildWindows(IntPtr parent, EnumProc cb, IntPtr l);
        [DllImport("user32.dll")] static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
        [DllImport("user32.dll")] static extern bool IsWindowVisible(IntPtr h);
        [DllImport("user32.dll")] static extern bool IsWindowEnabled(IntPtr h);
        [DllImport("user32.dll")] static extern int GetWindowLong(IntPtr h, int index);
        [DllImport("user32.dll")] static extern bool IsWindow(IntPtr h);
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
