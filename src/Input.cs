using System;
using System.Runtime.InteropServices;

namespace VpnKeeper
{
    // keep_active: if Connect Tunnel drops "idle" sessions by watching this
    // PC's keyboard and mouse, a key press every so often keeps it going.
    // After that many minutes without input, while the VPN is up, it presses
    // F15: a real key to Windows that no keyboard has and no app acts on.
    //
    // It also resets Windows' own idle timer, so the screen does not lock or
    // turn off by itself while the VPN is up. A locked session takes no input,
    // so it does nothing then; the log says so.
    static class Input
    {
        [StructLayout(LayoutKind.Sequential)]
        struct LastInputInfo { public uint Size; public uint Time; }

        [DllImport("user32.dll")]
        static extern bool GetLastInputInfo(ref LastInputInfo info);

        [DllImport("user32.dll")]
        static extern void keybd_event(byte key, byte scan, uint flags, UIntPtr extra);

        const byte F15 = 0x7E;
        const uint KeyUp = 0x0002;

        static bool? lastWorked;   // log only when it starts or stops working

        // How long since the last keyboard or mouse input in this session.
        public static TimeSpan Idle()
        {
            LastInputInfo i = new LastInputInfo { Size = (uint)Marshal.SizeOf(typeof(LastInputInfo)) };
            if (!GetLastInputInfo(ref i)) return TimeSpan.Zero;
            return TimeSpan.FromMilliseconds(unchecked((uint)Environment.TickCount - i.Time));   // both wrap at 49 days
        }

        // One agent pass: press F15 if there has been no input for 'minutes'.
        public static void KeepActive(int minutes, bool vpnUp)
        {
            if (minutes <= 0 || !vpnUp) return;
            TimeSpan idle = Idle();
            if (idle.TotalMinutes < minutes) return;
            keybd_event(F15, 0, 0, UIntPtr.Zero);
            keybd_event(F15, 0, KeyUp, UIntPtr.Zero);
            System.Threading.Thread.Sleep(500);   // the input queue takes a moment
            bool worked = Idle().TotalSeconds < 5;
            if (worked != lastWorked)
                Log.Info(worked ? "keep_active: no input for " + (int)idle.TotalMinutes + " min; pressing F15 every " + minutes + " min while the VPN is up"
                    : "keep_active: F15 did not count as input (screen locked?); the VPN may drop when idle");
            lastWorked = worked;
        }
    }
}
