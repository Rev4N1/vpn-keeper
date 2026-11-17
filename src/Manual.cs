using System;
using System.Globalization;
using System.IO;
using System.Threading;

namespace VpnKeeper
{
    // A one-off connection outside 'hours' (say, a weekend), started with
    // "vpn-keeper connect" or on /connect. While on, the watchdog acts as in
    // the hours: the VPN is kept up and logged in again whenever it drops. It
    // ends after 'manual_idle' minutes (30 by default) without traffic through
    // the proxy, or with "vpn-keeper disconnect"; outside the hours the VPN is
    // then disconnected.
    //
    // Started inside the hours, it keeps the VPN up past the window's end for
    // as long as the proxy is used.
    //
    // The session is a file holding the time of the last activity, so the
    // command line (another process) can start or end it, and an agent restart
    // does not lose it.
    static class Manual
    {
        public static TimeSpan Idle = TimeSpan.FromMinutes(30);   // from manual_idle

        public static string FilePath = Path.Combine(Path.GetDirectoryName(Log.FilePath), "manual");

        static long lastTraffic;   // UTC ticks of the last proxied byte, this process
        static long savedTraffic;  // the last of those written to the file

        // The proxy calls this for every request it forwards and every chunk it copies.
        public static void Traffic() { Interlocked.Exchange(ref lastTraffic, DateTime.UtcNow.Ticks); }

        public static void Start(DateTime utcNow)
        {
            Write(utcNow.Ticks);
            Log.Info("manual connection started");
        }

        // False if there was none.
        public static bool Stop()
        {
            try
            {
                if (!File.Exists(FilePath)) return false;
                File.Delete(FilePath);
                return true;
            }
            catch (IOException) { return false; }
            catch (UnauthorizedAccessException) { return false; }
        }

        // The last activity: the start, or proxy traffic since; null with no session.
        public static DateTime? LastActive()
        {
            long ticks;
            string text;
            try { text = File.ReadAllText(FilePath).Trim(); }
            catch (IOException) { return null; }   // includes not found
            catch (UnauthorizedAccessException) { return null; }
            // A damaged file is no session: traffic alone must never start one.
            if (!long.TryParse(text, NumberStyles.None, CultureInfo.InvariantCulture, out ticks) || ticks <= 0 || ticks > DateTime.MaxValue.Ticks)
            {
                Stop();
                return null;
            }
            ticks = Math.Max(ticks, Interlocked.Read(ref lastTraffic));
            return new DateTime(ticks, DateTimeKind.Utc);
        }

        // The agent's view each pass: whether a manual connection is on. Ends
        // one that has been idle too long, and remembers traffic (at most once
        // a minute) so a restart keeps it.
        public static bool Check(DateTime utcNow)
        {
            DateTime? last = LastActive();
            if (last == null) return false;
            if (utcNow - last.Value >= Idle)
            {
                if (Stop()) Log.Info("manual connection over: no proxy traffic for " + (int)Idle.TotalMinutes + " min");
                return false;
            }
            long t = Interlocked.Read(ref lastTraffic);
            if (t == last.Value.Ticks && t - savedTraffic > TimeSpan.TicksPerMinute)   // traffic since the start, not before it
            {
                Write(t);
                savedTraffic = t;
            }
            return true;
        }

        public static string Describe(DateTime utcNow)
        {
            DateTime? last = LastActive();
            if (last == null) return "off";
            int ago = (int)Math.Max(0, (utcNow - last.Value).TotalMinutes);
            int left = (int)Math.Max(0, Math.Ceiling((Idle - (utcNow - last.Value)).TotalMinutes));
            return "on (last proxy traffic " + (ago == 0 ? "just now" : ago + " min ago") + "; ends after " + left + " more min without any)";
        }

        public static string Started()
        {
            return "Connecting. The VPN stays up, outside the hours too, until " + (int)Idle.TotalMinutes
                + " min pass without traffic through the proxy (manual_idle), or until ended (vpn-keeper disconnect, or /connect).";
        }

        static void Write(long ticks)
        {
            try
            {
                Directory.CreateDirectory(Path.GetDirectoryName(FilePath));
                File.WriteAllText(FilePath, ticks.ToString(CultureInfo.InvariantCulture));
            }
            catch (IOException e) { Log.Warn("could not save the manual connection: " + e.Message); }
            catch (UnauthorizedAccessException e) { Log.Warn("could not save the manual connection: " + e.Message); }
        }

        // For the tests.
        internal static void Reset() { Interlocked.Exchange(ref lastTraffic, 0); savedTraffic = 0; }
    }
}
