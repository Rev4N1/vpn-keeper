using System;
using System.Globalization;
using System.IO;
using System.Threading;

namespace VpnKeeper
{
    // A one-off connection outside 'hours' (say, a weekend), started with
    // "vpn-keeper connect" or on /connect. It follows the proxy's traffic:
    //
    //   active    proxy traffic in the last 30 min (or just started): keep the
    //             VPN up and log in again whenever it drops, as in hours
    //   standby   no proxy traffic for 30 min: once the VPN drops (the server's
    //             idle timeout), leave it down; the next proxy request logs in
    //             again, and the proxy holds that request until the VPN is up
    //   over      no proxy traffic for 4 hours, or "vpn-keeper disconnect"
    //
    // Inside 'hours' the schedule keeps the VPN up anyway; a connection started
    // then only keeps it up past the window's end while it is being used.
    //
    // The session is a file holding the time of the last activity, so the
    // command line (another process) can start or end it, and an agent restart
    // does not lose it.
    static class Manual
    {
        public enum State { Off, Active, Standby }

        public static readonly TimeSpan Idle = TimeSpan.FromMinutes(30);
        public static readonly TimeSpan Expire = TimeSpan.FromHours(4);

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
            if (!long.TryParse(text, NumberStyles.None, CultureInfo.InvariantCulture, out ticks)) ticks = 0;
            ticks = Math.Max(ticks, Interlocked.Read(ref lastTraffic));
            return ticks <= 0 ? (DateTime?)null : new DateTime(ticks, DateTimeKind.Utc);
        }

        // The agent's view each pass: ends an expired session and remembers
        // traffic (at most once a minute) so a restart keeps it.
        public static State Check(DateTime utcNow)
        {
            DateTime? last = LastActive();
            if (last == null) return State.Off;
            TimeSpan quiet = utcNow - last.Value;
            if (quiet >= Expire)
            {
                if (Stop()) Log.Info("manual connection over: no proxy traffic for " + (int)Expire.TotalHours + " hours");
                return State.Off;
            }
            long t = Interlocked.Read(ref lastTraffic);
            if (t == last.Value.Ticks && t - savedTraffic > TimeSpan.TicksPerMinute)   // traffic since the start, not before it
            {
                Write(t);
                savedTraffic = t;
            }
            return quiet < Idle ? State.Active : State.Standby;
        }

        public static string Describe(DateTime utcNow)
        {
            DateTime? last = LastActive();
            if (last == null) return "off";
            int ago = (int)Math.Max(0, (utcNow - last.Value).TotalMinutes);
            string since = ago == 0 ? "just now" : ago + " min ago";
            return (utcNow - last.Value < Idle ? "on" : "standby, the next proxy request reconnects")
                + " (last activity " + since + "; ends after " + (int)Expire.TotalHours + " h without proxy traffic)";
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
