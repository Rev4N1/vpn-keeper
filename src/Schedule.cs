using System;
using System.Globalization;

namespace VpnKeeper
{
    // When the VPN is allowed to be connected. Empty means always. Otherwise a
    // daily time window "HH:MM-HH:MM" (e.g. 07:30-17:30); a window whose end is
    // before its start runs overnight (e.g. 22:00-06:00).
    class Schedule
    {
        readonly int startMin = -1, endMin = -1;   // minutes from midnight; -1 = always
        public readonly string Text;

        Schedule(string text, int start, int end) { Text = text; startMin = start; endMin = end; }

        public bool Always { get { return startMin < 0; } }

        public static Schedule Parse(string s)
        {
            s = (s ?? "").Trim();
            if (s.Length == 0) return new Schedule("", -1, -1);
            string[] parts = s.Split('-');
            if (parts.Length != 2) throw new FormatException("hours must be HH:MM-HH:MM, e.g. 07:30-17:30");
            return new Schedule(s, Minutes(parts[0]), Minutes(parts[1]));
        }

        static int Minutes(string hhmm)
        {
            DateTime t;
            if (!DateTime.TryParseExact(hhmm.Trim(), new[] { "H:mm", "HH:mm" }, CultureInfo.InvariantCulture, DateTimeStyles.None, out t))
                throw new FormatException("'" + hhmm.Trim() + "' is not a HH:MM time");
            return t.Hour * 60 + t.Minute;
        }

        public bool Active(DateTime now)
        {
            if (Always) return true;
            int m = now.Hour * 60 + now.Minute;
            return startMin <= endMin ? (m >= startMin && m < endMin) : (m >= startMin || m < endMin);
        }
    }
}
