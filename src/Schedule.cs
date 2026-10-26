using System;
using System.Collections.Generic;
using System.Globalization;

namespace VpnKeeper
{
    // When the VPN is allowed to be connected. Empty means always. Otherwise
    // one or more rules "[days] HH:MM-HH:MM", separated by commas:
    //
    //   07:30-17:30                        every day in that window
    //   Mon-Thu 07:45-17:00, Fri 07:45-15:00   weekdays, shorter Friday, weekend off
    //
    // Days are Mon Tue Wed Thu Fri Sat Sun (ranges like Mon-Thu, or lists like
    // Mon,Wed,Fri). A rule with no days applies to every day. The VPN is on
    // when any rule's days and time window include now; otherwise off.
    class Schedule
    {
        struct Rule { public int Days; public int Start, End; }   // Days: bit per DayOfWeek (Sun=0..Sat=6)

        readonly List<Rule> rules = new List<Rule>();   // empty = always

        public bool Always { get { return rules.Count == 0; } }

        public static Schedule Parse(string s)
        {
            s = (s ?? "").Trim();
            Schedule sched = new Schedule();
            if (s.Length == 0 || s.Equals("always", StringComparison.OrdinalIgnoreCase)) return sched;

            // Commas only separate; whitespace does the real splitting. A token
            // with ':' is a time window and ends the current rule; others name days.
            int days = 0;
            foreach (string tok in s.Replace(",", " ").Split(new[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries))
            {
                if (tok.IndexOf(':') >= 0)
                {
                    Rule r = new Rule();
                    r.Days = days == 0 ? 0x7F : days;   // no days named = every day
                    Window(tok, out r.Start, out r.End);
                    sched.rules.Add(r);
                    days = 0;
                }
                else days |= DayBits(tok);
            }
            if (days != 0) throw new FormatException("days '" + s + "' have no time window after them");
            if (sched.rules.Count == 0) throw new FormatException("hours needs a time window, e.g. 07:30-17:30");
            return sched;
        }

        public bool Active(DateTime now)
        {
            if (Always) return true;
            int bit = 1 << (int)now.DayOfWeek;
            int m = now.Hour * 60 + now.Minute;
            foreach (Rule r in rules)
                if ((r.Days & bit) != 0 && (r.Start <= r.End ? (m >= r.Start && m < r.End) : (m >= r.Start || m < r.End)))
                    return true;
            return false;
        }

        static void Window(string tok, out int start, out int end)
        {
            string[] parts = tok.Split('-');
            if (parts.Length != 2) throw new FormatException("'" + tok + "' must be HH:MM-HH:MM");
            start = Minutes(parts[0]);
            end = Minutes(parts[1]);
        }

        static int Minutes(string hhmm)
        {
            DateTime t;
            if (!DateTime.TryParseExact(hhmm.Trim(), new[] { "H:mm", "HH:mm" }, CultureInfo.InvariantCulture, DateTimeStyles.None, out t))
                throw new FormatException("'" + hhmm.Trim() + "' is not a HH:MM time");
            return t.Hour * 60 + t.Minute;
        }

        // A day name or range (Mon, Mon-Thu) to a bitmask. Ranges may wrap (Fri-Mon).
        static int DayBits(string tok)
        {
            int dash = tok.IndexOf('-');
            if (dash < 0) return 1 << Day(tok);
            int from = Day(tok.Substring(0, dash)), to = Day(tok.Substring(dash + 1));
            int bits = 0;
            for (int i = from; ; i = (i + 1) % 7)
            {
                bits |= 1 << i;
                if (i == to) break;
            }
            return bits;
        }

        static int Day(string name)
        {
            switch (name.Trim().ToLowerInvariant())
            {
                case "sun": case "sunday": return 0;
                case "mon": case "monday": return 1;
                case "tue": case "tues": case "tuesday": return 2;
                case "wed": case "weds": case "wednesday": return 3;
                case "thu": case "thur": case "thurs": case "thursday": return 4;
                case "fri": case "friday": return 5;
                case "sat": case "saturday": return 6;
                default: throw new FormatException("'" + name + "' is not a day (Mon Tue Wed Thu Fri Sat Sun)");
            }
        }
    }
}
