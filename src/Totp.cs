using System;
using System.Security.Cryptography;

namespace VpnKeeper
{
    // RFC 6238 TOTP (HMAC-SHA1), the scheme authenticator apps use.
    static class Totp
    {
        public static long Step(DateTime utc, int period)
        {
            long unix = (long)(utc - new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc)).TotalSeconds;
            return unix / period;
        }

        public static int SecondsLeft(DateTime utc, int period)
        {
            long unix = (long)(utc - new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc)).TotalSeconds;
            return period - (int)(unix % period);
        }

        public static string Code(byte[] key, long step, int digits)
        {
            byte[] msg = new byte[8];
            for (int i = 7; i >= 0; i--) { msg[i] = (byte)(step & 0xff); step >>= 8; }
            byte[] h;
            using (HMACSHA1 mac = new HMACSHA1(key)) h = mac.ComputeHash(msg);
            int o = h[h.Length - 1] & 0x0f;
            int bin = ((h[o] & 0x7f) << 24) | (h[o + 1] << 16) | (h[o + 2] << 8) | h[o + 3];
            int mod = 1;
            for (int i = 0; i < digits; i++) mod *= 10;
            return (bin % mod).ToString().PadLeft(digits, '0');
        }

        // Base32 (RFC 4648) as shown by "can't scan? enter this key" screens:
        // spaces, dashes, lower case and missing padding are all accepted.
        public static byte[] Base32Decode(string s)
        {
            const string Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
            s = s.Trim().TrimEnd('=').Replace(" ", "").Replace("-", "").ToUpperInvariant();
            if (s.Length == 0) throw new FormatException("empty OTP seed");
            byte[] outb = new byte[s.Length * 5 / 8];
            int buffer = 0, bits = 0, n = 0;
            foreach (char c in s)
            {
                int v = Alphabet.IndexOf(c);
                if (v < 0) throw new FormatException("the OTP seed is not Base32 (only A-Z and 2-7)");
                buffer = (buffer << 5) | v;
                bits += 5;
                if (bits >= 8)
                {
                    bits -= 8;
                    outb[n++] = (byte)((buffer >> bits) & 0xff);
                }
            }
            // A one-character "seed" decodes to no bytes at all: reject it here
            // instead of silently generating codes from an empty key.
            if (outb.Length == 0) throw new FormatException("the OTP seed is too short");
            return outb;
        }
    }
}
