using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;

namespace VpnKeeper
{
    // vpn-keeper.conf: "key = value" lines, # starts a comment. Every key
    // is optional except profile, check_url and allow, which describe your VPN.
    class Config
    {
        public string Profile = "";                // Connect Tunnel configuration name (required)
        public string ClientExe = @"C:\Program Files\SonicWall\Modern Connect Tunnel\SnwlConnect.exe";
        public string CheckUrl = "";               // a URL only reachable through the VPN (required)
        public int CheckInterval = 30;            // seconds between health checks while up
        public int FailedChecks = 3;              // failed checks in a row before reconnecting
        public string Credential = "vpn-keeper:vpn";     // Windows Credential Manager entries
        public string OtpCredential = "vpn-keeper:otp";
        public int OtpDigits = 6;
        public int OtpPeriod = 30;
        public string Listen = "0.0.0.0:8080";
        public List<string> Clients = Split("10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 127.0.0.1/32");   // private ranges; the firewall narrows it
        public List<string> Allow = new List<string>();   // destinations behind the VPN (required for the proxy)
        public bool KeepAwake = true;

        public static string DefaultPath()
        {
            return Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "vpn-keeper.conf");
        }

        public static Config Load(string path)
        {
            Config c = new Config();
            if (!File.Exists(path)) return c;
            int n = 0;
            foreach (string raw in File.ReadAllLines(path))
            {
                n++;
                string line = raw;
                int hash = line.IndexOf('#');
                if (hash >= 0) line = line.Substring(0, hash);
                line = line.Trim();
                if (line.Length == 0) continue;
                int eq = line.IndexOf('=');
                if (eq < 0) throw new FormatException(path + ":" + n + ": expected key = value");
                c.Set(line.Substring(0, eq).Trim().ToLowerInvariant(), line.Substring(eq + 1).Trim(), path + ":" + n);
            }
            return c;
        }

        void Set(string key, string v, string where)
        {
            switch (key)
            {
                case "profile": Profile = v; break;
                case "client_exe": ClientExe = v; break;
                case "check_url": CheckUrl = v; break;
                case "check_interval": CheckInterval = Int(v, 5, 3600, where); break;
                case "failed_checks": FailedChecks = Int(v, 1, 100, where); break;
                case "credential": Credential = v; break;
                case "otp_credential": OtpCredential = v; break;
                case "otp_digits": OtpDigits = Int(v, 6, 8, where); break;
                case "otp_period": OtpPeriod = Int(v, 10, 120, where); break;
                case "listen": Listen = v; break;
                case "clients": Clients = Split(v); break;
                case "allow": Allow = Split(v); break;
                case "keep_awake": KeepAwake = v == "1" || v.ToLowerInvariant() == "true" || v.ToLowerInvariant() == "yes"; break;
                default: throw new FormatException(where + ": unknown key '" + key + "'");
            }
        }

        static int Int(string v, int min, int max, string where)
        {
            int i;
            if (!int.TryParse(v, NumberStyles.Integer, CultureInfo.InvariantCulture, out i) || i < min || i > max)
                throw new FormatException(where + ": '" + v + "' must be a number from " + min + " to " + max);
            return i;
        }

        public static List<string> Split(string v)
        {
            List<string> l = new List<string>();
            foreach (string p in v.Split(new[] { ' ', ',', ';', '\t' }, StringSplitOptions.RemoveEmptyEntries)) l.Add(p);
            return l;
        }
    }
}
