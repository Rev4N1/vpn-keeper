using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace VpnKeeper
{
    // vpn-keeper.conf, next to the installed .exe, written by "vpn-keeper setup".
    // "key = value" lines; # starts a comment. Secrets are not here: they are
    // in Windows Credential Manager.
    class Config
    {
        public string Profile = "";                       // Connect Tunnel configuration to log in to
        public string CheckUrl = "";                      // answers only through the VPN
        public List<string> Allow = new List<string>();   // what the proxy may reach
        public List<string> Clients = new List<string>(); // who may use the proxy
        public int Port = 8080;
        public string Hours = "";   // "HH:MM-HH:MM" the VPN may be connected; empty = always

        public static string InstallDir
        {
            get { return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Programs", "vpn-keeper"); }
        }

        public static string InstalledExe { get { return Path.Combine(InstallDir, "vpn-keeper.exe"); } }

        public static string FilePath { get { return Path.Combine(InstallDir, "vpn-keeper.conf"); } }

        public static Config Load() { return Load(FilePath); }

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
                string key = line.Substring(0, eq).Trim().ToLowerInvariant(), v = line.Substring(eq + 1).Trim();
                switch (key)
                {
                    case "profile": c.Profile = v; break;
                    case "check_url": c.CheckUrl = v; break;
                    case "allow": c.Allow = Split(v); break;
                    case "clients": c.Clients = Split(v); break;
                    case "port":
                        if (!int.TryParse(v, out c.Port) || c.Port < 1 || c.Port > 65535)
                            throw new FormatException(path + ":" + n + ": port must be 1-65535");
                        break;
                    case "hours":
                        try { Schedule.Parse(v); }
                        catch (FormatException e) { throw new FormatException(path + ":" + n + ": " + e.Message); }
                        c.Hours = v;
                        break;
                    default: throw new FormatException(path + ":" + n + ": unknown key '" + key + "'");
                }
            }
            return c;
        }

        public void Save(string path)
        {
            StringBuilder sb = new StringBuilder();
            sb.AppendLine("# vpn-keeper settings, written by 'vpn-keeper setup'. Secrets are in Windows Credential Manager.");
            sb.AppendLine("profile   = " + Profile);
            sb.AppendLine("check_url = " + CheckUrl);
            sb.AppendLine("allow     = " + string.Join(" ", Allow.ToArray()));
            sb.AppendLine("clients   = " + string.Join(" ", Clients.ToArray()));
            sb.AppendLine("port      = " + Port);
            sb.AppendLine("hours     = " + Hours + "   # HH:MM-HH:MM the VPN may be on; empty = always");
            Directory.CreateDirectory(Path.GetDirectoryName(path));
            File.WriteAllText(path, sb.ToString());
        }

        // What is missing for the agent to do its job; empty when complete.
        public List<string> Problems()
        {
            List<string> p = new List<string>();
            if (Profile.Length == 0) p.Add("no Connect Tunnel configuration (profile) set");
            if (CheckUrl.Length == 0) p.Add("no check URL set");
            if (Allow.Count == 0) p.Add("no sites to share (allow) set");
            return p;
        }

        public static List<string> Split(string v)
        {
            return new List<string>(v.Split(new[] { ' ', ',', ';', '\t' }, StringSplitOptions.RemoveEmptyEntries));
        }
    }
}
