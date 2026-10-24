using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace VpnKeeper
{
    // The allow lists: which clients may use the proxy, and which
    // destinations it will reach. Entries are IPv4 CIDRs ("10.20.30.0/24"),
    // single addresses, host names, or "*.domain" for a domain and everything under it.
    class Rules
    {
        readonly List<uint[]> nets = new List<uint[]>();   // {network, mask}
        readonly List<string> names = new List<string>();  // exact host names
        readonly List<string> domains = new List<string>(); // ".corp.example" style suffixes
        readonly List<string> source;

        public override string ToString() { return source.Count == 0 ? "(none)" : string.Join(" ", source.ToArray()); }

        public Rules(IEnumerable<string> entries)
        {
            source = new List<string>(entries);
            foreach (string raw in source)
            {
                string e = raw.Trim().ToLowerInvariant();
                uint net, mask;
                if (TryCidr(e, out net, out mask)) nets.Add(new[] { net, mask });
                else if (e.StartsWith("*.")) domains.Add(e.Substring(1));
                else if (e.Length > 0) names.Add(e);
            }
        }

        public bool AllowsAddress(IPAddress ip)
        {
            if (ip.IsIPv4MappedToIPv6) ip = ip.MapToIPv4();
            if (ip.AddressFamily != AddressFamily.InterNetwork) return false;
            uint a = ToUint(ip);
            foreach (uint[] n in nets) if ((a & n[1]) == n[0]) return true;
            return false;
        }

        public bool AllowsName(string host)
        {
            string h = host.ToLowerInvariant().TrimEnd('.');
            if (names.Contains(h)) return true;
            foreach (string d in domains) if (h.EndsWith(d) || h == d.Substring(1)) return true;
            return false;
        }

        // A destination is allowed by name, or by its address (literal or resolved).
        public bool AllowsHost(string host, out IPAddress[] addresses)
        {
            addresses = null;
            IPAddress literal;
            if (IPAddress.TryParse(host, out literal))
            {
                addresses = new[] { literal };
                return AllowsAddress(literal);
            }
            if (AllowsName(host)) return true;
            if (nets.Count == 0) return false;
            try { addresses = Dns.GetHostAddresses(host); }
            catch (SocketException) { return false; }
            foreach (IPAddress a in addresses) if (AllowsAddress(a)) return true;
            return false;
        }

        // A PAC file that sends exactly the allowed destinations to this proxy
        // and everything else direct. Names never trigger DNS lookups on the
        // client (isInNet is only used on literal IPs), since the internal
        // names only resolve on the VPN side.
        public string Pac(string proxyHostPort)
        {
            StringBuilder sb = new StringBuilder();
            sb.Append("// vpn-keeper ").Append(BuildInfo.Version).Append(" - generated from the 'allow' list\n");
            sb.Append("function FindProxyForURL(url, host) {\n");
            sb.Append("  var p = \"PROXY ").Append(proxyHostPort).Append("\";\n");
            sb.Append("  host = host.toLowerCase();\n");
            foreach (string n in names) sb.Append("  if (host == \"").Append(n).Append("\") return p;\n");
            foreach (string d in domains)
                sb.Append("  if (dnsDomainIs(host, \"").Append(d).Append("\") || host == \"").Append(d.Substring(1)).Append("\") return p;\n");
            if (nets.Count > 0)
            {
                sb.Append("  if (/^\\d+\\.\\d+\\.\\d+\\.\\d+$/.test(host)) {\n");
                foreach (uint[] n in nets)
                    sb.Append("    if (isInNet(host, \"").Append(FromUint(n[0])).Append("\", \"").Append(FromUint(n[1])).Append("\")) return p;\n");
                sb.Append("  }\n");
            }
            sb.Append("  return \"DIRECT\";\n}\n");
            return sb.ToString();
        }

        // True for "10.20.30.0/24" or a bare IPv4 address, false for a host name.
        public static bool IsCidr(string e)
        {
            uint net, mask;
            return TryCidr(e, out net, out mask);
        }

        static bool TryCidr(string e, out uint net, out uint mask)
        {
            net = 0;
            mask = 0;
            string addr = e;
            int bits = 32;
            int slash = e.IndexOf('/');
            if (slash >= 0)
            {
                addr = e.Substring(0, slash);
                if (!int.TryParse(e.Substring(slash + 1), out bits) || bits < 0 || bits > 32) return false;
            }
            IPAddress ip;
            if (!IPAddress.TryParse(addr, out ip) || ip.AddressFamily != AddressFamily.InterNetwork) return false;
            if (addr.Split('.').Length != 4) return false;   // TryParse accepts "10" as 0.0.0.10
            mask = bits == 0 ? 0 : uint.MaxValue << (32 - bits);
            net = ToUint(ip) & mask;
            return true;
        }

        static uint ToUint(IPAddress ip)
        {
            byte[] b = ip.GetAddressBytes();
            return ((uint)b[0] << 24) | ((uint)b[1] << 16) | ((uint)b[2] << 8) | b[3];
        }

        static string FromUint(uint v)
        {
            return (v >> 24) + "." + ((v >> 16) & 0xff) + "." + ((v >> 8) & 0xff) + "." + (v & 0xff);
        }
    }
}
