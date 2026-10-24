using System;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.InteropServices;

namespace VpnKeeper
{
    // This PC's home network, and whether the VPN has claimed a subnet that
    // proxy clients come from. Everything here works without admin rights.
    class Lan
    {
        public string Address;   // this PC, e.g. 192.168.1.50
        public string Subnet;    // e.g. 192.168.1.0/24
        public string Gateway;   // the home router, e.g. 192.168.1.1
        public int IfIndex;

        // The physical adapter with a gateway on its own subnet. VPN and
        // virtual adapters are skipped by type and name.
        public static Lan Find()
        {
            foreach (NetworkInterface ni in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (ni.OperationalStatus != OperationalStatus.Up) continue;
                if (ni.NetworkInterfaceType != NetworkInterfaceType.Ethernet && ni.NetworkInterfaceType != NetworkInterfaceType.Wireless80211) continue;
                string d = (ni.Description + " " + ni.Name).ToLowerInvariant();
                if (d.Contains("vpn") || d.Contains("virtual") || d.Contains("sonicwall") || d.Contains("tap") || d.Contains("wireguard")) continue;
                IPInterfaceProperties props = ni.GetIPProperties();
                foreach (UnicastIPAddressInformation a in props.UnicastAddresses)
                {
                    if (a.Address.AddressFamily != AddressFamily.InterNetwork || a.IPv4Mask == null) continue;
                    uint ip = ToUint(a.Address), mask = ToUint(a.IPv4Mask);
                    foreach (GatewayIPAddressInformation g in props.GatewayAddresses)
                    {
                        if (g.Address.AddressFamily != AddressFamily.InterNetwork || (ToUint(g.Address) & mask) != (ip & mask)) continue;
                        Lan lan = new Lan();
                        lan.Address = a.Address.ToString();
                        lan.Subnet = FromUint(ip & mask) + "/" + Bits(mask);
                        lan.Gateway = g.Address.ToString();
                        lan.IfIndex = props.GetIPv4Properties().Index;
                        return lan;
                    }
                }
            }
            return null;
        }

        // True when traffic to this subnet would leave through another adapter
        // than the LAN one: replies to its clients would vanish into the VPN.
        public bool LosesRepliesTo(string cidr)
        {
            string net, mask;
            IPAddress host;
            if (!Rules.ParseCidr(cidr, out net, out mask, out host)) return false;
            MibIpForwardRow row;
            if (GetBestRoute(BitConverter.ToUInt32(host.GetAddressBytes(), 0), 0, out row) != 0) return false;
            return row.IfIndex != IfIndex;
        }

        public string RouteCommand(string cidr)
        {
            string net, mask;
            IPAddress host;
            Rules.ParseCidr(cidr, out net, out mask, out host);
            return "route -p add " + net + " mask " + mask + " " + Gateway + " metric 1";
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

        static int Bits(uint mask)
        {
            int n = 0;
            while ((mask & 0x80000000) != 0) { n++; mask <<= 1; }
            return n;
        }

        [StructLayout(LayoutKind.Sequential)]
        struct MibIpForwardRow
        {
            public uint Dest, Mask, Policy, NextHop, IfIndex, Type, Proto, Age, NextHopAs, Metric1, Metric2, Metric3, Metric4, Metric5;
        }

        [DllImport("iphlpapi.dll")]
        static extern int GetBestRoute(uint destination, uint source, out MibIpForwardRow row);
    }
}
