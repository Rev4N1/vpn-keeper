// vpn-keeper - keeps the SonicWall Connect Tunnel VPN logged in on this
// laptop and shares it with the home network through a small HTTP proxy.
//
// Written for C# 5 / .NET Framework 4.8 so it builds with the csc.exe that
// ships with Windows: no SDK, no NuGet, one .exe.

using System;
using System.Runtime.InteropServices;

namespace VpnKeeper
{
    static class Program
    {
        [DllImport("kernel32.dll")]
        static extern uint GetConsoleProcessList(uint[] list, uint count);

        [DllImport("kernel32.dll")]
        static extern bool FreeConsole();

        const string Usage =
@"vpn-keeper " + BuildInfo.Version + @"

  vpn-keeper.exe            run the agent (keep awake, watchdog, proxy); Ctrl+C stops it
  vpn-keeper.exe check      check config, credentials and the VPN client
  vpn-keeper.exe otp        print the current one-time code (compare with your app)
  vpn-keeper.exe login      log the VPN in once, now, and exit
  vpn-keeper.exe dump       show the Connect Tunnel windows as the agent sees them
  vpn-keeper.exe install    start the agent at every Windows logon
  vpn-keeper.exe uninstall  stop starting it at logon
  vpn-keeper.exe selftest   run the built-in tests (CI also passes a fake client)
  vpn-keeper.exe version

Config: vpn-keeper.conf next to the .exe (optional; see the example).
Log:    %LOCALAPPDATA%\vpn-keeper\vpn-keeper.log";

        static int Main(string[] args)
        {
            string cmd = args.Length > 0 ? args[0].TrimStart('-', '/').ToLowerInvariant() : "run";
            if (cmd != "run") Log.Echo = true;
            else if (GetConsoleProcessList(new uint[2], 2) <= 1) FreeConsole();   // started from the shortcut: hide the window
            else Log.Echo = true;                                                 // started in a terminal: show the log live

            try
            {
                if (cmd == "selftest") return SelfTest.Run(args.Length > 1 ? args[1] : null);
                if (cmd == "version") { Console.WriteLine(BuildInfo.Version); return 0; }
                if (cmd == "help" || cmd == "h" || cmd == "?") { Console.WriteLine(Usage); return 0; }

                Config cfg = Config.Load(Config.DefaultPath());
                switch (cmd)
                {
                    case "run": return Agent.Run(cfg);
                    case "check": return Agent.Check(cfg);
                    case "otp": return Agent.PrintOtp(cfg);
                    case "dump": return Agent.Dump();
                    case "login": return Watchdog.LoginOnce(cfg) ? 0 : 1;
                    case "install": Startup.Install(); return 0;
                    case "uninstall": Startup.Uninstall(); return 0;
                }
                Console.WriteLine(Usage);
                return 2;
            }
            catch (Exception e)
            {
                Log.Error("fatal: " + e);
                return 1;
            }
        }
    }
}
