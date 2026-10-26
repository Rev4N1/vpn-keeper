// vpn-keeper - keeps a SonicWall Connect Tunnel VPN logged in on this
// Windows PC and shares it with other machines through a small HTTP proxy.
//
// C# 5 / .NET Framework 4.8, so it builds with the csc.exe that ships with
// Windows: no SDK, no packages, one .exe.

using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Threading;

namespace VpnKeeper
{
    static class Program
    {
        const string Usage =
@"vpn-keeper " + BuildInfo.Version + @"

  vpn-keeper setup       set up or change settings (asks; Enter keeps the current values)
  vpn-keeper password    queue a new VPN password (used when the VPN asks to change it)
  vpn-keeper update      install this .exe over the running one (it restarts by itself)
  vpn-keeper status      how everything is, and what to fix
  vpn-keeper uninstall   stop it and remove it from this PC
  vpn-keeper run         run in this window, log on screen (for testing; Ctrl+C stops)";

        const string SupervisorMutex = @"Local\vpn-keeper";   // one supervisor per Windows session

        [DllImport("kernel32.dll")]
        static extern bool FreeConsole();

        static int Main(string[] args)
        {
            string cmd = args.Length > 0 ? args[0].TrimStart('-', '/').ToLowerInvariant() : "";
            try
            {
                switch (cmd)
                {
                    case "start": return Supervise();          // what autostart runs
                    case "agent": return RunAgent(false);      // started by the supervisor
                    case "run": Log.Echo = true; return RunAgent(true);
                    case "setup": return Setup.Run();
                    case "update": return Setup.Update();
                    case "password": return Setup.Password();
                    case "netsetup": return Admin.ApplyFromArgs(Skip(args));   // elevated worker, launched by setup with the plan as args
                    case "status": return Setup.Status();
                    case "uninstall": return Setup.Uninstall();
                    case "version": Console.WriteLine(BuildInfo.Version); return 0;
                }
                Console.WriteLine(Usage);
                return cmd.Length == 0 || cmd == "help" || cmd == "h" || cmd == "?" ? 0 : 2;
            }
            catch (Exception e)
            {
                Log.Echo = true;
                Log.Error(cmd + ": " + e.Message);
                Log.Debug(e.ToString());
                return 1;
            }
        }

        // Runs the agent as a child process and starts it again if it ever
        // exits, so a crash costs seconds, not the rest of the day.
        static int Supervise()
        {
            FreeConsole();   // started from the Startup shortcut: no window
            while (true)
            {
                string exe = Process.GetCurrentProcess().MainModule.FileName, stamp = Agent.ExeStamp(exe);
                bool created;
                using (Mutex m = new Mutex(true, SupervisorMutex, out created))
                {
                    if (!created) return 0;   // already running in this session
                    Log.Info("supervisor started");
                    Agent.BlockSleep();
                    int delay = 5;   // a quick exit waits 10 s, then doubles to 5 min
                    while (true)
                    {
                        // Nothing in here may throw out of the loop, or the agent
                        // would stop being restarted until the next logon.
                        int started = Environment.TickCount;
                        try
                        {
                            using (Process p = Process.Start(new ProcessStartInfo(exe, "agent") { UseShellExecute = false, CreateNoWindow = true }))
                            {
                                p.WaitForExit();
                                if (Agent.ExeStamp(exe) != stamp) break;   // updated: hand over to the new .exe
                                int ran = (Environment.TickCount - started) / 1000;
                                delay = ran < 60 ? Math.Min(delay * 2, 300) : 10;
                                Log.Warn("agent exited (code " + p.ExitCode + ") after " + ran + " s; starting it again in " + delay + " s");
                            }
                        }
                        catch (Exception e)
                        {
                            Log.Error("supervisor could not start the agent: " + e.Message);
                            delay = Math.Min(delay * 2, 300);
                        }
                        Thread.Sleep(delay * 1000);
                    }
                    m.ReleaseMutex();
                }
                // The mutex is gone now, so the new supervisor can take over.
                Log.Info("supervisor restarting on the new vpn-keeper.exe");
                if (HandOver(exe))
                {
                    Thread.Sleep(15000);   // keep blocking sleep until the new one blocks it too
                    return 0;
                }
                // The new .exe would not start. Keep this supervisor alive (it can
                // still run the new agent) rather than leave the PC unwatched.
                Log.Warn("the new supervisor did not start; this one keeps supervising");
                Thread.Sleep(5000);
            }
        }

        // Starts the new supervisor and waits until it really owns the mutex.
        // An earlier build's update could launch a half-copied .exe and then
        // quietly leave nothing running until the next logon.
        static bool HandOver(string exe)
        {
            for (int attempt = 1; attempt <= 12; attempt++)
            {
                try { Process.Start(new ProcessStartInfo(exe, "start") { UseShellExecute = false, CreateNoWindow = true }); }
                catch (Exception e) { Log.Error("could not start the new supervisor: " + e.Message); }
                if (SupervisorRunning(5000)) return true;
                Log.Warn("the new supervisor did not appear; trying again");
            }
            Log.Error("could not hand over to the new vpn-keeper.exe");
            return false;
        }

        static bool SupervisorRunning(int milliseconds)
        {
            for (int i = 0; i < milliseconds / 250; i++)
            {
                try
                {
                    Mutex m;
                    if (Mutex.TryOpenExisting(SupervisorMutex, out m)) { m.Dispose(); return true; }
                }
                catch (Exception) { }   // e.g. it is exiting; keep polling
                Thread.Sleep(250);
            }
            return false;
        }

        static string[] Skip(string[] args)
        {
            string[] rest = new string[Math.Max(0, args.Length - 1)];
            Array.Copy(args, 1, rest, 0, rest.Length);
            return rest;
        }

        static int RunAgent(bool foreground)
        {
            using (Mutex m = new Mutex(false, Agent.Mutex))
            {
                bool mine;
                try { mine = m.WaitOne(foreground ? 0 : Timeout.Infinite); }
                catch (AbandonedMutexException) { mine = true; }   // the previous agent died; take over
                if (!mine)
                {
                    Console.WriteLine("vpn-keeper is already running in the background. Stop it first: vpn-keeper uninstall");
                    return 3;
                }
                Agent.Run();
                return 0;
            }
        }
    }
}
