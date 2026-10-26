using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Threading;

namespace VpnKeeper
{
    // The long-running part: keeps the PC awake, serves the proxy, and runs
    // the VPN watchdog forever. Nothing in here may end the process, except
    // a new .exe being installed.
    static class Agent
    {
        public const string Mutex = @"Local\vpn-keeper-agent";   // one agent per Windows session

        [DllImport("kernel32.dll")]
        static extern uint SetThreadExecutionState(uint flags);
        const uint EsContinuous = 0x80000000, EsSystemRequired = 0x00000001;

        static long lastPass = DateTime.UtcNow.Ticks;   // when the main loop last went round

        // Idle sleep would cut the network and the VPN. This blocks it while the
        // calling thread's process runs (like a video player does); the screen
        // may still lock. The supervisor holds it too, so an agent restart is
        // never a gap: on a long-idle PC, Windows sleeps the moment none is held.
        public static void BlockSleep()
        {
            if (SetThreadExecutionState(EsContinuous | EsSystemRequired) == 0) Log.Warn("could not block idle sleep");
        }

        public static bool Running()
        {
            try
            {
                System.Threading.Mutex m;
                if (!System.Threading.Mutex.TryOpenExisting(Mutex, out m)) return false;
                m.Dispose();
                return true;
            }
            catch (UnauthorizedAccessException) { return false; }
        }

        public static void Run()
        {
            Log.Info("vpn-keeper " + BuildInfo.Version + " starting");

            // Block sleep before anything can fail: an unattended PC must not
            // doze off because the config needs a fix.
            BlockSleep();
            PruneDumps();

            // A bad config must not kill the agent (the supervisor would restart
            // it into the same error every ten seconds). Wait, and pick up a fix.
            Config cfg = null;
            while (cfg == null)
            {
                try { cfg = Config.Load(); }
                catch (Exception e)
                {
                    Log.Error("config: " + e.Message + " (fix " + Config.FilePath + "; retrying in 60 s)");
                    Thread.Sleep(60000);
                }
            }
            foreach (string p in cfg.Problems()) Log.Error("config: " + p + " (run vpn-keeper setup)");

            Proxy proxy = new Proxy(cfg.Port, new Rules(cfg.Clients), new Rules(cfg.Allow), Watchdog.Status.Report);
            proxy.SavePassword = Watchdog.SavePassword;
            proxy.PasswordAsked = Watchdog.Status.Asking;
            proxy.Start();

            // A pass takes 2 minutes at most (a login), so 10 minutes without one
            // means the agent is stuck: exit, and the supervisor starts a fresh one.
            Interlocked.Exchange(ref lastPass, DateTime.UtcNow.Ticks);   // the config wait above is not a stuck pass
            new Thread(delegate()
            {
                while (true)
                {
                    Thread.Sleep(60000);
                    if (DateTime.UtcNow.Ticks - Interlocked.Read(ref lastPass) > TimeSpan.FromMinutes(10).Ticks)
                    {
                        Log.Error("agent stuck for 10 minutes; exiting so the supervisor restarts it");
                        Environment.Exit(3);
                    }
                }
            }) { IsBackground = true, Name = "stuck-check" }.Start();

            string exe = System.Diagnostics.Process.GetCurrentProcess().MainModule.FileName, stamp = ExeStamp(exe);
            while (true)
            {
                Interlocked.Exchange(ref lastPass, DateTime.UtcNow.Ticks);
                // 'vpn-keeper update' swapped in a new .exe: exit, and the
                // supervisor starts the new one.
                if (ExeStamp(exe) != stamp)
                {
                    Log.Info("a new vpn-keeper.exe was installed; restarting on it");
                    proxy.Stop();
                    return;
                }
                int wait;
                try { wait = Watchdog.Tick(cfg); }
                catch (Exception e)
                {
                    Log.Error("watchdog: " + e.Message);
                    Log.Debug(e.ToString());
                    wait = 30;
                }
                Thread.Sleep(wait * 1000);
            }
        }

        // Changes when the file at that path is replaced.
        public static string ExeStamp(string path)
        {
            try { FileInfo f = new FileInfo(path); return f.Length + "@" + f.LastWriteTimeUtc.Ticks; }
            catch (IOException) { return ""; }
            catch (UnauthorizedAccessException) { return ""; }
        }

        // Dumps are tiny but one is written for each distinct window; over
        // months an unattended PC would collect thousands. Keep the recent ones.
        static void PruneDumps()
        {
            try
            {
                DirectoryInfo dir = new DirectoryInfo(Path.Combine(Path.GetDirectoryName(Log.FilePath), "dumps"));
                if (!dir.Exists) return;
                FileInfo[] files = dir.GetFiles("*.txt");
                Array.Sort(files, delegate(FileInfo a, FileInfo b) { return b.LastWriteTimeUtc.CompareTo(a.LastWriteTimeUtc); });
                DateTime old = DateTime.UtcNow.AddDays(-30);
                for (int i = 0; i < files.Length; i++)
                    if (i >= 50 || files[i].LastWriteTimeUtc < old)
                        try { files[i].Delete(); } catch (IOException) { } catch (UnauthorizedAccessException) { }
            }
            catch (Exception e) { Log.Debug("could not tidy the dumps: " + e.Message); }
        }
    }
}
