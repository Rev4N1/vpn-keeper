using System;
using System.IO;

namespace VpnKeeper
{
    // One log per Windows user, rotated at 2 MB. Secrets never reach it.
    static class Log
    {
        public static bool Echo;   // also print to the console
        static readonly object Gate = new object();

        public static string FilePath
        {
            get { return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "vpn-keeper", "vpn-keeper.log"); }
        }

        public static void Info(string msg) { Write("INFO ", msg, true); }
        public static void Warn(string msg) { Write("WARN ", msg, true); }
        public static void Error(string msg) { Write("ERROR", msg, true); }
        public static void Debug(string msg) { Write("DEBUG", msg, false); }   // file only

        static void Write(string level, string msg, bool echo)
        {
            string line = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss") + " " + level + " " + msg;
            lock (Gate)
            {
                if (Echo && echo) Console.WriteLine(line);
                try
                {
                    Directory.CreateDirectory(Path.GetDirectoryName(FilePath));
                    FileInfo f = new FileInfo(FilePath);
                    if (f.Exists && f.Length > 2 * 1024 * 1024)
                    {
                        File.Delete(FilePath + ".1");
                        File.Move(FilePath, FilePath + ".1");
                    }
                    File.AppendAllText(FilePath, line + Environment.NewLine);
                }
                catch (IOException) { }
                catch (UnauthorizedAccessException) { }
            }
        }
    }
}
