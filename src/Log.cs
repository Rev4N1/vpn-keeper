using System;
using System.IO;

namespace VpnKeeper
{
    // One log file per user, rotated at 2 MB. Secrets are never passed in here.
    static class Log
    {
        public static bool Echo;
        static readonly object Gate = new object();

        public static string Dir
        {
            get { return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "vpn-keeper"); }
        }

        public static string FilePath { get { return Path.Combine(Dir, "vpn-keeper.log"); } }

        public static void Info(string msg) { Write("INFO ", msg); }
        public static void Warn(string msg) { Write("WARN ", msg); }
        public static void Error(string msg) { Write("ERROR", msg); }

        static void Write(string level, string msg)
        {
            string line = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss") + " " + level + " " + msg;
            lock (Gate)
            {
                if (Echo) Console.WriteLine(line);
                try
                {
                    Directory.CreateDirectory(Dir);
                    FileInfo f = new FileInfo(FilePath);
                    if (f.Exists && f.Length > 2 * 1024 * 1024)
                    {
                        string old = FilePath + ".1";
                        if (File.Exists(old)) File.Delete(old);
                        File.Move(FilePath, old);
                    }
                    File.AppendAllText(FilePath, line + Environment.NewLine);
                }
                catch (IOException) { }
                catch (UnauthorizedAccessException) { }
            }
        }
    }
}
