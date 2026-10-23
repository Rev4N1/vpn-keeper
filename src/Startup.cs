using System;
using System.IO;
using System.Reflection;

namespace VpnKeeper
{
    // A shortcut in the user's Startup folder: starts the agent at logon,
    // in the desktop session where it can see Connect Tunnel. No admin needed.
    static class Startup
    {
        static string ShortcutPath
        {
            get { return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Startup), "vpn-keeper.lnk"); }
        }

        public static void Install()
        {
            string exe = Assembly.GetExecutingAssembly().Location;
            Type t = Type.GetTypeFromProgID("WScript.Shell");
            object shell = Activator.CreateInstance(t);
            object lnk = t.InvokeMember("CreateShortcut", BindingFlags.InvokeMethod, null, shell, new object[] { ShortcutPath });
            Type lt = lnk.GetType();
            lt.InvokeMember("TargetPath", BindingFlags.SetProperty, null, lnk, new object[] { exe });
            lt.InvokeMember("WorkingDirectory", BindingFlags.SetProperty, null, lnk, new object[] { Path.GetDirectoryName(exe) });
            lt.InvokeMember("WindowStyle", BindingFlags.SetProperty, null, lnk, new object[] { 7 });   // minimised: the console closes at once
            lt.InvokeMember("Description", BindingFlags.SetProperty, null, lnk, new object[] { "Keeps the VPN logged in" });
            lt.InvokeMember("Save", BindingFlags.InvokeMethod, null, lnk, null);
            Console.WriteLine("installed: " + ShortcutPath + " -> " + exe);
            // Start it now through the shortcut, the same way logon will.
            System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo(ShortcutPath) { UseShellExecute = true });
            Console.WriteLine("started; it also starts at every logon. Log: " + Log.FilePath);
        }

        public static void Uninstall()
        {
            if (File.Exists(ShortcutPath))
            {
                File.Delete(ShortcutPath);
                Console.WriteLine("removed " + ShortcutPath + " (a running agent keeps running until logoff or Task Manager)");
            }
            else Console.WriteLine("not installed");
        }
    }
}
