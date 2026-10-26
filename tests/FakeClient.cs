// A stand-in for SonicWall's SnwlConnect.exe, used only by the tests. Its
// windows copy the real client's (control types, captions, dialog order, the
// & shortcut markers, hiding to the tray once connected), and it really checks
// the password and the one-time code, so the login is tested end to end.
// Every login ends by offering a password change, as when it is about to
// expire; accepting really changes the password.
//
//   SnwlConnect.exe <password> <base32 seed> [<seconds until the session expires>]

using System;
using System.Drawing;
using System.Windows.Forms;

namespace VpnKeeper.Fake
{
    static class FakeClient
    {
        [STAThread]
        static int Main(string[] args)
        {
            if (args.Length < 2) { Console.Error.WriteLine("usage: SnwlConnect.exe <password> <seed> [expire-seconds]"); return 2; }
            Application.EnableVisualStyles();
            Application.Run(new MainForm(args[0], Totp.Base32Decode(args[1]), args.Length > 2 ? int.Parse(args[2]) : 0));
            return 0;
        }
    }

    class MainForm : Form
    {
        string password;   // changes when the user accepts a password change
        readonly byte[] key;
        readonly int expireSeconds;
        readonly ComboBox profile = new ComboBox();
        readonly Label status = new Label();
        readonly Button action = new Button();
        readonly Timer expiry = new Timer();
        int expiries;
        bool blocked;

        public MainForm(string password, byte[] key, int expireSeconds)
        {
            this.password = password;
            this.key = key;
            this.expireSeconds = expireSeconds;
            Text = "Connect Tunnel";
            ClientSize = new Size(560, 220);
            StartPosition = FormStartPosition.Manual;
            Location = new Point(40, 40);

            Label cfgLabel = new Label { Text = "Configuration:", Location = new Point(40, 60), AutoSize = true };
            profile.DropDownStyle = ComboBoxStyle.DropDownList;
            profile.Items.AddRange(new object[] { "VPN Lab", "VPN Office", "VPN Example" });
            profile.SelectedItem = "VPN Example";
            profile.Location = new Point(160, 56);
            profile.Width = 300;
            Label statusLabel = new Label { Text = "Status:", Location = new Point(40, 100), AutoSize = true };
            status.Text = "Disconnected";
            status.Location = new Point(160, 100);
            status.AutoSize = true;
            action.Text = "&Connect";   // the & marks the Alt shortcut, like many WinForms apps
            action.Location = new Point(420, 170);
            action.Click += OnAction;
            Controls.AddRange(new Control[] { cfgLabel, profile, statusLabel, status, action });

            expiry.Tick += delegate
            {
                expiry.Stop();
                if (++expiries % 2 == 0)
                {
                    // Every second expiry is the server's idle timeout: Disconnected,
                    // and a notice; Connect is ignored until someone presses OK.
                    SetState("Disconnected", "&Connect");
                    Show();
                    blocked = true;   // like the real one: Connect stays enabled but does nothing
                    using (NoticeForm n = new NoticeForm()) n.ShowDialog(this);
                    blocked = false;
                    return;
                }
                Show();   // the real client pops back up to ask again
                WindowState = FormWindowState.Normal;
                SetState("Reconnecting...", "&Cancel");
                BeginInvoke(new MethodInvoker(Authenticate));
            };
        }

        void SetState(string s, string button)
        {
            status.Text = s;
            action.Text = button;
            profile.Enabled = s == "Disconnected";
        }

        void OnAction(object sender, EventArgs e)
        {
            if (blocked) return;
            if (action.Text == "&Connect")
            {
                SetState("Connecting...", "&Cancel");
                BeginInvoke(new MethodInvoker(Authenticate));   // dialogs open after the handler returns
            }
            else { expiry.Stop(); SetState("Disconnected", "&Connect"); }
        }

        void Authenticate()
        {
            // A wrong password gets the prompt again, up to three times.
            for (int tries = 1; ; tries++)
                using (PasswordForm p = new PasswordForm())
                {
                    if (p.ShowDialog(this) != DialogResult.OK) { SetState("Disconnected", "&Connect"); return; }
                    if (p.Password == password) break;
                    if (tries == 3) { SetState("Disconnected", "&Connect"); return; }
                }
            using (OtpForm o = new OtpForm())
                if (o.ShowDialog(this) != DialogResult.OK || !CodeOk(o.Code)) { SetState("Disconnected", "&Connect"); return; }
            if (MessageBox.Show(this, "Your password will expire in 5 days. Do you want to change it now?", "Password expiring", MessageBoxButtons.YesNo) == DialogResult.Yes)
                using (ChangeForm c = new ChangeForm())
                {
                    if (c.ShowDialog(this) != DialogResult.OK) { SetState("Disconnected", "&Connect"); return; }
                    if (c.Old != password || c.New.Length == 0 || c.New != c.Confirm || c.New == password)
                    {
                        MessageBox.Show(this, "The password could not be changed.", "Change password");
                        SetState("Disconnected", "&Connect");
                        return;
                    }
                    password = c.New;
                }
            SetState("Connected", "&Disconnect");
            Hide();   // once connected, the real client goes to the tray
            if (expireSeconds > 0) { expiry.Interval = expireSeconds * 1000; expiry.Start(); }
        }

        bool CodeOk(string code)
        {
            long step = Totp.Step(DateTime.UtcNow, 30);
            for (long s = step - 1; s <= step + 1; s++) if (Totp.Code(key, s, 6) == code) return true;
            return false;
        }
    }

    class PasswordForm : Form
    {
        readonly TextBox pass = new TextBox();
        public string Password { get { return pass.Text; } }

        public PasswordForm()
        {
            Text = "Please log in:";
            ClientSize = new Size(520, 260);
            StartPosition = FormStartPosition.CenterParent;
            Label title = new Label { Text = "LOGIN", Location = new Point(30, 20), AutoSize = true };
            Label userLabel = new Label { Text = "User", Location = new Point(60, 70), AutoSize = true };
            TextBox user = new TextBox { Text = "test.user", Location = new Point(160, 66), Width = 280 };
            Label passLabel = new Label { Text = "Password", Location = new Point(60, 110), AutoSize = true };
            pass.Location = new Point(160, 106);
            pass.Width = 280;
            pass.UseSystemPasswordChar = true;
            Button ok = new Button { Text = "&OK", DialogResult = DialogResult.OK, Location = new Point(250, 210) };
            Button cancel = new Button { Text = "Cancel", DialogResult = DialogResult.Cancel, Location = new Point(360, 210) };
            Controls.AddRange(new Control[] { title, userLabel, user, passLabel, pass, ok, cancel });
            AcceptButton = ok;
            CancelButton = cancel;
        }
    }

    class ChangeForm : Form
    {
        readonly TextBox old = new TextBox(), neu = new TextBox(), confirm = new TextBox();
        public string Old { get { return old.Text; } }
        public string New { get { return neu.Text; } }
        public string Confirm { get { return confirm.Text; } }

        public ChangeForm()
        {
            Text = "Change Password";
            ClientSize = new Size(520, 260);
            StartPosition = FormStartPosition.CenterParent;
            Controls.Add(new Label { Text = "Old password", Location = new Point(30, 30), AutoSize = true });
            Controls.Add(old);
            Controls.Add(new Label { Text = "New password", Location = new Point(30, 80), AutoSize = true });
            Controls.Add(neu);
            Controls.Add(new Label { Text = "Confirm new password", Location = new Point(30, 130), AutoSize = true });
            Controls.Add(confirm);
            int y = 26;
            foreach (TextBox t in new[] { old, neu, confirm }) { t.Location = new Point(220, y); t.Width = 260; t.UseSystemPasswordChar = true; y += 50; }
            Button ok = new Button { Text = "OK", DialogResult = DialogResult.OK, Location = new Point(300, 210) };
            Button cancel = new Button { Text = "Cancel", DialogResult = DialogResult.Cancel, Location = new Point(400, 210) };
            Controls.AddRange(new Control[] { ok, cancel });
            AcceptButton = ok;
            CancelButton = cancel;
        }
    }

    class NoticeForm : Form
    {
        public NoticeForm()
        {
            Text = "Connect Tunnel";
            ClientSize = new Size(520, 140);
            StartPosition = FormStartPosition.CenterParent;
            Label info = new Label { Text = "Your session has been idle for 30 minutes and has been disconnected.", Location = new Point(20, 30), AutoSize = true };
            Button ok = new Button { Text = "OK", DialogResult = DialogResult.OK, Location = new Point(420, 95) };
            Controls.AddRange(new Control[] { info, ok });
            AcceptButton = ok;
        }
    }

    class OtpForm : Form
    {
        readonly TextBox code = new TextBox();
        public string Code { get { return code.Text.Trim(); } }

        public OtpForm()
        {
            Text = "One Time Password Required";
            ClientSize = new Size(800, 220);
            StartPosition = FormStartPosition.CenterParent;
            Label info = new Label { Text = "To continue with your login, enter the 6 digit code generated by the One Time Password app or the backup code.", Location = new Point(20, 20), AutoSize = true };
            Label prompt = new Label { Text = "Enter 6 digit code or backup code:", Location = new Point(20, 70), AutoSize = true };
            code.Location = new Point(280, 66);
            code.Width = 280;
            Button ok = new Button { Text = "&OK", DialogResult = DialogResult.OK, Location = new Point(500, 170) };
            Button cancel = new Button { Text = "Cancel", DialogResult = DialogResult.Cancel, Location = new Point(620, 170) };
            Controls.AddRange(new Control[] { info, prompt, code, ok, cancel });
            AcceptButton = ok;
            CancelButton = cancel;
        }
    }
}
