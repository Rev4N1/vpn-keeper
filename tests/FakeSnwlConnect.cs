// A stand-in for SonicWall's SnwlConnect.exe, used only by the self-test.
// It copies the real client's windows as seen with UI Automation (control
// types, captions, dialog order) and really checks the password and the
// one-time code, so the agent's login is tested end to end in CI.
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
            int expire = args.Length > 2 ? int.Parse(args[2]) : 0;
            Application.Run(new MainForm(args[0], Totp.Base32Decode(args[1]), expire));
            return 0;
        }
    }

    class MainForm : Form
    {
        readonly string password;
        readonly byte[] key;
        readonly int expireSeconds;
        readonly ComboBox profile = new ComboBox();
        readonly Label status = new Label();
        readonly Button action = new Button();
        readonly Timer expiry = new Timer();
        public int Logins;

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
            action.Text = "&Connect";   // shortcut marker, like many WinForms apps
            action.Location = new Point(420, 170);
            action.Click += OnAction;
            Controls.AddRange(new Control[] { cfgLabel, profile, statusLabel, status, action });

            expiry.Tick += delegate
            {
                expiry.Stop();
                // What the real client does at the 8h mark: it drops the tunnel
                // and asks for the credentials again.
                SetState("Reconnecting...", "&Cancel");
                Authenticate();
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
            if (action.Text == "&Connect")
            {
                SetState("Connecting...", "&Cancel");
                // The real client opens the dialogs after the button handler returns.
                BeginInvoke(new MethodInvoker(Authenticate));
            }
            else
            {
                expiry.Stop();
                SetState("Disconnected", "&Connect");
            }
        }

        void Authenticate()
        {
            using (PasswordForm p = new PasswordForm())
            {
                if (p.ShowDialog(this) != DialogResult.OK || p.Password != password)
                {
                    SetState("Disconnected", "&Connect");
                    return;
                }
            }
            using (OtpForm o = new OtpForm())
            {
                if (o.ShowDialog(this) != DialogResult.OK || !CodeOk(o.Code))
                {
                    SetState("Disconnected", "&Connect");
                    return;
                }
            }
            Logins++;
            SetState("Connected", "&Disconnect");
            // Like the real client: once connected, the window goes to the tray.
            Hide();
            if (expireSeconds > 0) { expiry.Interval = expireSeconds * 1000; expiry.Start(); }
        }

        bool CodeOk(string code)
        {
            long step = Totp.Step(DateTime.UtcNow, 30);
            for (long s = step - 1; s <= step + 1; s++)
                if (Totp.Code(key, s, 6) == code) return true;
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
            Label userLabel = new Label { Text = "Usuario", Location = new Point(60, 70), AutoSize = true };
            TextBox user = new TextBox { Text = "test.user", Location = new Point(160, 66), Width = 280 };
            Label passLabel = new Label { Text = "Contraseña", Location = new Point(60, 110), AutoSize = true };
            pass.Location = new Point(160, 106);
            pass.Width = 280;
            pass.UseSystemPasswordChar = true;
            CheckBox change = new CheckBox { Text = "Change password", Location = new Point(160, 140), AutoSize = true };
            Button ok = new Button { Text = "&OK", DialogResult = DialogResult.OK, Location = new Point(250, 210) };
            Button cancel = new Button { Text = "Cancel", DialogResult = DialogResult.Cancel, Location = new Point(360, 210) };
            Controls.AddRange(new Control[] { title, userLabel, user, passLabel, pass, change, ok, cancel });
            AcceptButton = ok;
            CancelButton = cancel;
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
            Label info = new Label
            {
                Text = "To continue with your login, enter the 6 digit code generated by the One Time Password app or the backup code.",
                Location = new Point(20, 20), AutoSize = true
            };
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
