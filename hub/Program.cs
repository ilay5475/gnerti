using System.Diagnostics;
using System.Drawing.Drawing2D;
using System.Security.Cryptography;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace GnertiHub
{
    // ===== Цвета gnerti (как на сайте) =====
    static class Theme
    {
        public static readonly Color Bg = Color.FromArgb(12, 14, 28);
        public static readonly Color Side = Color.FromArgb(17, 19, 38);
        public static readonly Color Surface = Color.FromArgb(24, 27, 52);
        public static readonly Color SurfaceHover = Color.FromArgb(32, 36, 68);
        public static readonly Color Line = Color.FromArgb(42, 46, 80);
        public static readonly Color Fg = Color.FromArgb(233, 235, 247);
        public static readonly Color Muted = Color.FromArgb(146, 152, 184);
        public static Color Accent = Color.FromArgb(115, 129, 255);
        public static readonly (string Name, Color Color)[] Accents =
        {
            ("Синий", Color.FromArgb(115, 129, 255)),
            ("Фиолетовый", Color.FromArgb(170, 110, 255)),
            ("Бирюзовый", Color.FromArgb(40, 190, 200)),
            ("Зелёный", Color.FromArgb(70, 190, 120)),
            ("Розовый", Color.FromArgb(240, 95, 160)),
        };
        public static void UseAccent(int i) => Accent = Accents[Math.Clamp(i, 0, Accents.Length - 1)].Color;
        public static Icon AppIcon
        {
            get { try { return Icon.ExtractAssociatedIcon(Application.ExecutablePath); } catch { return null; } }
        }
        public static readonly Color Signal = Color.FromArgb(255, 123, 77);
        public static readonly Color Danger = Color.FromArgb(235, 87, 97);
        public static readonly Color Good = Color.FromArgb(80, 200, 140);
        public static readonly Color Gold = Color.FromArgb(255, 200, 70);

        public static Font Font(float size, FontStyle style = FontStyle.Regular) =>
            new Font("Segoe UI", size, style);
    }

    // ===== Данные =====
    public class AppItem
    {
        public string Id { get; set; } = Guid.NewGuid().ToString("N");
        public string Name { get; set; } = "";
        public string Category { get; set; } = "Игры";
        public string Description { get; set; } = "";
        public string Path { get; set; } = "";
        public string IconPath { get; set; } = "";
        public int Launches { get; set; }
        public double MinutesPlayed { get; set; }
        public DateTime? LastLaunched { get; set; }
        public DateTime Added { get; set; } = DateTime.Now;
    }

    public class UserAccount
    {
        public string Login { get; set; } = "";
        public string Nickname { get; set; } = "";
        public string Salt { get; set; } = "";
        public string Hash { get; set; } = "";
        public bool IsAdmin { get; set; }
        public DateTime Created { get; set; } = DateTime.Now;
        public List<string> Favorites { get; set; } = new();
        public int AccentIndex { get; set; }
        public string Sort { get; set; } = "Популярные";
    }

    public class NewsPost
    {
        public string Id { get; set; } = Guid.NewGuid().ToString("N");
        public string Title { get; set; } = "";
        public string Text { get; set; } = "";
        public string Author { get; set; } = "";
        public DateTime Date { get; set; } = DateTime.Now;
    }

    public class HubData
    {
        public List<UserAccount> Users { get; set; } = new();
        public List<AppItem> Apps { get; set; } = new();
        public List<NewsPost> News { get; set; } = new();
        public string RememberedLogin { get; set; } = "";
        public string ServerUrl { get; set; } = "";
        public string ServerKey { get; set; } = "";
        public string SessionToken { get; set; } = "";
        public bool LocalOnly { get; set; }

        // Официальный сервер gnerti. Publishable key — публичный ключ, его можно встраивать в программу.
        public const string DefaultServerUrl = "https://bkhzbyaivzkzbdhujglb.supabase.co";
        public const string DefaultServerKey = "sb_publishable_yKbh1_FgzOD7E69ULu6sog_98K-wOZG";
        public int[] Window { get; set; }
        public bool Maximized { get; set; }
    }

    static class Storage
    {
        static readonly string Dir = System.IO.Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "gnerti");
        static readonly string FilePath = System.IO.Path.Combine(Dir, "hub.json");

        public static HubData Load()
        {
            HubData d = null;
            try
            {
                if (File.Exists(FilePath))
                    d = JsonSerializer.Deserialize<HubData>(File.ReadAllText(FilePath));
            }
            catch { }
            d ??= new HubData();
            // Старые версии: у продуктов не было Id
            foreach (var a in d.Apps)
                if (string.IsNullOrEmpty(a.Id)) a.Id = Guid.NewGuid().ToString("N");
            foreach (var u in d.Users) u.Favorites ??= new();
            d.News ??= new();
            // По умолчанию подключаемся к облаку gnerti
            if (!d.LocalOnly && string.IsNullOrWhiteSpace(d.ServerUrl))
            {
                d.ServerUrl = HubData.DefaultServerUrl;
                d.ServerKey = HubData.DefaultServerKey;
            }
            return d;
        }

        public static void Save(HubData data)
        {
            try
            {
                Directory.CreateDirectory(Dir);
                File.WriteAllText(FilePath, JsonSerializer.Serialize(data,
                    new JsonSerializerOptions { WriteIndented = true }));
            }
            catch (Exception ex)
            {
                MessageBox.Show("Не удалось сохранить: " + ex.Message, "gnerti Hub");
            }
        }
    }

    // ===== Пароли: хранятся не в открытом виде, а как защищённый хеш =====
    static class Auth
    {
        const int Iterations = 100_000;

        public static void SetPassword(UserAccount u, string password)
        {
            byte[] salt = RandomNumberGenerator.GetBytes(16);
            byte[] hash = Rfc2898DeriveBytes.Pbkdf2(password, salt, Iterations, HashAlgorithmName.SHA256, 32);
            u.Salt = Convert.ToBase64String(salt);
            u.Hash = Convert.ToBase64String(hash);
        }

        public static bool Check(UserAccount u, string password)
        {
            try
            {
                byte[] salt = Convert.FromBase64String(u.Salt);
                byte[] expected = Convert.FromBase64String(u.Hash);
                byte[] actual = Rfc2898DeriveBytes.Pbkdf2(password, salt, Iterations, HashAlgorithmName.SHA256, 32);
                return CryptographicOperations.FixedTimeEquals(expected, actual);
            }
            catch { return false; }
        }

        public static string ValidateLogin(string login, HubData data)
        {
            if (!Regex.IsMatch(login, "^[A-Za-z0-9_]{3,20}$"))
                return "Логин: от 3 до 20 символов, только английские буквы, цифры и _";
            if (data.Users.Any(u => u.Login.Equals(login, StringComparison.OrdinalIgnoreCase)))
                return "Такой логин уже занят";
            return null;
        }

        public static string ValidatePassword(string pass, string repeat)
        {
            if (pass.Length < 6) return "Пароль должен быть минимум 6 символов";
            if (!pass.Any(char.IsDigit) || !pass.Any(char.IsLetter))
                return "В пароле должны быть и буквы, и цифры";
            if (pass != repeat) return "Пароли не совпадают";
            return null;
        }

        public static UserAccount Find(HubData data, string login) =>
            data.Users.FirstOrDefault(u => u.Login.Equals(login, StringComparison.OrdinalIgnoreCase));
    }

    // ===== Картинки (загружаем без блокировки файла) =====
    static class Images
    {
        static readonly Dictionary<string, Image> cache = new();
        public static Image Get(string path)
        {
            if (string.IsNullOrWhiteSpace(path) || !File.Exists(path)) return null;
            if (cache.TryGetValue(path, out var img)) return img;
            try
            {
                using var ms = new MemoryStream(File.ReadAllBytes(path));
                using var tmp = Image.FromStream(ms);
                img = new Bitmap(tmp);
                cache[path] = img;
                return img;
            }
            catch { return null; }
        }
        public static void Forget(string path) { if (path != null) cache.Remove(path); }
    }

    static class Fmt
    {
        public static string Time(double minutes)
        {
            if (minutes < 1) return "меньше минуты";
            if (minutes < 60) return $"{(int)minutes} мин";
            return $"{(int)(minutes / 60)} ч {(int)(minutes % 60)} мин";
        }
        public static string Ago(DateTime? d)
        {
            if (d == null) return "ещё не запускали";
            var t = DateTime.Now - d.Value;
            if (t.TotalMinutes < 1) return "только что";
            if (t.TotalHours < 1) return $"{(int)t.TotalMinutes} мин назад";
            if (t.TotalDays < 1) return $"{(int)t.TotalHours} ч назад";
            if (t.TotalDays < 7) return $"{(int)t.TotalDays} дн назад";
            return d.Value.ToString("dd.MM.yyyy");
        }
    }

    // ===== Логотип gnerti: кольцо + оранжевый квадрат =====
    class LogoBox : Control
    {
        public LogoBox() { DoubleBuffered = true; Size = new Size(40, 40); }
        protected override void OnPaint(PaintEventArgs e)
        {
            var g = e.Graphics;
            g.SmoothingMode = SmoothingMode.AntiAlias;
            g.Clear(Parent?.BackColor ?? Theme.Side);
            float s = Math.Min(Width, Height);
            float pen = s * 0.15f;
            var r = new RectangleF(pen / 2 + 1, pen / 2 + 1, s - pen - 2, s - pen - 2);
            using (var p = new Pen(Theme.Accent, pen))
                g.DrawArc(p, r, 30, 290);
            float q = s * 0.24f;
            using var b = new SolidBrush(Theme.Signal);
            g.FillRectangle(b, s * 0.60f, s / 2 - q / 2, q, q);
        }
    }

    // ===== Иконка продукта: картинка или буква на цветном квадрате =====
    class ProductIcon : Control
    {
        readonly AppItem item;
        public ProductIcon(AppItem item, int size)
        {
            this.item = item;
            DoubleBuffered = true;
            Size = new Size(size, size);
        }
        protected override void OnPaint(PaintEventArgs e)
        {
            var g = e.Graphics;
            g.SmoothingMode = SmoothingMode.AntiAlias;
            g.InterpolationMode = InterpolationMode.HighQualityBicubic;
            g.Clear(Parent?.BackColor ?? Theme.Surface);

            using var path = RoundRect(new Rectangle(0, 0, Width - 1, Height - 1), 10);
            var img = Images.Get(item.IconPath);
            if (img != null)
            {
                g.SetClip(path);
                g.DrawImage(img, new Rectangle(0, 0, Width, Height));
                g.ResetClip();
                return;
            }
            Color c = item.Category switch
            {
                "Игры" => Theme.Signal,
                "Программы" => Theme.Accent,
                "Гаджеты" => Theme.Good,
                _ => Color.FromArgb(190, 110, 255)
            };
            using (var b = new SolidBrush(c)) g.FillPath(b, path);
            string letter = item.Name.Length > 0 ? item.Name.Substring(0, 1).ToUpper() : "?";
            using var f = Theme.Font(Height * 0.36f, FontStyle.Bold);
            TextRenderer.DrawText(g, letter, f, new Rectangle(0, 0, Width, Height), Color.White,
                TextFormatFlags.HorizontalCenter | TextFormatFlags.VerticalCenter);
        }
        public static GraphicsPath RoundRect(Rectangle r, int rad)
        {
            var p = new GraphicsPath();
            int d = rad * 2;
            p.AddArc(r.X, r.Y, d, d, 180, 90);
            p.AddArc(r.Right - d, r.Y, d, d, 270, 90);
            p.AddArc(r.Right - d, r.Bottom - d, d, d, 0, 90);
            p.AddArc(r.X, r.Bottom - d, d, d, 90, 90);
            p.CloseFigure();
            return p;
        }
    }

    // ===== Кнопка меню слева =====
    class NavButton : Button
    {
        public bool Active;
        public string Page;
        public NavButton(string text, string icon)
        {
            Page = text;
            Text = "  " + icon + "   " + text;
            FlatStyle = FlatStyle.Flat;
            FlatAppearance.BorderSize = 0;
            FlatAppearance.MouseOverBackColor = Theme.Surface;
            TextAlign = ContentAlignment.MiddleLeft;
            Font = Theme.Font(11);
            ForeColor = Theme.Muted;
            BackColor = Theme.Side;
            Height = 44;
            Dock = DockStyle.Top;
            Cursor = Cursors.Hand;
        }
        protected override void OnPaint(PaintEventArgs e)
        {
            BackColor = Active ? Theme.Surface : Theme.Side;
            if (Page != "Админ") ForeColor = Active ? Theme.Fg : Theme.Muted;
            base.OnPaint(e);
            if (Active)
            {
                using var b = new SolidBrush(Theme.Accent);
                e.Graphics.FillRectangle(b, 0, 8, 4, Height - 16);
            }
        }
    }

    static class UI
    {
        public static Button MakeButton(string text, Color back, Color fore)
        {
            var b = new Button
            {
                Text = text,
                FlatStyle = FlatStyle.Flat,
                BackColor = back,
                ForeColor = fore,
                Font = Theme.Font(10, FontStyle.Bold),
                Cursor = Cursors.Hand,
                AutoSize = true,
                Padding = new Padding(10, 4, 10, 4)
            };
            b.FlatAppearance.BorderSize = 0;
            return b;
        }

        public static Label MakeLabel(string text, float size, Color color, FontStyle style = FontStyle.Regular)
        {
            return new Label
            {
                Text = text,
                Font = Theme.Font(size, style),
                ForeColor = color,
                AutoSize = true,
                BackColor = Color.Transparent
            };
        }

        public static TextBox MakeBox(int width, bool password = false)
        {
            return new TextBox
            {
                Width = width,
                BackColor = Theme.Surface,
                ForeColor = Theme.Fg,
                BorderStyle = BorderStyle.FixedSingle,
                Font = Theme.Font(12),
                UseSystemPasswordChar = password
            };
        }

        // Поле пароля с кнопкой «показать»
        public static Panel PasswordBox(int width, out TextBox box)
        {
            var panel = new Panel { Size = new Size(width, 30), BackColor = Theme.Bg, Margin = new Padding(0) };
            var tb = MakeBox(width - 40, true);
            tb.Location = new Point(0, 0);
            var eye = MakeButton("👁", Theme.Surface, Theme.Muted);
            eye.AutoSize = false;
            eye.Size = new Size(36, tb.Height);
            eye.Location = new Point(width - 36, 0);
            eye.Padding = new Padding(0);
            eye.Click += (s, e) =>
            {
                tb.UseSystemPasswordChar = !tb.UseSystemPasswordChar;
                eye.ForeColor = tb.UseSystemPasswordChar ? Theme.Muted : Theme.Accent;
            };
            panel.Controls.Add(tb); panel.Controls.Add(eye);
            panel.Height = tb.Height;
            box = tb;
            return panel;
        }
    }

    // ===== Окно входа и регистрации =====
    class LoginForm : Form
    {
        readonly HubData data;
        public UserAccount LoggedIn;
        bool registerMode;

        readonly Panel body = new() { Dock = DockStyle.Fill, BackColor = Theme.Bg };

        public LoginForm(HubData data)
        {
            this.data = data;
            Text = "gnerti — вход";
            Icon = Theme.AppIcon;
            BackColor = Theme.Bg;
            ForeColor = Theme.Fg;
            Font = Theme.Font(10);
            FormBorderStyle = FormBorderStyle.FixedSingle;
            MaximizeBox = false;
            StartPosition = FormStartPosition.CenterScreen;
            ClientSize = new Size(440, 660);
            Controls.Add(body);

            registerMode = !Accounts.Online && data.Users.Count == 0;
            Build();
        }

        void Build()
        {
            body.Controls.Clear();
            var stack = new FlowLayoutPanel
            {
                Dock = DockStyle.Fill,
                FlowDirection = FlowDirection.TopDown,
                WrapContents = false,
                Padding = new Padding(44, 36, 44, 20),
                BackColor = Theme.Bg
            };
            body.Controls.Add(stack);

            var top = new FlowLayoutPanel { AutoSize = true, WrapContents = false, Margin = new Padding(0, 0, 0, 24) };
            top.Controls.Add(new LogoBox { Size = new Size(44, 44), Margin = new Padding(0, 0, 10, 0) });
            top.Controls.Add(UI.MakeLabel("gnerti", 22, Theme.Fg, FontStyle.Bold));
            stack.Controls.Add(top);

            stack.Controls.Add(UI.MakeLabel(registerMode ? "Создать аккаунт" : "Вход в аккаунт", 18, Theme.Fg, FontStyle.Bold));
            var where = UI.MakeLabel(Accounts.Online ? "☁ Онлайн-аккаунт gnerti" : "Аккаунт на этом компьютере", 9.5f,
                Accounts.Online ? Theme.Good : Theme.Muted);
            where.Margin = new Padding(0, 4, 0, 0);
            stack.Controls.Add(where);
            if (registerMode && !Accounts.Online && data.Users.Count == 0)
            {
                var first = UI.MakeLabel("Это первый аккаунт, он станет администратором.", 9.5f, Theme.Signal);
                first.Margin = new Padding(0, 4, 0, 0);
                stack.Controls.Add(first);
            }

            TextBox login, nick = null, pass, repeat = null;

            stack.Controls.Add(Field("Логин"));
            login = UI.MakeBox(350); stack.Controls.Add(login);

            if (registerMode)
            {
                stack.Controls.Add(Field("Ник (как тебя будут видеть)"));
                nick = UI.MakeBox(350); stack.Controls.Add(nick);
            }

            stack.Controls.Add(Field("Пароль"));
            stack.Controls.Add(UI.PasswordBox(350, out pass));

            if (registerMode)
            {
                stack.Controls.Add(Field("Повтори пароль"));
                stack.Controls.Add(UI.PasswordBox(350, out repeat));

                var hint = UI.MakeLabel("Минимум 6 символов, буквы и цифры", 9, Theme.Muted);
                hint.Margin = new Padding(0, 4, 0, 0);
                stack.Controls.Add(hint);
            }

            var remember = new CheckBox
            {
                Text = "Запомнить меня",
                ForeColor = Theme.Muted,
                AutoSize = true,
                Checked = true,
                Margin = new Padding(0, 12, 0, 0)
            };
            stack.Controls.Add(remember);

            var error = UI.MakeLabel("", 9.5f, Theme.Danger);
            error.MaximumSize = new Size(350, 0);
            error.Margin = new Padding(0, 8, 0, 0);
            stack.Controls.Add(error);

            var go = UI.MakeButton(registerMode ? "Создать аккаунт" : "Войти", Theme.Accent, Color.White);
            go.AutoSize = false;
            go.Size = new Size(350, 42);
            go.Margin = new Padding(0, 10, 0, 0);
            stack.Controls.Add(go);
            AcceptButton = go;

            go.Click += async (s, e) =>
            {
                error.Text = "";
                string l = login.Text.Trim();
                if (registerMode)
                {
                    string err = (string.IsNullOrWhiteSpace(nick.Text) ? "Впиши ник" : null)
                                 ?? Auth.ValidatePassword(pass.Text, repeat.Text);
                    if (err != null) { error.Text = err; return; }
                }
                go.Enabled = false;
                error.ForeColor = Theme.Muted;
                error.Text = Accounts.Online ? "Подключаюсь к серверу..." : "";
                try
                {
                    LoggedIn = registerMode
                        ? await Accounts.Register(l, nick.Text.Trim(), pass.Text, remember.Checked)
                        : await Accounts.Login(l, pass.Text, remember.Checked);
                    DialogResult = DialogResult.OK;
                }
                catch (HubError ex)
                {
                    error.ForeColor = Theme.Danger;
                    error.Text = ex.Message;
                    pass.Text = "";
                }
                finally { if (!IsDisposed) go.Enabled = true; }
            };

            if (Accounts.Online || data.Users.Count > 0)
            {
                var switchLink = new LinkLabel
                {
                    Text = registerMode ? "Уже есть аккаунт? Войти" : "Нет аккаунта? Зарегистрироваться",
                    LinkColor = Theme.Accent,
                    ActiveLinkColor = Theme.Fg,
                    AutoSize = true,
                    Margin = new Padding(0, 14, 0, 0)
                };
                switchLink.Click += (s, e) => { registerMode = !registerMode; Build(); };
                stack.Controls.Add(switchLink);
            }

            var server = new LinkLabel
            {
                Text = "⚙ Настроить сервер",
                LinkColor = Theme.Muted,
                ActiveLinkColor = Theme.Fg,
                AutoSize = true,
                Margin = new Padding(0, 10, 0, 0)
            };
            server.Click += (s, e) =>
            {
                using var d = new ServerDialog(data);
                if (d.ShowDialog(this) == DialogResult.OK)
                {
                    registerMode = !Accounts.Online && data.Users.Count == 0;
                    Build();
                }
            };
            stack.Controls.Add(server);

            ActiveControl = login;
        }

        Label Field(string text)
        {
            var l = UI.MakeLabel(text, 10, Theme.Muted);
            l.Margin = new Padding(0, 14, 0, 4);
            return l;
        }

    }

    // ===== Окно добавления / изменения продукта (только для админа) =====
    class ProductDialog : Form
    {
        public AppItem Result;
        readonly TextBox name = UI.MakeBox(440);
        readonly ComboBox cat = new();
        readonly TextBox desc = UI.MakeBox(440);
        readonly TextBox path = UI.MakeBox(340);
        readonly TextBox icon = UI.MakeBox(340);

        public ProductDialog(AppItem existing, string defaultCategory)
        {
            Text = existing == null ? "Добавить в gnerti Hub" : "Изменить продукт";
            Icon = Theme.AppIcon;
            BackColor = Theme.Bg;
            ForeColor = Theme.Fg;
            Font = Theme.Font(10);
            FormBorderStyle = FormBorderStyle.FixedDialog;
            MaximizeBox = false; MinimizeBox = false;
            StartPosition = FormStartPosition.CenterParent;
            ClientSize = new Size(490, 500);

            var layout = new FlowLayoutPanel
            {
                Dock = DockStyle.Fill,
                Padding = new Padding(20),
                FlowDirection = FlowDirection.TopDown,
                WrapContents = false
            };
            Controls.Add(layout);

            layout.Controls.Add(Field("Название"));
            layout.Controls.Add(name);

            layout.Controls.Add(Field("Раздел"));
            cat.DropDownStyle = ComboBoxStyle.DropDownList;
            cat.Items.AddRange(new object[] { "Игры", "Программы", "Гаджеты", "ИИ" });
            cat.BackColor = Theme.Surface; cat.ForeColor = Theme.Fg; cat.FlatStyle = FlatStyle.Flat;
            cat.Width = 200;
            layout.Controls.Add(cat);

            layout.Controls.Add(Field("Описание"));
            desc.Multiline = true; desc.Height = 70; desc.Font = Theme.Font(10);
            desc.MaxLength = 200;
            layout.Controls.Add(desc);

            layout.Controls.Add(Field("Файл .exe или ссылка (https://...)"));
            layout.Controls.Add(Row(path, "Программы (*.exe;*.lnk;*.bat)|*.exe;*.lnk;*.bat|Все файлы (*.*)|*.*", true));

            layout.Controls.Add(Field("Картинка-иконка (необязательно)"));
            layout.Controls.Add(Row(icon, "Картинки (*.png;*.jpg;*.jpeg;*.bmp;*.gif)|*.png;*.jpg;*.jpeg;*.bmp;*.gif", false));

            if (existing != null)
            {
                name.Text = existing.Name;
                cat.SelectedItem = existing.Category;
                desc.Text = existing.Description;
                path.Text = existing.Path;
                icon.Text = existing.IconPath;
            }
            else cat.SelectedItem = cat.Items.Contains(defaultCategory) ? defaultCategory : "Игры";

            var ok = UI.MakeButton(existing == null ? "Добавить" : "Сохранить", Theme.Accent, Color.White);
            ok.Margin = new Padding(3, 18, 3, 3);
            ok.Click += (s, e) =>
            {
                if (string.IsNullOrWhiteSpace(name.Text) || string.IsNullOrWhiteSpace(path.Text))
                {
                    MessageBox.Show("Впиши название и выбери файл.", "gnerti Hub");
                    return;
                }
                Result = existing ?? new AppItem();
                Images.Forget(Result.IconPath);
                Result.Name = name.Text.Trim();
                Result.Category = cat.SelectedItem?.ToString() ?? "Игры";
                Result.Description = desc.Text.Trim();
                Result.Path = path.Text.Trim();
                Result.IconPath = icon.Text.Trim();
                DialogResult = DialogResult.OK;
            };
            layout.Controls.Add(ok);
        }

        FlowLayoutPanel Row(TextBox box, string filter, bool fillName)
        {
            var row = new FlowLayoutPanel { AutoSize = true, WrapContents = false, Margin = new Padding(0) };
            var browse = UI.MakeButton("Обзор...", Theme.Surface, Theme.Fg);
            browse.Click += (s, e) =>
            {
                using var ofd = new OpenFileDialog { Filter = filter };
                if (ofd.ShowDialog() == DialogResult.OK)
                {
                    box.Text = ofd.FileName;
                    if (fillName && string.IsNullOrWhiteSpace(name.Text))
                        name.Text = System.IO.Path.GetFileNameWithoutExtension(ofd.FileName);
                }
            };
            row.Controls.Add(box); row.Controls.Add(browse);
            return row;
        }

        Label Field(string text)
        {
            var l = UI.MakeLabel(text, 10, Theme.Muted);
            l.Margin = new Padding(0, 10, 0, 4);
            return l;
        }
    }

    // ===== Ошибка, которую можно показать пользователю =====
    class HubError : Exception { public HubError(string m) : base(m) { } }

    // ===== Облако gnerti (Supabase) =====
    static class Cloud
    {
        static readonly HttpClient http = new() { Timeout = TimeSpan.FromSeconds(15) };

        static readonly Dictionary<string, string> Messages = new()
        {
            ["bad_login"] = "Логин: от 3 до 20 символов, только английские буквы, цифры и _",
            ["bad_nickname"] = "Ник не может быть пустым (до 32 символов)",
            ["weak_password"] = "Пароль: минимум 6 символов, буквы и цифры",
            ["login_taken"] = "Такой логин уже занят",
            ["wrong_login"] = "Неверный логин или пароль",
            ["locked"] = "Слишком много попыток. Подожди минуту",
            ["not_logged_in"] = "Сессия закончилась, войди снова",
            ["wrong_old_password"] = "Старый пароль неверный",
            ["not_admin"] = "Это может только админ",
            ["cannot_self"] = "Это нельзя сделать с самим собой",
            ["empty_title"] = "Впиши заголовок",
        };

        public static async Task<JsonElement> Rpc(HubData d, string fn, object args)
        {
            string url = d.ServerUrl.TrimEnd('/') + "/rest/v1/rpc/" + fn;
            using var req = new HttpRequestMessage(HttpMethod.Post, url);
            req.Headers.Add("apikey", d.ServerKey);
            // Старый anon key — это JWT (начинается с eyJ), его можно передать и в Authorization.
            // Новый Publishable key (sb_publishable_...) передаётся только в apikey.
            if (d.ServerKey.StartsWith("eyJ"))
                req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", d.ServerKey);
            req.Content = new StringContent(JsonSerializer.Serialize(args ?? new { }), Encoding.UTF8, "application/json");

            HttpResponseMessage res;
            try { res = await http.SendAsync(req); }
            catch (Exception) { throw new HubError("Нет связи с сервером gnerti. Проверь интернет."); }

            string body = await res.Content.ReadAsStringAsync();
            JsonElement json;
            try { json = JsonDocument.Parse(string.IsNullOrWhiteSpace(body) ? "null" : body).RootElement.Clone(); }
            catch { throw new HubError("Сервер ответил непонятно (" + (int)res.StatusCode + ")"); }

            if (!res.IsSuccessStatusCode)
            {
                string code = json.ValueKind == JsonValueKind.Object && json.TryGetProperty("message", out var m) ? m.GetString() : "";
                if ((int)res.StatusCode == 401 || (int)res.StatusCode == 403 && code == "")
                    throw new HubError("Сервер не принял ключ. Проверь настройки сервера.");
                if ((int)res.StatusCode == 404)
                    throw new HubError("На сервере нет функций gnerti. Запусти файл supabase.sql в Supabase.");
                throw new HubError(Messages.TryGetValue(code ?? "", out var t) ? t : "Ошибка сервера: " + code);
            }
            if (json.ValueKind == JsonValueKind.Object && json.TryGetProperty("error", out var err))
            {
                string code = err.GetString() ?? "";
                throw new HubError(Messages.TryGetValue(code, out var t) ? t : "Ошибка: " + code);
            }
            return json;
        }

        public static UserAccount ToUser(JsonElement u) => new()
        {
            Login = u.GetProperty("login").GetString(),
            Nickname = u.GetProperty("nickname").GetString(),
            IsAdmin = u.GetProperty("is_admin").GetBoolean(),
            Created = u.GetProperty("created").GetDateTime().ToLocalTime(),
            Favorites = u.GetProperty("favorites").EnumerateArray().Select(x => x.GetString()).ToList(),
            AccentIndex = u.GetProperty("accent").GetInt32(),
            Sort = u.GetProperty("sort").GetString()
        };
    }

    // ===== Аккаунты: работают локально или через облако =====
    static class Accounts
    {
        public static HubData Data;
        public static bool Online => !string.IsNullOrWhiteSpace(Data.ServerUrl) && !string.IsNullOrWhiteSpace(Data.ServerKey);
        static int localFails;
        static DateTime localLockedUntil;

        static void Remember(UserAccount u, string token, bool remember)
        {
            if (Online) { Data.SessionToken = remember ? token : ""; Data.RememberedLogin = ""; }
            else Data.RememberedLogin = remember ? u.Login : "";
            Storage.Save(Data);
        }

        public static async Task<UserAccount> Register(string login, string nick, string pass, bool remember)
        {
            if (Online)
            {
                var r = await Cloud.Rpc(Data, "gn_register", new { p_login = login, p_nickname = nick, p_password = pass });
                var u = Cloud.ToUser(r.GetProperty("user"));
                CurrentToken = r.GetProperty("token").GetString();
                Remember(u, CurrentToken, remember);
                return u;
            }
            var err = Auth.ValidateLogin(login, Data);
            if (err != null) throw new HubError(err);
            var nu = new UserAccount { Login = login, Nickname = nick, IsAdmin = Data.Users.Count == 0 };
            Auth.SetPassword(nu, pass);
            Data.Users.Add(nu);
            Remember(nu, null, remember);
            return nu;
        }

        public static async Task<UserAccount> Login(string login, string pass, bool remember)
        {
            if (Online)
            {
                var r = await Cloud.Rpc(Data, "gn_login", new { p_login = login, p_password = pass });
                var u = Cloud.ToUser(r.GetProperty("user"));
                CurrentToken = r.GetProperty("token").GetString();
                Remember(u, CurrentToken, remember);
                return u;
            }
            if (DateTime.Now < localLockedUntil)
                throw new HubError($"Слишком много попыток. Подожди {(int)(localLockedUntil - DateTime.Now).TotalSeconds + 1} сек.");
            var lu = Auth.Find(Data, login);
            if (lu == null || !Auth.Check(lu, pass))
            {
                if (++localFails >= 5) { localFails = 0; localLockedUntil = DateTime.Now.AddSeconds(30); }
                throw new HubError("Неверный логин или пароль");
            }
            localFails = 0;
            Remember(lu, null, remember);
            return lu;
        }

        public static string CurrentToken;

        // Автовход, если нажали «Запомнить меня»
        public static async Task<UserAccount> Restore()
        {
            if (Online)
            {
                if (string.IsNullOrEmpty(Data.SessionToken)) return null;
                try
                {
                    var r = await Cloud.Rpc(Data, "gn_me", new { p_token = Data.SessionToken });
                    CurrentToken = Data.SessionToken;
                    return Cloud.ToUser(r.GetProperty("user"));
                }
                catch (HubError) { return null; }
            }
            return string.IsNullOrEmpty(Data.RememberedLogin) ? null : Auth.Find(Data, Data.RememberedLogin);
        }

        public static async Task SaveProfile(UserAccount me)
        {
            Storage.Save(Data);
            if (!Online) return;
            await Cloud.Rpc(Data, "gn_update_profile", new
            {
                p_token = CurrentToken,
                p_nickname = me.Nickname,
                p_accent = me.AccentIndex,
                p_sort = me.Sort,
                p_favorites = me.Favorites.ToArray()
            });
        }

        public static async Task ChangePassword(UserAccount me, string oldP, string newP)
        {
            if (Online)
            {
                await Cloud.Rpc(Data, "gn_change_password", new { p_token = CurrentToken, p_old = oldP, p_new = newP });
                return;
            }
            if (!Auth.Check(me, oldP)) throw new HubError("Старый пароль неверный");
            Auth.SetPassword(me, newP);
            Storage.Save(Data);
        }

        public static async Task Logout()
        {
            if (Online && !string.IsNullOrEmpty(CurrentToken))
            {
                try { await Cloud.Rpc(Data, "gn_logout", new { p_token = CurrentToken }); } catch (HubError) { }
            }
            CurrentToken = null;
            Data.SessionToken = "";
            Data.RememberedLogin = "";
            Storage.Save(Data);
        }

        public static async Task<List<NewsPost>> News()
        {
            if (!Online) return Data.News.OrderByDescending(n => n.Date).ToList();
            var r = await Cloud.Rpc(Data, "gn_news_list", new { p_token = CurrentToken });
            return r.EnumerateArray().Select(n => new NewsPost
            {
                Id = n.GetProperty("id").GetString(),
                Title = n.GetProperty("title").GetString(),
                Text = n.GetProperty("text").GetString(),
                Author = n.GetProperty("author").GetString(),
                Date = n.GetProperty("date").GetDateTime().ToLocalTime()
            }).ToList();
        }

        public static async Task AddNews(UserAccount me, string title, string text)
        {
            if (Online) { await Cloud.Rpc(Data, "gn_news_add", new { p_token = CurrentToken, p_title = title, p_text = text }); return; }
            Data.News.Add(new NewsPost { Title = title, Text = text, Author = me.Nickname });
            Storage.Save(Data);
        }

        public static async Task DeleteNews(string id)
        {
            if (Online) { await Cloud.Rpc(Data, "gn_news_delete", new { p_token = CurrentToken, p_id = id }); return; }
            Data.News.RemoveAll(n => n.Id == id);
            Storage.Save(Data);
        }

        public static async Task<List<UserAccount>> Users()
        {
            if (!Online) return Data.Users.ToList();
            var r = await Cloud.Rpc(Data, "gn_users_list", new { p_token = CurrentToken });
            return r.GetProperty("users").EnumerateArray().Select(Cloud.ToUser).ToList();
        }

        public static async Task SetAdmin(string login, bool value)
        {
            if (Online) { await Cloud.Rpc(Data, "gn_set_admin", new { p_token = CurrentToken, p_login = login, p_value = value }); return; }
            var u = Auth.Find(Data, login);
            if (u != null) { u.IsAdmin = value; Storage.Save(Data); }
        }

        public static async Task DeleteUser(string login)
        {
            if (Online) { await Cloud.Rpc(Data, "gn_delete_user", new { p_token = CurrentToken, p_login = login }); return; }
            Data.Users.RemoveAll(u => u.Login.Equals(login, StringComparison.OrdinalIgnoreCase));
            if (Data.RememberedLogin.Equals(login, StringComparison.OrdinalIgnoreCase)) Data.RememberedLogin = "";
            Storage.Save(Data);
        }
    }

    // ===== Настройки сервера =====
    class ServerDialog : Form
    {
        readonly HubData data;
        readonly TextBox url = UI.MakeBox(420);
        readonly TextBox key = UI.MakeBox(420);
        readonly Label status = UI.MakeLabel("", 9.5f, Theme.Muted);

        public ServerDialog(HubData data)
        {
            this.data = data;
            Text = "Сервер gnerti";
            Icon = Theme.AppIcon;
            BackColor = Theme.Bg;
            ForeColor = Theme.Fg;
            Font = Theme.Font(10);
            FormBorderStyle = FormBorderStyle.FixedDialog;
            MaximizeBox = false; MinimizeBox = false;
            StartPosition = FormStartPosition.CenterParent;
            ClientSize = new Size(470, 420);

            var layout = new FlowLayoutPanel { Dock = DockStyle.Fill, Padding = new Padding(22), FlowDirection = FlowDirection.TopDown, WrapContents = false };
            Controls.Add(layout);

            layout.Controls.Add(UI.MakeLabel("☁ Онлайн-аккаунты", 14, Theme.Fg, FontStyle.Bold));
            var info = UI.MakeLabel("Впиши данные из Supabase: Project Settings → API. Если поля пустые, аккаунты хранятся только на этом компьютере.", 9.5f, Theme.Muted);
            info.MaximumSize = new Size(420, 0);
            layout.Controls.Add(info);

            layout.Controls.Add(Field("Project URL (https://....supabase.co)"));
            url.Text = data.ServerUrl;
            layout.Controls.Add(url);
            layout.Controls.Add(Field("Publishable key или anon public key"));
            key.Text = data.ServerKey;
            key.Font = Theme.Font(9);
            layout.Controls.Add(key);

            status.MaximumSize = new Size(420, 0);
            status.Margin = new Padding(0, 10, 0, 0);
            layout.Controls.Add(status);

            var row = new FlowLayoutPanel { AutoSize = true, Margin = new Padding(0, 14, 0, 0) };
            var test = UI.MakeButton("Проверить", Theme.Surface, Theme.Fg);
            var save = UI.MakeButton("Сохранить", Theme.Accent, Color.White);
            var local = UI.MakeButton("Только этот компьютер", Theme.SurfaceHover, Theme.Muted);
            row.Controls.Add(save); row.Controls.Add(test); row.Controls.Add(local);
            layout.Controls.Add(row);

            test.Click += async (s, e) => await Test();
            save.Click += async (s, e) =>
            {
                if (!await Test()) return;
                data.ServerUrl = url.Text.Trim().TrimEnd('/');
                data.ServerKey = key.Text.Trim();
                data.LocalOnly = false;
                data.SessionToken = "";
                Storage.Save(data);
                DialogResult = DialogResult.OK;
            };
            local.Click += (s, e) =>
            {
                data.ServerUrl = ""; data.ServerKey = ""; data.SessionToken = "";
                data.LocalOnly = true;
                Storage.Save(data);
                DialogResult = DialogResult.OK;
            };
        }

        async Task<bool> Test()
        {
            var u = url.Text.Trim();
            if (!u.StartsWith("https://") || key.Text.Trim().Length < 20)
            {
                status.ForeColor = Theme.Danger;
                status.Text = "Проверь адрес (начинается с https://) и ключ.";
                return false;
            }
            status.ForeColor = Theme.Muted; status.Text = "Проверяю...";
            var tmp = new HubData { ServerUrl = u, ServerKey = key.Text.Trim() };
            try
            {
                var r = await Cloud.Rpc(tmp, "gn_ping", null);
                if (r.ValueKind == JsonValueKind.String && r.GetString() == "gnerti")
                {
                    status.ForeColor = Theme.Good; status.Text = "✓ Сервер gnerti работает";
                    return true;
                }
                throw new HubError("Сервер ответил, но это не gnerti.");
            }
            catch (HubError ex)
            {
                status.ForeColor = Theme.Danger; status.Text = ex.Message;
                return false;
            }
        }

        static Label Field(string t)
        {
            var l = UI.MakeLabel(t, 10, Theme.Muted);
            l.Margin = new Padding(0, 14, 0, 4);
            return l;
        }
    }

    // ===== Заставка при запуске =====
    class SplashForm : Form
    {
        readonly System.Windows.Forms.Timer timer = new() { Interval = 16 };
        float angle, progress;

        public SplashForm()
        {
            FormBorderStyle = FormBorderStyle.None;
            StartPosition = FormStartPosition.CenterScreen;
            ClientSize = new Size(420, 280);
            BackColor = Theme.Bg;
            DoubleBuffered = true;
            ShowInTaskbar = false;
            TopMost = true;
            timer.Tick += (s, e) =>
            {
                angle = (angle + 6) % 360;
                progress += 1f / 80f;
                Invalidate();
                if (progress >= 1f) { timer.Stop(); Close(); }
            };
            Shown += (s, e) => timer.Start();
        }

        protected override void OnPaint(PaintEventArgs e)
        {
            var g = e.Graphics;
            g.SmoothingMode = SmoothingMode.AntiAlias;
            using (var border = new Pen(Theme.Line)) g.DrawRectangle(border, 0, 0, Width - 1, Height - 1);

            float cx = Width / 2f, cy = 110, r = 46;
            using (var p = new Pen(Theme.Accent, 16))
                g.DrawArc(p, cx - r, cy - r, r * 2, r * 2, 30 + angle, 290);
            using (var b = new SolidBrush(Theme.Signal))
                g.FillRectangle(b, cx + 14, cy - 13, 26, 26);

            using var f = Theme.Font(22, FontStyle.Bold);
            TextRenderer.DrawText(g, "gnerti Hub", f, new Rectangle(0, 175, Width, 40), Theme.Fg, TextFormatFlags.HorizontalCenter);
            using var f2 = Theme.Font(9.5f);
            TextRenderer.DrawText(g, "Игры · Программы · Гаджеты · ИИ", f2, new Rectangle(0, 212, Width, 24), Theme.Muted, TextFormatFlags.HorizontalCenter);

            using var track = new SolidBrush(Theme.Surface);
            using var bar = new SolidBrush(Theme.Accent);
            g.FillRectangle(track, 60, 250, Width - 120, 4);
            g.FillRectangle(bar, 60, 250, (Width - 120) * Math.Min(1f, progress), 4);
        }
    }

    // ===== Импорт игр и программ с рабочего стола (только админ) =====
    class ImportDialog : Form
    {
        public readonly List<AppItem> Selected = new();
        readonly CheckedListBox list = new();
        readonly ComboBox cat = new();
        readonly List<string> paths = new();

        public ImportDialog(HubData data)
        {
            Text = "Импорт с рабочего стола";
            Icon = Theme.AppIcon;
            BackColor = Theme.Bg;
            ForeColor = Theme.Fg;
            Font = Theme.Font(10);
            FormBorderStyle = FormBorderStyle.FixedDialog;
            MaximizeBox = false; MinimizeBox = false;
            StartPosition = FormStartPosition.CenterParent;
            ClientSize = new Size(460, 520);

            var layout = new FlowLayoutPanel { Dock = DockStyle.Fill, Padding = new Padding(20), FlowDirection = FlowDirection.TopDown, WrapContents = false };
            Controls.Add(layout);

            layout.Controls.Add(UI.MakeLabel("Ярлыки на рабочем столе", 13, Theme.Fg, FontStyle.Bold));
            layout.Controls.Add(UI.MakeLabel("Отметь, что добавить в gnerti Hub.", 10, Theme.Muted));

            list.Size = new Size(420, 330);
            list.BackColor = Theme.Surface;
            list.ForeColor = Theme.Fg;
            list.BorderStyle = BorderStyle.None;
            list.CheckOnClick = true;
            list.Margin = new Padding(0, 10, 0, 10);
            layout.Controls.Add(list);

            var known = new HashSet<string>(data.Apps.Select(a => a.Path), StringComparer.OrdinalIgnoreCase);
            var dirs = new[]
            {
                Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory),
                Environment.GetFolderPath(Environment.SpecialFolder.CommonDesktopDirectory)
            };
            foreach (var dir in dirs.Where(Directory.Exists).Distinct())
            {
                try
                {
                    foreach (var f in Directory.GetFiles(dir))
                    {
                        string ext = System.IO.Path.GetExtension(f).ToLowerInvariant();
                        if (ext is not (".lnk" or ".url" or ".exe")) continue;
                        if (known.Contains(f)) continue;
                        paths.Add(f);
                        list.Items.Add(System.IO.Path.GetFileNameWithoutExtension(f));
                    }
                }
                catch { }
            }
            if (paths.Count == 0) list.Items.Add("(новых ярлыков не найдено)");

            var row = new FlowLayoutPanel { AutoSize = true, WrapContents = false };
            row.Controls.Add(UI.MakeLabel("Раздел:", 10, Theme.Muted));
            cat.DropDownStyle = ComboBoxStyle.DropDownList;
            cat.Items.AddRange(new object[] { "Игры", "Программы", "Гаджеты", "ИИ" });
            cat.SelectedIndex = 0;
            cat.BackColor = Theme.Surface; cat.ForeColor = Theme.Fg; cat.FlatStyle = FlatStyle.Flat;
            row.Controls.Add(cat);
            layout.Controls.Add(row);

            var ok = UI.MakeButton("Добавить отмеченные", Theme.Accent, Color.White);
            ok.Margin = new Padding(0, 14, 0, 0);
            ok.Click += (s, e) =>
            {
                foreach (int i in list.CheckedIndices)
                {
                    if (i >= paths.Count) continue;
                    Selected.Add(new AppItem
                    {
                        Name = list.Items[i].ToString(),
                        Path = paths[i],
                        Category = cat.SelectedItem?.ToString() ?? "Игры"
                    });
                }
                DialogResult = DialogResult.OK;
            };
            layout.Controls.Add(ok);
        }
    }

    // ===== Главное окно =====
    class MainForm : Form
    {
        readonly HubData data;
        readonly UserAccount me;
        public bool LoggedOut;

        readonly Panel content = new() { Dock = DockStyle.Fill, BackColor = Theme.Bg, AutoScroll = true };
        readonly TextBox search = new();
        readonly Label toast = new();
        readonly System.Windows.Forms.Timer toastTimer = new() { Interval = 2600 };
        readonly List<NavButton> navs = new();
        string page = "Главная";
        AppItem selected;
        string backPage = "Главная";
        List<NewsPost> news = new();
        List<UserAccount> users = new();

        async void RefreshNews()
        {
            try
            {
                news = await Accounts.News();
                if (!IsDisposed && page == "Главная") ShowPage(page);
            }
            catch (HubError ex) { if (!IsDisposed) Toast(ex.Message, Theme.Danger); }
        }

        async void RefreshUsers()
        {
            if (!me.IsAdmin) return;
            try
            {
                users = await Accounts.Users();
                if (!IsDisposed && page == "Админ") ShowPage(page);
            }
            catch (HubError ex) { if (!IsDisposed) Toast(ex.Message, Theme.Danger); }
        }

        // Сохраняем ник, цвет, сортировку и избранное (в облако, если оно включено)
        async void SaveMe()
        {
            try { await Accounts.SaveProfile(me); }
            catch (HubError ex) { if (!IsDisposed) Toast(ex.Message, Theme.Danger); }
        }

        static readonly (string Name, string Icon)[] AllPages =
        {
            ("Главная", "⌂"), ("Избранное", "★"), ("Игры", "🎮"), ("Программы", "▣"),
            ("Гаджеты", "⚙"), ("ИИ", "✦"), ("Аккаунт", "◉"), ("Админ", "⛨")
        };
        static readonly string[] Categories = { "Игры", "Программы", "Гаджеты", "ИИ" };

        public MainForm(HubData data, UserAccount me)
        {
            this.data = data;
            this.me = me;
            Text = "gnerti Hub — " + me.Nickname;
            BackColor = Theme.Bg;
            ForeColor = Theme.Fg;
            Font = Theme.Font(10);
            ClientSize = new Size(1180, 740);
            MinimumSize = new Size(880, 560);
            StartPosition = FormStartPosition.CenterScreen;
            DoubleBuffered = true;
            Icon = Theme.AppIcon;

            // Восстанавливаем размер и положение окна
            if (data.Window is { Length: 4 })
            {
                var r = new Rectangle(data.Window[0], data.Window[1], data.Window[2], data.Window[3]);
                if (Screen.AllScreens.Any(sc => sc.WorkingArea.IntersectsWith(r)))
                {
                    StartPosition = FormStartPosition.Manual;
                    Bounds = r;
                }
            }
            if (data.Maximized) WindowState = FormWindowState.Maximized;
            FormClosing += (s, e) =>
            {
                var b = WindowState == FormWindowState.Normal ? Bounds : RestoreBounds;
                data.Window = new[] { b.X, b.Y, b.Width, b.Height };
                data.Maximized = WindowState == FormWindowState.Maximized;
                Storage.Save(data);
            };

            // Уведомление внизу справа
            toast.AutoSize = true;
            toast.Padding = new Padding(16, 10, 16, 10);
            toast.BackColor = Theme.Accent;
            toast.ForeColor = Color.White;
            toast.Font = Theme.Font(10.5f, FontStyle.Bold);
            toast.Visible = false;
            toastTimer.Tick += (s, e) => { toast.Visible = false; toastTimer.Stop(); };

            Controls.Add(toast);
            Controls.Add(content);
            Controls.Add(BuildTopBar());
            Controls.Add(BuildSidebar());
            toast.BringToFront();

            ShowPage("Главная");
            RefreshNews();
            RefreshUsers();
        }

        public void Toast(string text, Color? color = null)
        {
            toast.Text = text;
            toast.BackColor = color ?? Theme.Accent;
            toast.Visible = true;
            toast.Location = new Point(ClientSize.Width - toast.PreferredWidth - 24, ClientSize.Height - toast.PreferredHeight - 24);
            toast.BringToFront();
            toastTimer.Stop(); toastTimer.Start();
        }

        Panel BuildTopBar()
        {
            var bar = new Panel { Dock = DockStyle.Top, Height = 64, BackColor = Theme.Bg, Padding = new Padding(36, 16, 36, 0) };
            var icon = UI.MakeLabel("🔍", 12, Theme.Muted);
            icon.Location = new Point(36, 20);
            search.Location = new Point(66, 18);
            search.Width = 380;
            search.BackColor = Theme.Surface;
            search.ForeColor = Theme.Fg;
            search.BorderStyle = BorderStyle.FixedSingle;
            search.Font = Theme.Font(12);
            search.PlaceholderText = "Поиск игр и программ...";
            search.TextChanged += (s, e) =>
            {
                // Поиск работает по разделам; с главной и аккаунта переходим к результатам
                bool empty = search.Text.Trim().Length == 0;
                if (empty) ShowPage(page == "Поиск" ? "Главная" : page);
                else if (page is "Главная" or "Аккаунт" or "Админ" or "Поиск" or "Продукт") ShowPage("Поиск");
                else ShowPage(page);
            };
            bar.Controls.Add(icon); bar.Controls.Add(search);
            return bar;
        }

        Panel BuildSidebar()
        {
            var side = new Panel { Dock = DockStyle.Left, Width = 230, BackColor = Theme.Side };

            var navHolder = new Panel { Dock = DockStyle.Fill, BackColor = Theme.Side, Padding = new Padding(0, 10, 0, 0) };
            var pages = AllPages.Where(p => p.Name != "Админ" || me.IsAdmin).ToArray();
            for (int i = pages.Length - 1; i >= 0; i--)
            {
                var (p, ic) = pages[i];
                var b = new NavButton(p, ic);
                if (p == "Админ") b.ForeColor = Theme.Signal;
                b.Click += (s, e) => { search.Text = ""; ShowPage(p); if (p == "Админ") RefreshUsers(); if (p == "Главная") RefreshNews(); };
                navs.Add(b);
                navHolder.Controls.Add(b);
            }
            side.Controls.Add(navHolder);

            var top = new Panel { Dock = DockStyle.Top, Height = 80, BackColor = Theme.Side };
            var logo = new LogoBox { Location = new Point(20, 22) };
            var title = UI.MakeLabel("gnerti", 18, Theme.Fg, FontStyle.Bold);
            title.Location = new Point(68, 22);
            top.Controls.Add(logo); top.Controls.Add(title);
            side.Controls.Add(top);

            var who = UI.MakeLabel((me.IsAdmin ? "★ " : "") + me.Nickname + (me.IsAdmin ? " · админ" : ""), 9.5f,
                me.IsAdmin ? Theme.Signal : Theme.Muted);
            who.Dock = DockStyle.Bottom;
            who.AutoSize = false; who.Height = 40;
            who.Padding = new Padding(20, 0, 0, 0);
            who.TextAlign = ContentAlignment.MiddleLeft;
            side.Controls.Add(who);

            return side;
        }

        IEnumerable<AppItem> Filtered(IEnumerable<AppItem> items)
        {
            string q = search.Text.Trim();
            if (q.Length == 0) return items;
            return items.Where(a => a.Name.Contains(q, StringComparison.OrdinalIgnoreCase)
                                 || a.Description.Contains(q, StringComparison.OrdinalIgnoreCase));
        }

        void ShowPage(string p)
        {
            page = p;
            foreach (var n in navs) { n.Active = n.Page == p; n.Invalidate(); }

            int scroll = -content.AutoScrollPosition.Y;
            content.SuspendLayout();
            content.Controls.Clear();

            var stack = new FlowLayoutPanel
            {
                FlowDirection = FlowDirection.TopDown,
                WrapContents = false,
                AutoSize = true,
                Padding = new Padding(36, 6, 36, 30),
                BackColor = Theme.Bg
            };
            content.Controls.Add(stack);

            switch (p)
            {
                case "Главная": BuildHome(stack); break;
                case "Избранное": BuildFavorites(stack); break;
                case "Поиск": BuildSearch(stack); break;
                case "Аккаунт": BuildAccount(stack); break;
                case "Админ" when me.IsAdmin: BuildAdmin(stack); break;
                case "Продукт" when selected != null && data.Apps.Contains(selected): BuildProduct(stack); break;
                case "Продукт": page = "Главная"; BuildHome(stack); break;
                default: BuildCategory(stack, p); break;
            }

            content.ResumeLayout();
            content.AutoScrollPosition = new Point(0, scroll);
        }

        // ---- Главная ----
        void BuildHome(FlowLayoutPanel stack)
        {
            int h = DateTime.Now.Hour;
            string hello = h < 6 ? "Доброй ночи" : h < 12 ? "Доброе утро" : h < 18 ? "Добрый день" : "Добрый вечер";

            stack.Controls.Add(UI.MakeLabel("ТЕХНОЛОГИЧЕСКАЯ КОМПАНИЯ GNERTI", 9, Theme.Muted, FontStyle.Bold));
            stack.Controls.Add(UI.MakeLabel($"{hello}, {me.Nickname}!", 26, Theme.Fg, FontStyle.Bold));
            stack.Controls.Add(UI.MakeLabel("Все игры и программы gnerti в одном месте.", 12, Theme.Muted));

            var stats = new FlowLayoutPanel { AutoSize = true, Margin = new Padding(0, 24, 0, 8) };
            foreach (var c in Categories)
            {
                int count = data.Apps.Count(a => a.Category == c);
                var tile = new Panel { Size = new Size(170, 90), BackColor = Theme.Surface, Margin = new Padding(0, 0, 12, 12), Cursor = Cursors.Hand };
                var num = UI.MakeLabel(count.ToString(), 24, Theme.Accent, FontStyle.Bold);
                num.Location = new Point(16, 10);
                var lbl = UI.MakeLabel(c, 11, Theme.Fg);
                lbl.Location = new Point(18, 54);
                tile.Controls.Add(num); tile.Controls.Add(lbl);
                string cc = c;
                foreach (Control ctl in new Control[] { tile, num, lbl })
                    ctl.Click += (s, e) => ShowPage(cc);
                stats.Controls.Add(tile);
            }
            stack.Controls.Add(stats);

            // Продолжить: последний запущенный продукт
            var last = data.Apps.Where(a => a.LastLaunched != null).OrderByDescending(a => a.LastLaunched).FirstOrDefault();
            if (last != null)
            {
                stack.Controls.Add(Section("Продолжить"));
                stack.Controls.Add(BuildContinue(last));
            }

            stack.Controls.Add(Section("Популярное"));
            var popular = data.Apps.OrderByDescending(a => a.Launches).Take(6).ToList();
            if (popular.Count == 0)
                stack.Controls.Add(UI.MakeLabel(me.IsAdmin
                    ? "Пока пусто. Открой раздел слева и нажми «+ Добавить»."
                    : "Пока пусто. Скоро администратор добавит игры и программы.", 11, Theme.Muted));
            else
                stack.Controls.Add(BuildGrid(popular));

            // Новости компании
            stack.Controls.Add(Section("Новости gnerti"));
            if (news.Count == 0)
                stack.Controls.Add(UI.MakeLabel(me.IsAdmin ? "Новостей пока нет. Напиши первую в разделе «Админ»." : "Новостей пока нет.", 11, Theme.Muted));
            foreach (var n in news.Take(5))
                stack.Controls.Add(BuildNews(n));
        }

        Panel BuildContinue(AppItem a)
        {
            var row = new Panel { Size = new Size(620, 84), BackColor = Theme.Surface, Margin = new Padding(0, 0, 0, 8) };
            var ic = new ProductIcon(a, 56) { Location = new Point(14, 14) };
            var nm = UI.MakeLabel(a.Name, 13, Theme.Fg, FontStyle.Bold);
            nm.Location = new Point(84, 14);
            var sub = UI.MakeLabel($"Запускали {Fmt.Ago(a.LastLaunched)} · в игре {Fmt.Time(a.MinutesPlayed)}", 9.5f, Theme.Muted);
            sub.Location = new Point(86, 44);
            var play = UI.MakeButton("▶ Играть", Theme.Signal, Color.White);
            play.Location = new Point(500, 24);
            play.Click += (s, e) => Launch(a);
            row.Controls.AddRange(new Control[] { ic, nm, sub, play });
            return row;
        }

        Panel BuildNews(NewsPost n)
        {
            var box = new Panel { Width = 620, BackColor = Theme.Surface, Margin = new Padding(0, 0, 0, 10), Padding = new Padding(16, 12, 16, 12) };
            var title = UI.MakeLabel(n.Title, 12, Theme.Fg, FontStyle.Bold);
            title.Location = new Point(16, 12);
            var meta = UI.MakeLabel($"{n.Author} · {n.Date:dd.MM.yyyy HH:mm}", 9, Theme.Signal);
            meta.Location = new Point(16, 36);
            var text = UI.MakeLabel(n.Text, 10.5f, Theme.Muted);
            text.MaximumSize = new Size(580, 0);
            text.Location = new Point(16, 58);
            box.Controls.AddRange(new Control[] { title, meta, text });

            if (me.IsAdmin)
            {
                var del = UI.MakeButton("✕", Theme.SurfaceHover, Theme.Muted);
                del.Location = new Point(570, 10);
                del.Click += async (s, e) =>
                {
                    try
                    {
                        await Accounts.DeleteNews(n.Id);
                        news.Remove(n);
                        ShowPage(page);
                        Toast("Новость удалена", Theme.Danger);
                    }
                    catch (HubError ex) { Toast(ex.Message, Theme.Danger); }
                };
                box.Controls.Add(del);
            }
            box.Height = 58 + text.PreferredHeight + 14;
            return box;
        }

        // ---- Избранное ----
        void BuildFavorites(FlowLayoutPanel stack)
        {
            stack.Controls.Add(UI.MakeLabel("ТВОЯ ПОДБОРКА", 9, Theme.Gold, FontStyle.Bold));
            var t = UI.MakeLabel("Избранное", 24, Theme.Fg, FontStyle.Bold);
            t.Margin = new Padding(0, 0, 0, 18);
            stack.Controls.Add(t);
            stack.Controls.Add(SortBox());
            var items = Sorted(Filtered(data.Apps.Where(a => me.Favorites.Contains(a.Id)))).ToList();
            if (items.Count == 0)
                stack.Controls.Add(UI.MakeLabel("Нажми ☆ на карточке игры или программы, и она появится здесь.", 11, Theme.Muted));
            else
                stack.Controls.Add(BuildGrid(items));
        }

        // ---- Результаты поиска ----
        void BuildSearch(FlowLayoutPanel stack)
        {
            var items = Filtered(data.Apps).ToList();
            var t = UI.MakeLabel($"Поиск: «{search.Text.Trim()}»", 22, Theme.Fg, FontStyle.Bold);
            t.Margin = new Padding(0, 0, 0, 18);
            stack.Controls.Add(t);
            if (items.Count == 0)
                stack.Controls.Add(UI.MakeLabel("Ничего не найдено.", 11, Theme.Muted));
            else
                stack.Controls.Add(BuildGrid(items));
        }

        // ---- Раздел (Игры, Программы, Гаджеты, ИИ) ----
        void BuildCategory(FlowLayoutPanel stack, string category)
        {
            string code = category switch
            {
                "Игры" => "G/01 · GAMES",
                "Программы" => "G/02 · SOFT",
                "Гаджеты" => "G/03 · DEVICES",
                _ => "G/04 · AI"
            };
            stack.Controls.Add(UI.MakeLabel(code, 9, Theme.Signal, FontStyle.Bold));
            var title = UI.MakeLabel("gnerti " + category, 24, Theme.Fg, FontStyle.Bold);
            title.Margin = new Padding(0, 0, 0, 18);
            stack.Controls.Add(title);

            if (me.IsAdmin)
            {
                var add = UI.MakeButton("+ Добавить", Theme.Accent, Color.White);
                add.Margin = new Padding(0, 0, 0, 18);
                add.Click += (s, e) => OpenProductDialog(null, category);
                stack.Controls.Add(add);
            }

            stack.Controls.Add(SortBox());
            var items = Sorted(Filtered(data.Apps.Where(a => a.Category == category))).ToList();
            if (items.Count == 0)
                stack.Controls.Add(UI.MakeLabel(search.Text.Trim().Length > 0 ? "Ничего не найдено."
                    : me.IsAdmin ? "Здесь пока ничего нет. Нажми «+ Добавить» и выбери .exe файл."
                    : "Здесь пока ничего нет. Скоро появится.", 11, Theme.Muted));
            else
                stack.Controls.Add(BuildGrid(items));
        }

        void OpenProductDialog(AppItem existing, string category)
        {
            if (!me.IsAdmin) return;
            using var d = new ProductDialog(existing, category);
            if (d.ShowDialog(this) == DialogResult.OK && d.Result != null)
            {
                if (existing == null) data.Apps.Add(d.Result);
                Storage.Save(data);
                ShowPage(existing == null ? d.Result.Category : page);
                Toast(existing == null ? $"«{d.Result.Name}» добавлен" : "Сохранено", Theme.Good);
            }
        }

        FlowLayoutPanel BuildGrid(List<AppItem> items)
        {
            var grid = new FlowLayoutPanel
            {
                AutoSize = true,
                MaximumSize = new Size(Math.Max(400, content.ClientSize.Width - 90), 0),
                WrapContents = true
            };
            foreach (var a in items) grid.Controls.Add(BuildCard(a));
            return grid;
        }

        Panel BuildCard(AppItem a)
        {
            var card = new Panel { Size = new Size(260, 200), BackColor = Theme.Surface, Margin = new Padding(0, 0, 14, 14) };

            var icon = new ProductIcon(a, 52) { Location = new Point(16, 16) };
            var name = new Label
            {
                Text = a.Name,
                Font = Theme.Font(11.5f, FontStyle.Bold),
                ForeColor = Theme.Fg,
                AutoEllipsis = true,
                Size = new Size(140, 24),
                Location = new Point(78, 18)
            };
            var info = UI.MakeLabel($"{a.Category} · {a.Launches} запусков", 9, Theme.Muted);
            info.Location = new Point(78, 44);

            // Избранное
            bool fav = me.Favorites.Contains(a.Id);
            var star = UI.MakeButton(fav ? "★" : "☆", Theme.Surface, fav ? Theme.Gold : Theme.Muted);
            star.Font = Theme.Font(13);
            star.Padding = new Padding(0);
            star.AutoSize = false; star.Size = new Size(32, 32);
            star.Location = new Point(222, 12);
            star.Click += (s, e) =>
            {
                if (me.Favorites.Contains(a.Id)) { me.Favorites.Remove(a.Id); Toast("Убрано из избранного"); }
                else { me.Favorites.Add(a.Id); Toast("Добавлено в избранное ★", Theme.Gold); }
                SaveMe();
                ShowPage(page);
            };

            foreach (Control c in new Control[] { icon, name })
            {
                c.Cursor = Cursors.Hand;
                c.Click += (s, e) => OpenProduct(a);
            }
            var desc = new Label
            {
                Text = string.IsNullOrWhiteSpace(a.Description) ? "Без описания" : a.Description,
                Font = Theme.Font(9.5f),
                ForeColor = Theme.Muted,
                AutoEllipsis = true,
                Size = new Size(228, 54),
                Location = new Point(16, 80),
                Cursor = Cursors.Hand
            };
            desc.Click += (s, e) => OpenProduct(a);

            var played = UI.MakeLabel(a.MinutesPlayed >= 1 ? "⏱ " + Fmt.Time(a.MinutesPlayed) : "", 9, Theme.Muted);
            played.Location = new Point(150, 160);

            var play = UI.MakeButton("▶ Запустить", a.Category == "Игры" ? Theme.Signal : Theme.Accent, Color.White);
            play.Location = new Point(16, 152);
            play.Click += (s, e) => Launch(a);

            card.Controls.AddRange(new Control[] { icon, name, info, star, desc, played, play });

            if (me.IsAdmin)
            {
                played.Visible = false;
                var edit = UI.MakeButton("✎", Theme.SurfaceHover, Theme.Fg);
                edit.Location = new Point(158, 152);
                edit.Click += (s, e) => OpenProductDialog(a, a.Category);

                var del = UI.MakeButton("✕", Theme.SurfaceHover, Theme.Muted);
                del.Location = new Point(204, 152);
                del.Click += (s, e) =>
                {
                    if (MessageBox.Show($"Убрать «{a.Name}» из gnerti Hub?\nСам файл не удалится.", "gnerti Hub",
                            MessageBoxButtons.YesNo) == DialogResult.Yes)
                    {
                        data.Apps.Remove(a);
                        foreach (var u in data.Users) u.Favorites.Remove(a.Id);
                        if (me.Favorites.Remove(a.Id)) SaveMe();
                        Storage.Save(data);
                        ShowPage(page);
                        Toast($"«{a.Name}» удалён", Theme.Danger);
                    }
                };
                card.Controls.Add(edit); card.Controls.Add(del);
            }

            card.MouseEnter += (s, e) => card.BackColor = Theme.SurfaceHover;
            card.MouseLeave += (s, e) =>
            {
                if (!card.ClientRectangle.Contains(card.PointToClient(Cursor.Position)))
                    card.BackColor = Theme.Surface;
            };
            return card;
        }

        void Launch(AppItem a)
        {
            try
            {
                bool isUrl = a.Path.StartsWith("http", StringComparison.OrdinalIgnoreCase);
                if (!isUrl && !File.Exists(a.Path))
                {
                    Toast("Файл не найден: " + System.IO.Path.GetFileName(a.Path), Theme.Danger);
                    return;
                }
                var psi = new ProcessStartInfo(a.Path) { UseShellExecute = true };
                if (!isUrl) psi.WorkingDirectory = System.IO.Path.GetDirectoryName(a.Path);

                var proc = Process.Start(psi);
                a.Launches++;
                a.LastLaunched = DateTime.Now;
                Storage.Save(data);
                Toast($"Запускаю «{a.Name}»...");

                // Считаем время в программе, когда она закроется
                if (proc != null)
                {
                    var started = DateTime.Now;
                    try
                    {
                        proc.EnableRaisingEvents = true;
                        proc.Exited += (s, e) =>
                        {
                            double mins = (DateTime.Now - started).TotalMinutes;
                            if (IsDisposed) return;
                            BeginInvoke(() =>
                            {
                                a.MinutesPlayed += mins;
                                Storage.Save(data);
                                ShowPage(page);
                                Toast($"«{a.Name}» закрыт · {Fmt.Time(mins)}");
                            });
                        };
                    }
                    catch { }
                }
                ShowPage(page);
            }
            catch (Exception ex)
            {
                Toast("Не удалось запустить: " + ex.Message, Theme.Danger);
            }
        }

        // ---- Аккаунт ----
        void BuildAccount(FlowLayoutPanel stack)
        {
            stack.Controls.Add(UI.MakeLabel("АККАУНТ GNERTI", 9, Theme.Muted, FontStyle.Bold));
            stack.Controls.Add(UI.MakeLabel(me.Nickname, 24, Theme.Fg, FontStyle.Bold));
            stack.Controls.Add(UI.MakeLabel($"Логин: {me.Login} · {(me.IsAdmin ? "администратор" : "игрок")} · с {me.Created:dd.MM.yyyy}",
                10.5f, me.IsAdmin ? Theme.Signal : Theme.Muted));
            stack.Controls.Add(UI.MakeLabel($"В избранном: {me.Favorites.Count}", 10.5f, Theme.Muted));
            stack.Controls.Add(UI.MakeLabel(Accounts.Online ? "☁ Онлайн-аккаунт: можно входить с любого компьютера" : "Аккаунт хранится на этом компьютере",
                10.5f, Accounts.Online ? Theme.Good : Theme.Muted));

            stack.Controls.Add(Section("Ник"));
            var nick = UI.MakeBox(300); nick.Text = me.Nickname;
            stack.Controls.Add(nick);
            var saveNick = UI.MakeButton("Сохранить ник", Theme.Accent, Color.White);
            saveNick.Margin = new Padding(0, 10, 0, 0);
            saveNick.Click += (s, e) =>
            {
                if (string.IsNullOrWhiteSpace(nick.Text)) return;
                me.Nickname = nick.Text.Trim();
                SaveMe();
                Text = "gnerti Hub — " + me.Nickname;
                ShowPage("Аккаунт");
                Toast("Ник сохранён", Theme.Good);
            };
            stack.Controls.Add(saveNick);

            stack.Controls.Add(Section("Цвет оформления"));
            var colors = new FlowLayoutPanel { AutoSize = true };
            for (int i = 0; i < Theme.Accents.Length; i++)
            {
                int idx = i;
                var (cn, cc) = Theme.Accents[i];
                var sw = UI.MakeButton(me.AccentIndex == i ? "✓ " + cn : cn, cc, Color.White);
                sw.Margin = new Padding(0, 0, 8, 8);
                sw.Click += (s, e) =>
                {
                    me.AccentIndex = idx;
                    Theme.UseAccent(idx);
                    SaveMe();
                    foreach (var n in navs) n.Invalidate();
                    Controls.OfType<Panel>().ToList().ForEach(p => p.Refresh());
                    ShowPage("Аккаунт");
                    Toast("Цвет изменён");
                };
                colors.Controls.Add(sw);
            }
            stack.Controls.Add(colors);

            stack.Controls.Add(Section("Сменить пароль"));
            var oldP = UI.MakeBox(300, true); oldP.PlaceholderText = "Старый пароль";
            var newP = UI.MakeBox(300, true); newP.PlaceholderText = "Новый пароль";
            var repP = UI.MakeBox(300, true); repP.PlaceholderText = "Повтори новый пароль";
            newP.Margin = repP.Margin = new Padding(0, 8, 0, 0);
            stack.Controls.Add(oldP); stack.Controls.Add(newP); stack.Controls.Add(repP);
            var msg = UI.MakeLabel("", 9.5f, Theme.Danger);
            stack.Controls.Add(msg);
            var savePass = UI.MakeButton("Сменить пароль", Theme.Surface, Theme.Fg);
            savePass.Margin = new Padding(0, 8, 0, 0);
            savePass.Click += async (s, e) =>
            {
                var err = Auth.ValidatePassword(newP.Text, repP.Text);
                if (err != null) { msg.Text = err; return; }
                savePass.Enabled = false;
                try
                {
                    await Accounts.ChangePassword(me, oldP.Text, newP.Text);
                    oldP.Text = newP.Text = repP.Text = "";
                    msg.Text = "";
                    Toast("Пароль изменён", Theme.Good);
                }
                catch (HubError ex) { msg.Text = ex.Message; }
                finally { savePass.Enabled = true; }
            };
            stack.Controls.Add(savePass);

            var logout = UI.MakeButton("Выйти из аккаунта", Theme.Danger, Color.White);
            logout.Margin = new Padding(0, 30, 0, 0);
            logout.Click += async (s, e) =>
            {
                logout.Enabled = false;
                await Accounts.Logout();
                LoggedOut = true;
                Close();
            };
            stack.Controls.Add(logout);
        }

        // ---- Админ-панель ----
        void BuildAdmin(FlowLayoutPanel stack)
        {
            stack.Controls.Add(UI.MakeLabel("ТОЛЬКО ДЛЯ АДМИНА", 9, Theme.Signal, FontStyle.Bold));
            stack.Controls.Add(UI.MakeLabel("Админ-панель", 24, Theme.Fg, FontStyle.Bold));

            // Статистика
            var stats = new FlowLayoutPanel { AutoSize = true, Margin = new Padding(0, 16, 0, 0) };
            void Tile(string num, string label)
            {
                var t = new Panel { Size = new Size(150, 80), BackColor = Theme.Surface, Margin = new Padding(0, 0, 12, 0) };
                var n = UI.MakeLabel(num, 20, Theme.Accent, FontStyle.Bold); n.Location = new Point(14, 8);
                var l = UI.MakeLabel(label, 9.5f, Theme.Muted); l.Location = new Point(16, 48);
                t.Controls.Add(n); t.Controls.Add(l);
                stats.Controls.Add(t);
            }
            Tile(users.Count.ToString(), "аккаунтов");
            Tile(data.Apps.Count.ToString(), "продуктов");
            Tile(data.Apps.Sum(a => a.Launches).ToString(), "запусков");
            Tile(((int)(data.Apps.Sum(a => a.MinutesPlayed) / 60)).ToString() + " ч", "общее время");
            stack.Controls.Add(stats);

            // Новая новость
            stack.Controls.Add(Section("Написать новость"));
            var nt = UI.MakeBox(620); nt.PlaceholderText = "Заголовок";
            var nx = UI.MakeBox(620); nx.Multiline = true; nx.Height = 80; nx.Font = Theme.Font(10.5f);
            nx.PlaceholderText = "Текст новости";
            nx.Margin = new Padding(0, 8, 0, 0);
            stack.Controls.Add(nt); stack.Controls.Add(nx);
            var post = UI.MakeButton("Опубликовать", Theme.Accent, Color.White);
            post.Margin = new Padding(0, 10, 0, 0);
            post.Click += async (s, e) =>
            {
                if (string.IsNullOrWhiteSpace(nt.Text)) { Toast("Впиши заголовок", Theme.Danger); return; }
                post.Enabled = false;
                try
                {
                    await Accounts.AddNews(me, nt.Text.Trim(), nx.Text.Trim());
                    Toast("Новость опубликована", Theme.Good);
                    RefreshNews();
                    ShowPage("Админ");
                }
                catch (HubError ex) { Toast(ex.Message, Theme.Danger); post.Enabled = true; }
            };
            stack.Controls.Add(post);

            stack.Controls.Add(Section("Быстро добавить"));
            var import = UI.MakeButton("⇩ Импорт ярлыков с рабочего стола", Theme.Surface, Theme.Fg);
            import.Click += (s, e) =>
            {
                using var d = new ImportDialog(data);
                if (d.ShowDialog(this) == DialogResult.OK && d.Selected.Count > 0)
                {
                    data.Apps.AddRange(d.Selected);
                    Storage.Save(data);
                    Toast($"Добавлено: {d.Selected.Count}", Theme.Good);
                    ShowPage("Админ");
                }
            };
            stack.Controls.Add(import);

            // Пользователи
            stack.Controls.Add(Section("Пользователи"));
            if (users.Count == 0)
                stack.Controls.Add(UI.MakeLabel("Загружаю...", 10.5f, Theme.Muted));
            foreach (var u in users.ToList())
            {
                var row = new Panel { Size = new Size(620, 54), BackColor = Theme.Surface, Margin = new Padding(0, 0, 0, 8) };
                var nm = UI.MakeLabel(u.Nickname, 11, Theme.Fg, FontStyle.Bold);
                nm.Location = new Point(14, 6);
                var sub = UI.MakeLabel($"{u.Login} · {(u.IsAdmin ? "админ" : "игрок")} · с {u.Created:dd.MM.yyyy}", 9,
                    u.IsAdmin ? Theme.Signal : Theme.Muted);
                sub.Location = new Point(14, 28);
                row.Controls.Add(nm); row.Controls.Add(sub);

                if (!u.Login.Equals(me.Login, StringComparison.OrdinalIgnoreCase))
                {
                    var toggle = UI.MakeButton(u.IsAdmin ? "Снять админа" : "Сделать админом", Theme.SurfaceHover, Theme.Fg);
                    toggle.Location = new Point(330, 12);
                    toggle.Click += async (s, e) =>
                    {
                        try
                        {
                            await Accounts.SetAdmin(u.Login, !u.IsAdmin);
                            Toast(!u.IsAdmin ? $"{u.Nickname} теперь админ" : $"{u.Nickname} больше не админ");
                            RefreshUsers();
                        }
                        catch (HubError ex) { Toast(ex.Message, Theme.Danger); }
                    };
                    var del = UI.MakeButton("Удалить", Theme.Danger, Color.White);
                    del.Location = new Point(510, 12);
                    del.Click += async (s, e) =>
                    {
                        if (MessageBox.Show($"Удалить аккаунт «{u.Login}»?", "gnerti Hub", MessageBoxButtons.YesNo) != DialogResult.Yes) return;
                        try
                        {
                            await Accounts.DeleteUser(u.Login);
                            Toast("Аккаунт удалён", Theme.Danger);
                            RefreshUsers();
                        }
                        catch (HubError ex) { Toast(ex.Message, Theme.Danger); }
                    };
                    row.Controls.Add(toggle); row.Controls.Add(del);
                }
                else
                {
                    var you = UI.MakeLabel("это ты", 9.5f, Theme.Muted);
                    you.Location = new Point(540, 18);
                    row.Controls.Add(you);
                }
                stack.Controls.Add(row);
            }
        }

        Label Section(string text)
        {
            var l = UI.MakeLabel(text, 13, Theme.Fg, FontStyle.Bold);
            l.Margin = new Padding(0, 26, 0, 10);
            return l;
        }

        // ---- Сортировка ----
        static readonly string[] SortModes = { "Популярные", "Новые", "По имени", "Недавно запущенные", "Больше всего времени" };

        IEnumerable<AppItem> Sorted(IEnumerable<AppItem> items) => me.Sort switch
        {
            "Новые" => items.OrderByDescending(a => a.Added),
            "По имени" => items.OrderBy(a => a.Name, StringComparer.CurrentCultureIgnoreCase),
            "Недавно запущенные" => items.OrderByDescending(a => a.LastLaunched ?? DateTime.MinValue),
            "Больше всего времени" => items.OrderByDescending(a => a.MinutesPlayed),
            _ => items.OrderByDescending(a => a.Launches)
        };

        FlowLayoutPanel SortBox()
        {
            var row = new FlowLayoutPanel { AutoSize = true, WrapContents = false, Margin = new Padding(0, 0, 0, 14) };
            var l = UI.MakeLabel("Сортировка:", 10, Theme.Muted);
            l.Margin = new Padding(0, 6, 8, 0);
            var cb = new ComboBox
            {
                DropDownStyle = ComboBoxStyle.DropDownList,
                BackColor = Theme.Surface,
                ForeColor = Theme.Fg,
                FlatStyle = FlatStyle.Flat,
                Width = 200
            };
            cb.Items.AddRange(SortModes);
            cb.SelectedItem = SortModes.Contains(me.Sort) ? me.Sort : SortModes[0];
            cb.SelectedIndexChanged += (s, e) =>
            {
                me.Sort = cb.SelectedItem?.ToString() ?? SortModes[0];
                SaveMe();
                BeginInvoke(() => ShowPage(page));
            };
            row.Controls.Add(l); row.Controls.Add(cb);
            return row;
        }

        // ---- Страница продукта ----
        void OpenProduct(AppItem a)
        {
            if (page != "Продукт") backPage = page;
            selected = a;
            ShowPage("Продукт");
        }

        void BuildProduct(FlowLayoutPanel stack)
        {
            var a = selected;
            var back = UI.MakeButton("← Назад", Theme.Surface, Theme.Fg);
            back.Margin = new Padding(0, 0, 0, 16);
            back.Click += (s, e) => ShowPage(backPage == "Продукт" ? "Главная" : backPage);
            stack.Controls.Add(back);

            var head = new Panel { Size = new Size(760, 150), BackColor = Theme.Surface };
            var icon = new ProductIcon(a, 110) { Location = new Point(20, 20) };
            var cat = UI.MakeLabel(a.Category.ToUpper(), 9, Theme.Signal, FontStyle.Bold);
            cat.Location = new Point(150, 22);
            var nm = UI.MakeLabel(a.Name, 24, Theme.Fg, FontStyle.Bold);
            nm.Location = new Point(146, 42);
            var play = UI.MakeButton("▶ Запустить", a.Category == "Игры" ? Theme.Signal : Theme.Accent, Color.White);
            play.Font = Theme.Font(12, FontStyle.Bold);
            play.Location = new Point(150, 96);
            play.Click += (s, e) => Launch(a);

            bool fav = me.Favorites.Contains(a.Id);
            var star = UI.MakeButton(fav ? "★ В избранном" : "☆ В избранное", Theme.SurfaceHover, fav ? Theme.Gold : Theme.Fg);
            star.Location = new Point(310, 100);
            star.Click += (s, e) =>
            {
                if (fav) me.Favorites.Remove(a.Id); else me.Favorites.Add(a.Id);
                SaveMe();
                ShowPage("Продукт");
            };
            head.Controls.AddRange(new Control[] { icon, cat, nm, play, star });

            if (me.IsAdmin)
            {
                var edit = UI.MakeButton("✎ Изменить", Theme.SurfaceHover, Theme.Fg);
                edit.Location = new Point(480, 100);
                edit.Click += (s, e) => OpenProductDialog(a, a.Category);
                head.Controls.Add(edit);
            }
            stack.Controls.Add(head);

            stack.Controls.Add(Section("Описание"));
            var d = UI.MakeLabel(string.IsNullOrWhiteSpace(a.Description) ? "Описания пока нет." : a.Description, 11, Theme.Muted);
            d.MaximumSize = new Size(740, 0);
            stack.Controls.Add(d);

            stack.Controls.Add(Section("Статистика"));
            var stats = new FlowLayoutPanel { AutoSize = true };
            void Tile(string num, string label)
            {
                var t = new Panel { Size = new Size(176, 80), BackColor = Theme.Surface, Margin = new Padding(0, 0, 12, 0) };
                var n = UI.MakeLabel(num, 15, Theme.Accent, FontStyle.Bold); n.Location = new Point(14, 10);
                var l = UI.MakeLabel(label, 9.5f, Theme.Muted); l.Location = new Point(16, 48);
                t.Controls.Add(n); t.Controls.Add(l);
                stats.Controls.Add(t);
            }
            Tile(a.Launches.ToString(), "запусков");
            Tile(Fmt.Time(a.MinutesPlayed), "всего времени");
            Tile(Fmt.Ago(a.LastLaunched), "последний запуск");
            Tile(a.Added.ToString("dd.MM.yyyy"), "добавлено");
            stack.Controls.Add(stats);

            if (me.IsAdmin)
            {
                stack.Controls.Add(Section("Файл"));
                var path = UI.MakeLabel(a.Path, 9.5f, Theme.Muted);
                path.MaximumSize = new Size(740, 0);
                stack.Controls.Add(path);
            }
        }

        protected override void OnResizeEnd(EventArgs e)
        {
            base.OnResizeEnd(e);
            ShowPage(page);
        }

        protected override void OnResize(EventArgs e)
        {
            base.OnResize(e);
            if (toast.Visible)
                toast.Location = new Point(ClientSize.Width - toast.PreferredWidth - 24, ClientSize.Height - toast.PreferredHeight - 24);
        }
    }

    static class Program
    {
        [STAThread]
        static void ReportError(Exception ex)
        {
            try
            {
                string dir = System.IO.Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "gnerti");
                Directory.CreateDirectory(dir);
                File.AppendAllText(System.IO.Path.Combine(dir, "errors.log"), $"[{DateTime.Now}] {ex}\n\n");
            }
            catch { }
            MessageBox.Show("Что-то пошло не так, но программа продолжает работать.\n\n" + ex?.Message +
                            "\n\nПодробности записаны в %AppData%\\gnerti\\errors.log", "gnerti Hub");
        }

        static void Main()
        {
            // Только одна копия программы
            using var mutex = new Mutex(true, "gnerti-hub-single-instance", out bool firstCopy);
            if (!firstCopy)
            {
                MessageBox.Show("gnerti Hub уже запущен.", "gnerti Hub");
                return;
            }

            ApplicationConfiguration.Initialize();
            Application.SetUnhandledExceptionMode(UnhandledExceptionMode.CatchException);
            Application.ThreadException += (s, e) => ReportError(e.Exception);
            AppDomain.CurrentDomain.UnhandledException += (s, e) => ReportError(e.ExceptionObject as Exception);

            using (var splash = new SplashForm()) splash.ShowDialog();

            var data = Storage.Load();

            while (true)
            {
                Accounts.Data = data;
                UserAccount user = Task.Run(() => Accounts.Restore()).GetAwaiter().GetResult();

                if (user == null)
                {
                    using var login = new LoginForm(data);
                    if (login.ShowDialog() != DialogResult.OK || login.LoggedIn == null) return;
                    user = login.LoggedIn;
                }

                Theme.UseAccent(user.AccentIndex);
                var main = new MainForm(data, user);
                Application.Run(main);
                if (!main.LoggedOut) return;
            }
        }
    }
}
