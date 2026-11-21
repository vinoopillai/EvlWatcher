using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;
using System.Threading;
using System.Windows;
using System.Windows.Threading;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace EvlWatcherConsole.Tests
{
    /// <summary>
    /// Checks the console's own theme: every resource the views reference must exist, and nothing may
    /// depend on the .NET 9+ Fluent theme or on icon fonts that Windows 7 / 8.1 don't have.
    /// </summary>
    [TestClass]
    public class ThemeResourceTests
    {
        private static readonly Regex ResourceRef = new Regex(@"(?:Static|Dynamic)Resource\s+([A-Za-z0-9]+)\s*\}");
        private static readonly Regex TypeRef = new Regex(@"StaticResource\s+\{x:Type\s+(\w+)\}");
        private static readonly Regex LocalKey = new Regex(@"x:Key=""([^""]+)""");

        private static string XamlDir => Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "Xaml");

        private static IEnumerable<string> ViewFiles => Directory.GetFiles(Path.Combine(XamlDir, "View"), "*.xaml");

        private static IEnumerable<string> AllXamlFiles => Directory.GetFiles(XamlDir, "*.xaml", SearchOption.AllDirectories);

        [ClassCleanup]
        public static void StopWpf()
        {
            WpfApp.Shutdown();
        }

        [TestMethod]
        public void EveryReferencedKeyExists()
        {
            var missing = new List<string>();
            WpfApp.Invoke(() =>
            {
                foreach (string file in ViewFiles)
                {
                    string xaml = File.ReadAllText(file);
                    var local = new HashSet<string>(LocalKey.Matches(xaml).Cast<Match>().Select(m => m.Groups[1].Value));

                    foreach (string key in ResourceRef.Matches(xaml).Cast<Match>().Select(m => m.Groups[1].Value).Distinct())
                    {
                        if (!local.Contains(key) && Application.Current.TryFindResource(key) == null)
                            missing.Add($"{Path.GetFileName(file)}: {key}");
                    }

                    foreach (string typeName in TypeRef.Matches(xaml).Cast<Match>().Select(m => m.Groups[1].Value).Distinct())
                    {
                        Type type = typeof(FrameworkElement).Assembly.GetType("System.Windows.Controls." + typeName)
                                    ?? typeof(FrameworkElement).Assembly.GetType("System.Windows." + typeName);
                        if (type == null || Application.Current.TryFindResource(type) == null)
                            missing.Add($"{Path.GetFileName(file)}: {{x:Type {typeName}}}");
                    }
                }
            });

            Assert.AreEqual(0, missing.Count, "Missing resources:\n" + string.Join("\n", missing));
        }

        [TestMethod]
        public void NoIconGlyphsInViews()
        {
            var glyph = new Regex(@"&#x[Ee][0-9A-Fa-f]{3};");
            var offenders = AllXamlFiles
                .Where(f => glyph.IsMatch(File.ReadAllText(f)) || File.ReadAllText(f).Contains("IconTextStyle"))
                .Select(Path.GetFileName)
                .ToList();

            Assert.AreEqual(0, offenders.Count, "Icon-font glyphs or IconTextStyle still used in: " + string.Join(", ", offenders));
        }

        [TestMethod]
        public void IconsAreGeometries()
        {
            string[] keys =
            {
                "ShieldIcon", "PulseIcon", "ListIcon", "SettingsIcon", "CodeIcon", "EditIcon",
                "PlayIcon", "ResetIcon", "AddIcon", "CancelIcon", "LockIcon", "UnlockIcon", "AnalyzeIcon"
            };
            var problems = new List<string>();
            WpfApp.Invoke(() =>
            {
                foreach (string key in keys)
                {
                    var geometry = Application.Current.TryFindResource(key) as System.Windows.Media.Geometry;
                    if (geometry == null)
                    {
                        problems.Add(key + ": missing or not a Geometry");
                        continue;
                    }
                    Rect b = geometry.Bounds;
                    if (b.IsEmpty || b.Left < 0 || b.Top < 0 || b.Right > 16 || b.Bottom > 16)
                        problems.Add($"{key}: bounds {b} outside 0..16");
                }
            });

            Assert.AreEqual(0, problems.Count, string.Join("\n", problems));
        }

        [TestMethod]
        public void SelectedTabDoesNotMakeItsContentBold()
        {
            FontWeight weight = FontWeights.Black;
            WpfApp.Invoke(() =>
            {
                var body = new System.Windows.Controls.TextBlock { Text = "body" };
                var tabs = new System.Windows.Controls.TabControl();
                tabs.Items.Add(new System.Windows.Controls.TabItem { Header = "Tab", Content = body, IsSelected = true });
                using (OffscreenWindow.Show(tabs))
                {
                    weight = body.FontWeight;
                }
            });

            Assert.AreEqual(FontWeights.Normal, weight);
        }

        [TestMethod]
        public void ReadOnlyTextBoxShowsKeyboardFocus()
        {
            bool focused = false, frameIsAccent = false;
            WpfApp.Invoke(() =>
            {
                var box = new System.Windows.Controls.TextBox { IsReadOnly = true, Text = "log" };
                using (OffscreenWindow.Show(box))
                {
                    focused = System.Windows.Input.Keyboard.Focus(box) == box;
                    box.UpdateLayout();
                    var frame = (System.Windows.Controls.Border)box.Template.FindName("Frame", box);
                    var accent = (System.Windows.Media.SolidColorBrush)Application.Current.FindResource("AccentFillColorDefaultBrush");
                    frameIsAccent = frame.BorderBrush is System.Windows.Media.SolidColorBrush b && b.Color == accent.Color;
                }
            });

            if (!focused)
                Assert.Inconclusive("The test host could not give keyboard focus to an offscreen window.");
            Assert.IsTrue(frameIsAccent, "A focused read-only TextBox must show an accent border.");
        }

        [TestMethod]
        public void NoFluentOrIconFontReferences()
        {
            var offenders = AllXamlFiles
                .SelectMany(f => new[] { "PresentationFramework.Fluent", "SymbolThemeFontFamily", "Cascadia" }
                    .Where(word => File.ReadAllText(f).Contains(word))
                    .Select(word => $"{Path.GetFileName(f)}: {word}"))
                .ToList();

            Assert.AreEqual(0, offenders.Count, string.Join("\n", offenders));
        }
    }

    /// <summary>Shows content in a real window far off screen, so templates and triggers apply. Dispose closes it.</summary>
    internal sealed class OffscreenWindow : IDisposable
    {
        private readonly Window _window;

        private OffscreenWindow(UIElement content)
        {
            _window = new Window
            {
                Content = content, Width = 400, Height = 300, Left = -5000, Top = -5000,
                WindowStartupLocation = WindowStartupLocation.Manual, ShowInTaskbar = false
            };
            _window.Show();
            _window.Activate();
            _window.UpdateLayout();
        }

        public static OffscreenWindow Show(UIElement content) => new OffscreenWindow(content);

        public void Dispose() => _window.Close();
    }

    /// <summary>One EvlWatcherConsole.App per test run, living on its own STA dispatcher thread.</summary>
    internal static class WpfApp
    {
        private static readonly object Sync = new object();
        private static Dispatcher _dispatcher;
        private static Exception _startupError;

        /// <summary>Stops the dispatcher so the test host can unload cleanly.</summary>
        public static void Shutdown()
        {
            lock (Sync)
            {
                _dispatcher?.InvokeShutdown();
                _dispatcher = null;
            }
        }

        public static void Invoke(Action action)
        {
            EnsureStarted();
            if (_startupError != null)
                throw new InvalidOperationException("EvlWatcherConsole.App failed to load its resources.", _startupError);

            Exception error = null;
            _dispatcher.Invoke(() =>
            {
                try { action(); }
                catch (Exception e) { error = e; }
            });
            if (error != null)
                throw new InvalidOperationException(error.Message, error);
        }

        private static void EnsureStarted()
        {
            lock (Sync)
            {
                if (_dispatcher != null)
                    return;

                var ready = new ManualResetEventSlim();
                var thread = new Thread(() =>
                {
                    try
                    {
                        // the test host has no entry assembly, so relative pack URIs need to be told where to look
                        Application.ResourceAssembly = typeof(EvlWatcherConsole.App).Assembly;
                        var app = new EvlWatcherConsole.App { ShutdownMode = ShutdownMode.OnExplicitShutdown };
                        app.InitializeComponent();
                    }
                    catch (Exception e)
                    {
                        _startupError = e;
                    }
                    _dispatcher = Dispatcher.CurrentDispatcher;
                    ready.Set();
                    Dispatcher.Run();
                });
                thread.SetApartmentState(ApartmentState.STA);
                thread.IsBackground = true;
                thread.Start();
                ready.Wait();
            }
        }
    }
}
