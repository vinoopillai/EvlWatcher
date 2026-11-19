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
        [Ignore("until Task 3")]
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
