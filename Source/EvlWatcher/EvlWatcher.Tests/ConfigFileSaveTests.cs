using System.IO;
using System.Xml.Linq;
using EvlWatcher.Config;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;

namespace EvlWatcher.Tests
{
    [TestClass]
    public class ConfigFileSaveTests
    {
        [TestMethod]
        public void Save_InvalidChar_ThrowsAndLeavesPreviousFileIntact()
        {
            using (var cfg = new TempConfig())
            {
                var before = File.ReadAllText(cfg.FilePath);
                var d = XDocument.Load(cfg.FilePath);
                d.Root.Add(new XElement("Bad", "a\vb"));

                Assert.ThrowsExactly<ArgumentException>(() => ConfigFile.Save(d));

                Assert.AreEqual(before, File.ReadAllText(cfg.FilePath));
                Assert.IsFalse(File.Exists(cfg.FilePath + ".tmp"));
            }
        }

        [TestMethod]
        public void Save_ValidDoc_ReplacesFile()
        {
            using (var cfg = new TempConfig())
            {
                var d = XDocument.Load(cfg.FilePath);
                d.Root.Add(new XElement("Ok", "x"));
                ConfigFile.Save(d);
                StringAssert.Contains(File.ReadAllText(cfg.FilePath), "<Ok>x</Ok>");
                Assert.IsFalse(File.Exists(cfg.FilePath + ".tmp"));
            }
        }

        [TestMethod]
        public void Save_TransientLock_RetriesAndSucceeds()
        {
            using (var cfg = new TempConfig())
            {
                var d = XDocument.Load(cfg.FilePath);
                d.Root.Add(new XElement("Retried", "yes"));
                var held = new FileStream(cfg.FilePath, FileMode.Open, FileAccess.Read, FileShare.None);
                var release = System.Threading.Tasks.Task.Run(() =>
                {
                    System.Threading.Thread.Sleep(150);
                    held.Dispose();
                });

                ConfigFile.Save(d);

                release.Wait();
                StringAssert.Contains(File.ReadAllText(cfg.FilePath), "<Retried>yes</Retried>");
                Assert.IsFalse(File.Exists(cfg.FilePath + ".tmp"));
            }
        }

        [TestMethod]
        public void Save_PermanentLock_ThrowsKeepsOriginalAndRemovesTmp()
        {
            using (var cfg = new TempConfig())
            {
                var before = File.ReadAllText(cfg.FilePath);
                var d = XDocument.Load(cfg.FilePath);
                d.Root.Add(new XElement("Never", "x"));
                bool threw = false;
                using (new FileStream(cfg.FilePath, FileMode.Open, FileAccess.Read, FileShare.None))
                {
                    try { ConfigFile.Save(d); }
                    catch (IOException) { threw = true; }
                    catch (UnauthorizedAccessException) { threw = true; }
                    Assert.IsTrue(threw);
                    Assert.IsFalse(File.Exists(cfg.FilePath + ".tmp"));
                }
                Assert.AreEqual(before, File.ReadAllText(cfg.FilePath));
            }
        }
    }
}
