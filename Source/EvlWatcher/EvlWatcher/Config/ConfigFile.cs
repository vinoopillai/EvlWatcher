using System;
using System.IO;
using System.Reflection;
using System.Threading;
using System.Xml.Linq;

namespace EvlWatcher.Config
{
    /// <summary>
    /// the location of config.xml. Overridable so tests never touch the real file.
    /// </summary>
    internal static class ConfigFile
    {
        internal static string Path { get; set; } = Assembly.GetExecutingAssembly().Location.Replace("EvlWatcher.exe", "config.xml");

        private static readonly int[] RetryDelaysMs = { 100, 300 };

        /// <summary>
        /// Writes the document to a temp file first and then swaps it in, so a failed write
        /// (e.g. a character XML cannot represent) never truncates the live config.xml.
        /// The swap is retried a few times, because antivirus or indexers may hold config.xml briefly.
        /// </summary>
        internal static void Save(XDocument d)
        {
            string tmp = Path + ".tmp";
            try
            {
                d.Save(tmp);
                for (int attempt = 0; ; attempt++)
                {
                    try
                    {
                        if (File.Exists(Path))
                            File.Replace(tmp, Path, null);
                        else
                            File.Move(tmp, Path);
                        break;
                    }
                    catch (Exception e) when ((e is IOException || e is UnauthorizedAccessException) && attempt < RetryDelaysMs.Length)
                    {
                        Thread.Sleep(RetryDelaysMs[attempt]);
                    }
                }
            }
            catch
            {
                try { if (File.Exists(tmp)) File.Delete(tmp); } catch (IOException) { } catch (UnauthorizedAccessException) { }
                throw;
            }
        }
    }
}
