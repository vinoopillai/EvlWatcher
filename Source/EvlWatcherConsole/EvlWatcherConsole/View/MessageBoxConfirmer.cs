using System.Windows;
using EvlWatcherConsole.Analysis;

namespace EvlWatcherConsole.View
{
    /// <summary>Yes/No confirmation as a standard message box.</summary>
    public sealed class MessageBoxConfirmer : IConfirmer
    {
        public bool Confirm(string title, string message)
        {
            return MessageBox.Show(Application.Current?.MainWindow, message, title, MessageBoxButton.YesNo, MessageBoxImage.Warning, MessageBoxResult.No)
                   == MessageBoxResult.Yes;
        }
    }
}
