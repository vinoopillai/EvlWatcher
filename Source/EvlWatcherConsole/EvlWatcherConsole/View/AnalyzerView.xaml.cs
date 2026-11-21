using System;
using System.Globalization;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;

namespace EvlWatcherConsole.View
{
    /// <summary>The Analyzer tab. All logic lives in AnalyzerViewModel and the Analysis namespace.</summary>
    public partial class AnalyzerView : UserControl
    {
        public AnalyzerView()
        {
            InitializeComponent();
        }
    }

    /// <summary>true → false and back.</summary>
    public sealed class InverseBooleanConverter : IValueConverter
    {
        public static readonly InverseBooleanConverter Instance = new InverseBooleanConverter();

        public object Convert(object value, Type targetType, object parameter, CultureInfo culture) => !(value is bool b && b);

        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) => !(value is bool b && b);
    }

    /// <summary>Visible when the bound count is 0.</summary>
    public sealed class ZeroToVisibleConverter : IValueConverter
    {
        public static readonly ZeroToVisibleConverter Instance = new ZeroToVisibleConverter();

        public object Convert(object value, Type targetType, object parameter, CultureInfo culture) =>
            value is int n && n == 0 ? Visibility.Visible : Visibility.Collapsed;

        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) =>
            throw new NotSupportedException();
    }
}
