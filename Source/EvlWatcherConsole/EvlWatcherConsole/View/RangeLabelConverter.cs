using System;
using System.Globalization;
using System.Windows.Data;
using EvlWatcherConsole.Analysis;

namespace EvlWatcherConsole.View
{
    /// <summary>Shows an <see cref="AnalysisRange"/> as "Last 24 hours" etc.</summary>
    public sealed class RangeLabelConverter : IValueConverter
    {
        public object Convert(object value, Type targetType, object parameter, CultureInfo culture) =>
            value is AnalysisRange range ? range.Label() : "";

        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) =>
            throw new NotSupportedException();
    }
}
