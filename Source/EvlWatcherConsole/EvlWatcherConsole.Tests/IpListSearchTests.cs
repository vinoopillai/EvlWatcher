using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Linq;
using System.Net;
using System.Windows.Data;
using EvlWatcherConsole.ViewModel;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace EvlWatcherConsole.Tests
{
    [TestClass]
    public class IpListSearchTests
    {
        private static object[] Visible(System.Collections.IEnumerable source) =>
            CollectionViewSource.GetDefaultView(source).Cast<object>().ToArray();

        [TestMethod]
        public void MatchesPartOfTheAddressIgnoringCaseAndSpaces()
        {
            Assert.IsTrue(IpListSearch.Matches(IPAddress.Parse("203.0.113.7"), "113."));
            Assert.IsTrue(IpListSearch.Matches(IPAddress.Parse("2001:db8::1"), " DB8 "));
            Assert.IsTrue(IpListSearch.Matches("192.168.*", "168"));
            Assert.IsFalse(IpListSearch.Matches(IPAddress.Parse("203.0.113.7"), "10.0"));
        }

        [TestMethod]
        public void EmptySearchShowsEverything()
        {
            Assert.IsTrue(IpListSearch.Matches(IPAddress.Parse("203.0.113.7"), ""));
            Assert.IsTrue(IpListSearch.Matches(IPAddress.Parse("203.0.113.7"), "   "));
            Assert.IsTrue(IpListSearch.Matches(IPAddress.Parse("203.0.113.7"), null));
        }

        [TestMethod]
        public void FiltersEveryListAndSummarises()
        {
            var temp = new ObservableCollection<IPAddress> { IPAddress.Parse("203.0.113.7"), IPAddress.Parse("198.51.100.4") };
            var perma = new ObservableCollection<IPAddress> { IPAddress.Parse("203.0.113.99") };
            var white = new ObservableCollection<string> { "10.0.*", "203.0.113.*" };
            var search = new IpListSearch(temp, perma, white);

            search.Text = "203.0.113";

            CollectionAssert.AreEqual(new object[] { temp[0] }, Visible(temp));
            CollectionAssert.AreEqual(new object[] { perma[0] }, Visible(perma));
            CollectionAssert.AreEqual(new object[] { "203.0.113.*" }, Visible(white));
            Assert.IsTrue(search.IsActive);
            Assert.AreEqual("3 of 5 entries match.", search.Summary);

            search.Text = "";
            Assert.AreEqual(2, Visible(temp).Length);
            Assert.IsFalse(search.IsActive);
            Assert.AreEqual("", search.Summary);
        }

        [TestMethod]
        public void NewEntriesAreFilteredAndCounted()
        {
            var temp = new ObservableCollection<IPAddress>();
            var search = new IpListSearch(temp, new ObservableCollection<IPAddress>(), new ObservableCollection<string>());
            search.Text = "203.";
            var changed = new System.Collections.Generic.List<string>();
            ((INotifyPropertyChanged)search).PropertyChanged += (s, e) => changed.Add(e.PropertyName);

            temp.Add(IPAddress.Parse("198.51.100.4"));
            temp.Add(IPAddress.Parse("203.0.113.7"));

            CollectionAssert.AreEqual(new object[] { temp[1] }, Visible(temp));
            Assert.AreEqual("1 of 2 entries match.", search.Summary);
            CollectionAssert.Contains(changed, nameof(IpListSearch.Summary));
        }

        [TestMethod]
        public void NothingMatchingSaysSo()
        {
            var search = new IpListSearch(new ObservableCollection<IPAddress> { IPAddress.Parse("203.0.113.7") },
                                          new ObservableCollection<IPAddress>(), new ObservableCollection<string>());
            search.Text = "8.8.8.8";
            Assert.AreEqual("No entry matches \"8.8.8.8\".", search.Summary);
        }

        [TestMethod]
        public void ClearCommandEmptiesTheSearch()
        {
            var search = new IpListSearch(new ObservableCollection<IPAddress>(), new ObservableCollection<IPAddress>(),
                                          new ObservableCollection<string>());
            search.Text = "203";
            search.ClearCommand.Execute(null);
            Assert.AreEqual("", search.Text);
        }
    }
}
