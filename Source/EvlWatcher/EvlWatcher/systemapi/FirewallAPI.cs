using System;
using System.Collections.Generic;
using System.IO;
using NetFwTypeLib;
using System.Net;
using EvlWatcher.Comparer;
using System.Runtime.InteropServices;

namespace EvlWatcher.SystemAPI
{
    /// <summary>
    /// this class wraps required parts of the Microsoft Firewall with Enhanced Security COM API
    /// </summary>
    public class FirewallAPI : IDisposable
    {
        #region private members
        private const string CLSID_FWPOLICY2 = "{E2B3C97F-6AE1-41AC-817A-F6F92166D7DD}";
        private const string CLSID_FWRULE = "{2C5BC43E-3369-4C33-AB0C-BE9469677AF4}";
        private const string RULE_NAME = "EvlWatcher";
        private bool _disposed;

        private INetFwPolicy2 _fwPolicy2 = null;

        #endregion

        #region .ctor

        ~FirewallAPI()
        {
            Dispose(disposing: false);
        }

        #endregion

        #region private operations

        private static void ReleaseComObject(object comObject)
        {
            if (comObject != null && Marshal.IsComObject(comObject))
                Marshal.ReleaseComObject(comObject);
        }

        /// <summary>
        /// Returns the EvlWatcher rule, creating it when <paramref name="create"/> is set.
        /// The caller owns the returned COM object and must release it with <see cref="ReleaseComObject"/>.
        /// </summary>
        private INetFwRule GetEvlWatcherRule(bool create)
        {
            INetFwRules rules = GetPolicy2().Rules;
            try
            {
                try
                {
                    // Item() looks the rule up by name, so we don't have to marshal (and leak) every rule on the system
                    return rules.Item(RULE_NAME);
                }
                catch (FileNotFoundException)
                {
                    // rule does not exist (HRESULT 0x80070002)
                }

                if (!create)
                    return null;

                INetFwRule rule = CreateFwRule();
                rule.Enabled = false;
                rule.Action = NET_FW_ACTION_.NET_FW_ACTION_BLOCK;
                rule.Description = "This is the rule EvlWatcher uses for temporarily banning IPs. It will enable/disable automatically when IPs need to be banned. You don't have to manually enable it.";
                rule.Direction = NET_FW_RULE_DIRECTION_.NET_FW_RULE_DIR_IN;
                rule.EdgeTraversal = false;
                rule.LocalAddresses = "*";
                rule.Name = RULE_NAME;
                rule.Profiles = int.MaxValue;// = means all Profiles
                rule.Protocol = 256;
                rules.Add(rule);

                return rule;
            }
            finally
            {
                ReleaseComObject(rules);
            }
        }

        private INetFwPolicy2 GetPolicy2()
        {
            if (_fwPolicy2 == null)
            {
                Type objectType = Type.GetTypeFromCLSID(
                    new Guid(CLSID_FWPOLICY2));
                _fwPolicy2 = Activator.CreateInstance(objectType)
                      as INetFwPolicy2;
            }

            return _fwPolicy2;
        }

        private static INetFwRule CreateFwRule()
        {
            Type objectType = Type.GetTypeFromCLSID(new Guid(CLSID_FWRULE));
            return Activator.CreateInstance(objectType) as INetFwRule;
        }

        #endregion

        #region public operations

        public void Dispose()
        {
            // Do not change this code. Put cleanup code in 'Dispose(bool disposing)' method
            Dispose(disposing: true);
            GC.SuppressFinalize(this);
        }

        public void ClearIPBanList()
        {
            INetFwRule rule = GetEvlWatcherRule(false);
            if (rule == null)
                return;

            ReleaseComObject(rule);

            INetFwRules rules = GetPolicy2().Rules;
            try
            {
                rules.Remove(RULE_NAME);
            }
            finally
            {
                ReleaseComObject(rules);
            }
        }

        public bool AdjustIPBanList(List<IPAddress> ips)
        {
            ips.Sort(new IPAddressComparer());

            INetFwRule rule = GetEvlWatcherRule(true);
            try
            {
                bool changed = false;

                if (ips.Count == 0)
                {
                    if (rule.Enabled)
                    {
                        rule.RemoteAddresses = "";
                        rule.Enabled = false;
                        changed = true;
                    }
                }
                else
                {
                    string remoteAdresses = "";
                    bool first = true;
                    foreach (IPAddress s in ips)
                    {
                        if (!first)
                            remoteAdresses += ",";
                        else
                            first = false;

                        if (s.ToString().Contains("."))
                            remoteAdresses += s + "/255.255.255.255";
                        else
                            remoteAdresses += s; //no netmask for ipv6?
                    }

                    if (rule.RemoteAddresses != remoteAdresses)
                    {
                        rule.RemoteAddresses = remoteAdresses;
                        changed = true;
                    }

                    if (!rule.Enabled)
                    {
                        rule.Enabled = true;
                        changed = true;
                    }
                }

                return changed;
            }
            finally
            {
                ReleaseComObject(rule);
            }
        }

        public List<string> GetBannedIPs()
        {
            List<string> currentlyBannedIPs = new List<string>();

            INetFwRule fwRule = GetEvlWatcherRule(true);
            try
            {
                if (fwRule.Enabled)
                {
                    string remoteAddresses = fwRule.RemoteAddresses;
                    if (remoteAddresses != null)
                    {
                        foreach (string s in remoteAddresses.Split(','))
                            currentlyBannedIPs.Add(s.Contains("-") ? s.Split('-')[0] : s);
                    }
                }
            }
            finally
            {
                ReleaseComObject(fwRule);
            }

            return currentlyBannedIPs;
        }

        #endregion

        #region protected operations

        protected virtual void Dispose(bool disposing)
        {
            if (!_disposed)
            {
                if (disposing)
                {
                    // TODO: dispose managed state (managed objects)
                }

                if (_fwPolicy2 != null)
                {
                    Marshal.ReleaseComObject(_fwPolicy2);
                    _fwPolicy2 = null;
                }
                _disposed = true;
            }
        }

        #endregion
    }
}
