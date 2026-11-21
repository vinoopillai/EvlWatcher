using System;
using System.Net;

namespace EvlWatcher.Geo
{
    /// <summary>Fetches one registry file; throws on failure.</summary>
    public interface IRegistryDownloader
    {
        string Download(string url);
    }

    /// <summary>HTTPS download with TLS 1.2 (needed on Windows 8.1 / Server 2012) and a 60 s timeout.</summary>
    public sealed class HttpRegistryDownloader : IRegistryDownloader
    {
        public string Download(string url)
        {
            ServicePointManager.SecurityProtocol |= SecurityProtocolType.Tls12;
            using (var client = new TimeoutWebClient())
            {
                client.Headers[HttpRequestHeader.UserAgent] = "EvlWatcher";
                return client.DownloadString(url);
            }
        }

        private sealed class TimeoutWebClient : WebClient
        {
            protected override WebRequest GetWebRequest(Uri address)
            {
                WebRequest request = base.GetWebRequest(address);
                if (request != null)
                    request.Timeout = 60000;
                if (request is HttpWebRequest http)
                    http.ReadWriteTimeout = 60000;
                return request;
            }
        }
    }
}
