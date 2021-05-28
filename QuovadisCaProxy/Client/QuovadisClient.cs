using System;
using System.Collections.Concurrent;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using CAProxy.AnyGateway.Interfaces;
using CSS.Common.Logging;
using Keyfactor.AnyGateway.Quovadis.Exceptions;
using Newtonsoft.Json;

namespace Keyfactor.AnyGateway.Quovadis.Client
{
    public sealed class CscGlobalClient : LoggingClientBase
    {
        public CscGlobalClient(ICAConnectorConfigProvider config)
        {
            if (config.CAConnectionData.ContainsKey(Constants.CscGlobalApiKey))
            {
                BaseUrl = new Uri(config.CAConnectionData[Constants.CscGlobalUrl].ToString());
                ApiKey = config.CAConnectionData[Constants.CscGlobalApiKey].ToString();
                Authorization = config.CAConnectionData[Constants.BearerToken].ToString();
            }
        }

        private Uri BaseUrl { get; }
        private HttpClient RestClient { get; }
        private int PageSize { get; } = 100;
        private string ApiKey { get; }
        private string Authorization { get; }


    }
}