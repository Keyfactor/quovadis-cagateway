using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Threading.Tasks;
using CAProxy.AnyGateway.Interfaces;
using CSS.Common.Logging;
using Keyfactor.AnyGateway.Quovadis.Models;
using Newtonsoft.Json;

namespace Keyfactor.AnyGateway.Quovadis.Client
{
    public sealed class KeyfactorClient : LoggingClientBase
    {
        private HttpClient RestClient { get; }

        public KeyfactorClient(ICAConnectorConfigProvider configProvider)
        {
            try
            {
                var keyfactorBaseUrl = new Uri(configProvider.CAConnectionData["KeyfactorApiUrl"].ToString());
                var keyfactorAuth = configProvider.CAConnectionData["KeyfactorApiUserId"] + ":" + configProvider.CAConnectionData["KeyfactorApiPassword"];
                var plainTextBytes = Encoding.UTF8.GetBytes(keyfactorAuth);

                Logger.Trace($"KeyfactorBaseUrl={keyfactorBaseUrl}, KeyfactorAuth={keyfactorAuth}, Plain Text Bytes={plainTextBytes}");

                var clientHandler = new WebRequestHandler();
                RestClient = new HttpClient(clientHandler, true) { BaseAddress = keyfactorBaseUrl };
                RestClient.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
                RestClient.DefaultRequestHeaders.Add("x-keyfactor-requested-with", "APIClient");
                RestClient.DefaultRequestHeaders.Add("Authorization", "Basic " + Convert.ToBase64String(plainTextBytes));
            }
            catch (Exception e)
            {
                Logger.Error($"Error in Keyfactor Client Constructor {e.Message}");
                throw;
            }

        }

        public async Task<List<KeyfactorCertificate>> SubmitGetKeyfactorCertAsync(string serialNumberFilter)
        {
            try
            {
                using (var resp = await RestClient.GetAsync($"Certificates?pq.queryString=SerialNumber%20-eq%20%22{serialNumberFilter}%22"))
                {
                    resp.EnsureSuccessStatusCode();
                    var keyfactorCertificateResponse =
                        JsonConvert.DeserializeObject<List<KeyfactorCertificate>>(await resp.Content.ReadAsStringAsync());

                    Logger.Trace($"Keyfactor Cert Response={JsonConvert.SerializeObject(keyfactorCertificateResponse)}");

                    return keyfactorCertificateResponse;
                }
            }
            catch (Exception e)
            {
                Logger.Error($"Error in SubmitGetKeyfactorCertAsync {e.Message}");
                throw;
            }
        }
    }
}
