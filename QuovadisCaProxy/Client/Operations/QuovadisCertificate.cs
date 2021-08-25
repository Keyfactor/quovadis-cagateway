using System;
using System.IO;
using System.ServiceModel;
using System.ServiceModel.Channels;
using System.Threading.Tasks;
using System.Xml.Serialization;
using CSS.Common.Logging;
using Keyfactor.AnyGateway.Quovadis.Client.XSDs;
using Keyfactor.AnyGateway.Quovadis.QuovadisClient;

namespace Keyfactor.AnyGateway.Quovadis.Client.Operations
{
    public class QuovadisCertificate<T, TR>:LoggingClientBase
    {
        private readonly string baseUrl;
        private readonly string wsSigningCertDir;
        private readonly string wsSigningCertPwd;

        public QuovadisCertificate(string baseUrl, string wsSigningCertDir, string wsSigningCertPwd)
        {
            this.baseUrl = baseUrl;
            this.wsSigningCertDir = wsSigningCertDir;
            this.wsSigningCertPwd = wsSigningCertPwd;
        }

        public TR RequestCertificate(string emailAddress, string account, string transactionId)
        {
            try
            {
                Logger.MethodEntry(ILogExtensions.MethodLogLevel.Debug);

                Logger.Trace($"Building Request with Email Address={emailAddress}, Account={account}, TransactionId={transactionId}");

                var req = BuildRequest(emailAddress, account, transactionId);

                Logger.Trace($"Raw Cert Request Xml={req}");

                var x = new XmlSerializer(req.GetType());
                byte[] bytes;
                using (var stream = new MemoryStream())
                {
                    x.Serialize(stream, req);
                    bytes = stream.ToArray();
                }

                Binding bind = new BasicHttpsBinding();
                var ep = new EndpointAddress(baseUrl);
                var quovadisClient = new CertificateServicesSoapClient(bind, ep);

                var signedRequest = Utilities.BuildSignedCmsStructure(wsSigningCertDir, wsSigningCertPwd, bytes);

                Logger.Trace($"signedRequest={signedRequest}");
                Logger.Trace($"RequestCertificate Type={typeof(T).Name}");

                var resWriter = new StringWriter();
                var resSerializer = new XmlSerializer(typeof(RevokeCertificateBySerialNoResponse1));

                switch (typeof(T).Name)
                {
                    case "RequestCertificateStatusRequestType":
                        var certStatusResponse = Task.Run(async () =>
                            await quovadisClient.RequestCertificateStatusAsync(APIVersion.v1_0, ContentEncoding.UTF8,
                                signedRequest)).Result;
                        resSerializer.Serialize(resWriter, certStatusResponse);
                        Logger.Trace("RequestCertificateStatusAsync Response : " + resWriter);
                        return (TR)Convert.ChangeType(certStatusResponse, typeof(TR));
                    case "RequestSSLCertStatusRequestType":
                        var sslCertStatusResponse = Task.Run(async () =>
                            await quovadisClient.RequestSSLCertStatusAsync(APIVersion.v1_0, ContentEncoding.UTF8,
                                signedRequest)).Result;
                        resSerializer.Serialize(resWriter, sslCertStatusResponse);
                        Logger.Trace("RequestSSLCertStatusRequestType Response : " + resWriter);
                        return (TR)Convert.ChangeType(sslCertStatusResponse, typeof(TR));
                    case "RetrieveCertificateRequestType":
                        var certRetrieval = Task.Run(async () =>
                            await quovadisClient.RetrieveCertificateAsync(APIVersion.v1_0, ContentEncoding.UTF8,
                                signedRequest)).Result;
                        resSerializer.Serialize(resWriter, certRetrieval);
                        Logger.Trace("RetrieveCertificateRequestType Response : " + resWriter);
                        return (TR)Convert.ChangeType(certRetrieval, typeof(TR));
                    default: //make SSL Cert the default
                        var sslCertRetrieval = Task.Run(async () =>
                            await quovadisClient.RetrieveSSLCertAsync(APIVersion.v1_0, ContentEncoding.UTF8,
                                signedRequest)).Result;
                        resSerializer.Serialize(resWriter, sslCertRetrieval);
                        Logger.Trace("SSL Cert Response : " + resWriter);
                        return (TR)Convert.ChangeType(sslCertRetrieval, typeof(TR));
                }
            }
            catch (Exception e)
            {
                Logger.Error($"Error in RequestCertificate.RequestCertificate {e.Message}");
                throw;
            }
        }

        private T BuildRequest(string emailAddress, string account, string transactionId)
        {
            try
            {
                switch (typeof(T).Name)
                {
                    case "RequestCertificateStatusRequestType":
                        var a = new CertificateStatusAccountInfo
                        {
                            Name = account,
                            Organisation = account
                        };

                        var req = new RequestCertificateStatusRequestType
                        {
                            Account = a,
                            TransactionId = transactionId,
                            RequestPartyEmailAddress = emailAddress,
                            DateTime = DateTime.Now
                        };
                        return (T)Convert.ChangeType(req, typeof(T));
                    case "RequestSSLCertStatusRequestType":
                        var sslStatusAccount = new StatusAccountInfo
                        {
                            Name = account,
                            Organisation = account
                        };

                        var sslStatusResponse = new RequestSSLCertStatusRequestType
                        {
                            Account = sslStatusAccount,
                            TransactionId = transactionId,
                            SubscriberEmailAddress = emailAddress,
                            DateTime = DateTime.Now
                        };
                        return (T)Convert.ChangeType(sslStatusResponse, typeof(T));
                    case "RetrieveCertificateRequestType":
                        var certAccount = new RetrieveCertificateAccountInfo
                        {
                            Name = account,
                            Organisation = account
                        };
                        var certRequest = new RetrieveCertificateRequestType
                        {
                            Account = certAccount,
                            TransactionId = transactionId,
                            RequestPartyEmailAddress = emailAddress,
                            DateTime = DateTime.Now
                        };
                        return (T)Convert.ChangeType(certRequest, typeof(T));
                    default:
                        var sslCertAccount = new RetrieveAccountInfo
                        {
                            Name = account,
                            Organisation = account
                        };
                        var sslCertResponse = new RetrieveSSLCertRequestType
                        {
                            Account = sslCertAccount,
                            TransactionId = transactionId,
                            SubscriberEmailAddress = emailAddress,
                            DateTime = DateTime.Now
                        };
                        return (T)Convert.ChangeType(sslCertResponse, typeof(T));
                }
            }
            catch (Exception e)
            {
                Logger.Error($"Error in QuovadisCertificate.BuildRequest {e.Message}");
                throw;
            }
        }
    }
}
