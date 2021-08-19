using System;
using System.IO;
using System.ServiceModel;
using System.ServiceModel.Channels;
using System.Threading.Tasks;
using System.Xml;
using System.Xml.Serialization;
using CAProxy.AnyGateway.Models;
using CSS.Common.Logging;
using Keyfactor.AnyGateway.Quovadis.Client.XSDs;
using Keyfactor.AnyGateway.Quovadis.QuovadisClient;

namespace Keyfactor.AnyGateway.Quovadis.Client.Operations
{
    public class Renewal:LoggingClientBase
    {
        private readonly string baseUrl;
        private readonly string wsSigningCertDir;
        private readonly string wsSigningCertPwd;

        public Renewal(string baseUrl, string wsSigningCertDir, string wsSigningCertPwd)
        {
            this.baseUrl = baseUrl;
            this.wsSigningCertDir = wsSigningCertDir;
            this.wsSigningCertPwd = wsSigningCertPwd;
        }

        public async Task<RenewSSLCertResponse1> RenewCertificate(string tempXml, string csr, EnrollmentProductInfo enrollParams,
            string transactionId)
        {
            try
            {
                Logger.Debug("Entering Renew Certificate Method");
                var renewRequest = Utilities.BuildRequestXml(tempXml, csr, enrollParams, true);
                Logger.Trace($"Renew Request Generated Xml {renewRequest}");

                var renewDoc = new XmlDocument();
                renewDoc.LoadXml(renewRequest);
                var elem = renewDoc.CreateElement("TransactionId");
                elem.InnerText = transactionId;
                renewDoc.LastChild.AppendChild(elem);
                var certFields = renewDoc.SelectSingleNode("//CertFields");
                certFields?.ParentNode?.RemoveChild(certFields);

                Logger.Trace($"Renew Request Modified Xml {renewDoc.OuterXml}");

                RenewSSLCertRequestType renewRequestObj;
                var deSerializer = new XmlSerializer(typeof(RenewSSLCertRequestType));
                using (TextReader reader = new StringReader(renewDoc.OuterXml))
                {
                    renewRequestObj = (RenewSSLCertRequestType)deSerializer.Deserialize(reader);
                }

                var reqWriter = new StringWriter();
                var reqSerializer = new XmlSerializer(typeof(RenewSSLCertRequestType));

                reqSerializer.Serialize(reqWriter, renewRequestObj);
                Logger.Trace($"Serialized Renew Request {reqWriter}");

                var x = new XmlSerializer(renewRequestObj.GetType());
                byte[] bytes;
                using (var stream = new MemoryStream())
                {
                    x.Serialize(stream, renewRequestObj);
                    bytes = stream.ToArray();
                }

                Binding bind = new BasicHttpsBinding();
                var ep = new EndpointAddress(baseUrl);
                var quovadisClient = new CertificateServicesSoapClient(bind, ep);

                var signedRequest = Utilities.BuildSignedCmsStructure(wsSigningCertDir, wsSigningCertPwd, bytes);


                Logger.Trace($"Signed Renew Request Xml {signedRequest}");

                var response = Task.Run(async () =>
                    await quovadisClient.RenewSSLCertAsync(APIVersion.v1_0, ContentEncoding.UTF8,
                        signedRequest)).Result;

                var resWriter = new StringWriter();
                var serializer = new XmlSerializer(typeof(RenewSSLCertResponse1));

                serializer.Serialize(resWriter, response);
                Logger.Trace($"Final Renew Response {resWriter}");


                return response;
            }
            catch (Exception e)
            {
                Logger.Error($"An Error Occurred in Renew Certificate: {e.Message}");
                throw;
            }
         
        }
    }
}
