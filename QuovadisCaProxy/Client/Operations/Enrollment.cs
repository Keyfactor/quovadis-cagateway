using System;
using System.IO;
using System.ServiceModel;
using System.ServiceModel.Channels;
using System.Threading.Tasks;
using System.Xml.Serialization;
using CAProxy.AnyGateway.Models;
using Keyfactor.AnyGateway.Quovadis.QuovadisClient;
using CSS.Common.Logging;


namespace Keyfactor.AnyGateway.Quovadis.Client.Operations
{
    public class Enrollment<T, TR>: LoggingClientBase
    {
        private readonly string baseUrl;
        private readonly string wsSigningCertDir;
        private readonly string wsSigningCertPwd;

        public Enrollment(string baseUrl, string wsSigningCertDir, string wsSigningCertPwd)
        {
            this.baseUrl = baseUrl;
            this.wsSigningCertDir = wsSigningCertDir;
            this.wsSigningCertPwd = wsSigningCertPwd;
        }

        public TR PerformEnrollment(string tempXml, string csr, EnrollmentProductInfo enrollParams)
        {
            try
            {
                var ret = Utilities.BuildRequestXml(tempXml, csr, enrollParams, false);
                Logger.Trace($"Request Xml Built {ret}");
                TextReader txtRdr = new StringReader(ret);
                var mySerializer = new XmlSerializer(typeof(T));
                var req = (T)mySerializer.Deserialize(txtRdr);

                var x = new XmlSerializer(req.GetType());
                byte[] bytes;
                using (MemoryStream stream = new MemoryStream())
                {
                    x.Serialize(stream, req);
                    bytes = stream.ToArray();
                }

                Binding bind = new BasicHttpsBinding();
                EndpointAddress ep = new EndpointAddress(baseUrl);
                var quovadisClient = new CertificateServicesSoapClient(bind, ep);

                var signedRequest = Utilities.BuildSignedCmsStructure(wsSigningCertDir, wsSigningCertPwd, bytes);
                Logger.Trace($"Signed Enrollment Request {signedRequest}");
                object response = null;

                if (typeof(T).Name == "InitiateInviteRequestType")
                {
                    response = Task.Run(async () =>
                        await quovadisClient.InitiateInviteAsync(APIVersion.v2_0, ContentEncoding.UTF8,
                            signedRequest)).Result;
                }
                else if (typeof(T).Name == "RequestSSLCertRequestType")
                {
                    response = Task.Run(async () =>
                        await quovadisClient.RequestSSLCertAsync(APIVersion.v2_0, ContentEncoding.UTF8,
                            signedRequest)).Result;
                }

                var finalResponse = (TR) Convert.ChangeType(response, typeof(TR));
                
                var resWriter = new StringWriter();
                var serializer = new XmlSerializer(typeof(TR));

                serializer.Serialize(resWriter, finalResponse);
                Logger.Trace($"Final Response {resWriter}");
                
                return finalResponse;
            }
            catch (Exception e)
            {
                Logger.Error($"Error Occurred in Perform Enrollment: {e.Message}");
                throw;
            }

        }


    }
}
