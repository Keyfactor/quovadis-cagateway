using System;
using System.IO;
using System.ServiceModel;
using System.ServiceModel.Channels;
using System.Threading.Tasks;
using System.Xml.Serialization;
using CAProxy.AnyGateway.Models;
using Keyfactor.AnyGateway.Quovadis.QuovadisClient;

namespace QuovadisAPITester.Operations
{
    public class Enrollment<T,TR>
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
        
        public string PerformEnrollment(string tempXml,string csr, EnrollmentProductInfo enrollParams)
        {
            try
            {
                var ret = Utilities.BuildRequestXml(tempXml, csr, enrollParams,false);
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

                StringWriter reqWriter = new StringWriter();
                var reqSerializer = new XmlSerializer(typeof(T));
                reqSerializer.Serialize(reqWriter, req);

                StringWriter resWriter = new StringWriter();
                var serializer = new XmlSerializer(typeof(TR));

                serializer.Serialize(resWriter, response ?? "");
                return "Request: " + reqWriter.ToString() + "Response: " + resWriter.ToString();
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
                throw;
            }

        }

      
    }
}
