using System;
using System.IO;
using System.ServiceModel;
using System.ServiceModel.Channels;
using System.Threading.Tasks;
using System.Xml.Serialization;
using Keyfactor.AnyGateway.Quovadis.Client.XSDs;
using Keyfactor.AnyGateway.Quovadis.QuovadisClient;

namespace QuovadisAPITester.Operations
{
    public class Templates
    {
        private readonly string baseUrl;
        private readonly string wsSigningCertDir;
        private readonly string wsSigningCertPwd;

        public Templates(string baseUrl, string wsSigningCertDir, string wsSigningCertPwd)
        {
            this.baseUrl = baseUrl;
            this.wsSigningCertDir = wsSigningCertDir;
            this.wsSigningCertPwd = wsSigningCertPwd;
        }

        public string TestGetTemplates()
        {
            var tr = new GetAccountPolicyTemplateListRequestType
            {
                Account = "KeyFactor",
                DateTime = DateTime.Now,
                Test = false
            };

            var x = new XmlSerializer(tr.GetType());
            byte[] bytes;
            using (var stream = new MemoryStream())
            {
                x.Serialize(stream, tr);
                bytes = stream.ToArray();
            }

            Binding bind = new BasicHttpsBinding();
            var ep = new EndpointAddress(baseUrl);
            var quovadisClient = new CertificateServicesSoapClient(bind, ep);

            var signedRequest = Utilities.BuildSignedCmsStructure(wsSigningCertDir, wsSigningCertPwd, bytes);

            var templatesResponse = Task.Run(async () =>
                await quovadisClient.GetAccountPolicyTemplateListAsync(APIVersion.v2_0, ContentEncoding.UTF8,
                    signedRequest)).Result;

            var writer = new StringWriter();
            var serializer = new XmlSerializer(typeof(GetAccountPolicyTemplateListResponse1));
            serializer.Serialize(writer, templatesResponse);
            return writer.ToString();
        }
    }
}