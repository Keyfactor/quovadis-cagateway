using System;
using System.IO;
using System.ServiceModel;
using System.ServiceModel.Channels;
using System.Threading.Tasks;
using System.Xml;
using System.Xml.Serialization;
using CAProxy.AnyGateway.Models;
using Keyfactor.AnyGateway.Quovadis.Client.XSDs;
using Keyfactor.AnyGateway.Quovadis.QuovadisClient;

namespace QuovadisAPITester.Operations
{
    public class Renewal
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

        public string RenewCertificate(string tempXml, string csr, EnrollmentProductInfo enrollParams,
            string transactionId)
        {
            var renewRequest = Utilities.BuildRequestXml(tempXml, csr, enrollParams, true);

            var renewDoc = new XmlDocument();
            renewDoc.LoadXml(renewRequest);
            var elem = renewDoc.CreateElement("TransactionId");
            elem.InnerText = transactionId;
            renewDoc.LastChild.AppendChild(elem);
            var certFields = renewDoc.SelectSingleNode("//CertFields");
            certFields?.ParentNode?.RemoveChild(certFields);

            RenewSSLCertRequestType renewRequestObj;
            var deSerializer = new XmlSerializer(typeof(RenewSSLCertRequestType));
            using (TextReader reader = new StringReader(renewDoc.OuterXml))
            {
                renewRequestObj = (RenewSSLCertRequestType) deSerializer.Deserialize(reader);
            }

            var x = new XmlSerializer(renewRequestObj.GetType());
            byte[] bytes;
            using (var stream = new MemoryStream())
            {
                x.Serialize(stream, renewRequestObj);
                bytes = stream.ToArray();
            }

            Console.Write(renewDoc.OuterXml);

            Binding bind = new BasicHttpsBinding();
            var ep = new EndpointAddress(baseUrl);
            var quovadisClient = new CertificateServicesSoapClient(bind, ep);

            var signedRequest = Utilities.BuildSignedCmsStructure(wsSigningCertDir, wsSigningCertPwd, bytes);

            var response = Task.Run(async () =>
                await quovadisClient.RenewSSLCertAsync(APIVersion.v1_0, ContentEncoding.UTF8,
                    signedRequest)).Result;

            var reqWriter = new StringWriter();
            var reqSerializer = new XmlSerializer(renewRequestObj.GetType());
            reqSerializer.Serialize(reqWriter, renewRequestObj);

            var resWriter = new StringWriter();
            var serializer = new XmlSerializer(response.GetType());

            serializer.Serialize(resWriter, response);
            return "Request: " + reqWriter + " Response: " + resWriter;
        }
    }
}