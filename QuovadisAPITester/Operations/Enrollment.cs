using System;
using System.IO;
using System.ServiceModel;
using System.ServiceModel.Channels;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.Xml;
using System.Xml.Serialization;
using CAProxy.AnyGateway.Models;
using Keyfactor.AnyGateway.Quovadis.QuovadisClient;
using Org.BouncyCastle.Asn1.Pkcs;

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
                var ret = BuildRequestXml(tempXml, csr, enrollParams);
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
                return resWriter.ToString();
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
                throw;
            }

        }

        public static string BuildRequestXml(string templateXml, string csrString, EnrollmentProductInfo enrollParams)
        {
            using (TextReader sr = new StringReader(csrString))
            {
                var reader = new Org.BouncyCastle.OpenSsl.PemReader(sr);
                var req = reader.ReadObject() as Org.BouncyCastle.Pkcs.Pkcs10CertificationRequest;
                var csr = req?.GetCertificationRequestInfo();
                var finalXml = templateXml;

                XmlReader rdr = XmlReader.Create(new StringReader(templateXml));
                while (rdr.Read())
                {
                    if (rdr.NodeType == XmlNodeType.Element)
                    {
                        Console.WriteLine("Name: " + rdr.LocalName);
                    }
                    if (rdr.NodeType == XmlNodeType.Text)
                    {
                        Console.WriteLine("Value: " + rdr.Value);
                        var currentElementValue = rdr.Value;
                        var fieldValueArray = currentElementValue.Split('|');
                        if (fieldValueArray[0].ToUpper() == "ENROLLMENT" || fieldValueArray[0] == "DateTime.Now")
                        {
                            finalXml = finalXml.Replace(currentElementValue, currentElementValue == "DateTime.Now" ? DateTime.Now.ToString("yyyy-MM-ddTHH:mm:ssK") : enrollParams.ProductParameters[fieldValueArray[1]]);
                        }
                        else if (fieldValueArray[0].ToUpper() == "CSR")
                        {
                            var csrFieldValueArray = currentElementValue.Split('|');
                            if (csrFieldValueArray[1].ToUpper() == "RAW")
                            {
                                finalXml = finalXml.Replace(currentElementValue, csrString);
                            }
                            else
                            {
                                var csrValue = GetValueFromCsr(csrFieldValueArray, csr);
                                var pattern = @"\b" + currentElementValue.Replace("|", "\\|") + @"\b";
                                finalXml = Regex.Replace(finalXml, pattern, csrValue);
                            }
                        }
                    }

                }

                return finalXml;
            }

        }

        private static string GetValueFromCsr(string[] csrFieldValueArray, CertificationRequestInfo csr)
        {
            var csrVals = csr.Subject.ToString().Split(',');
            foreach (var val in csrVals)
            {
                var nmValPair = val.Split('=');

                if (csrFieldValueArray[1] == nmValPair[0])
                {
                    return nmValPair[1];
                }
            }

            return "";
        }
    }
}
