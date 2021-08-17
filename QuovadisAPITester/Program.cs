using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Keyfactor.AnyGateway.Quovadis.Client.XSDs;
using Keyfactor.AnyGateway.Quovadis.QuovadisClient;
using Newtonsoft.Json.Linq;
using QuovadisAPITester.Operations;
using CertificateStatusResultType = Keyfactor.AnyGateway.Quovadis.QuovadisClient.CertificateStatusResultType;
using CertificateStatusType = Keyfactor.AnyGateway.Quovadis.QuovadisClient.CertificateStatusType;
using StatusResultType = Keyfactor.AnyGateway.Quovadis.QuovadisClient.StatusResultType;
using StatusType = Keyfactor.AnyGateway.Quovadis.QuovadisClient.StatusType;

namespace QuovadisAPITester
{
    internal class Program
    {
        private static string BaseUrl { get; set; }
        private static string WebServiceSigningCertDir { get; set; }
        private static string WebServiceSigningCertPassword { get; set; }

        private static void Main()
        {
            JObject obj;
            using (var r = new StreamReader($"{Directory.GetCurrentDirectory()}\\SampleConfig.json"))
            {
                var json = r.ReadToEnd();
                obj = JObject.Parse(json);
            }

            BaseUrl = (obj["CAConnection"]?["BaseUrl"] ?? "").Value<string>();
            WebServiceSigningCertDir = (obj["CAConnection"]?["WebServiceSigningCertDir"] ?? "").Value<string>();
            WebServiceSigningCertPassword =
                (obj["CAConnection"]?["WebServiceSigningCertPassword"] ?? "").Value<string>();
            Console.WriteLine("Choose Function");
            Console.WriteLine("GetTemplates");
            Console.WriteLine("Enroll:TemplateId");
            Console.WriteLine("Download: TransactionId,emailAddress,Account,EnrollType");
            Console.WriteLine("Revoke:TransactionId,emailAddress,Account,EnrollType,RevokeReason");
            Console.WriteLine("Renew:TemplateId,TransactionId");

            var input = Console.ReadLine();

            if (input != null && input.Contains("Enroll"))
            {
                var templateId = Convert.ToInt32(input.Split(':')[1]);
                var productInfo = Utilities.GetEnrollmentParameters(templateId);
                var token = obj
                    .Descendants()
                    .OfType<JProperty>()
                    .First(p => p.Value.ToString() == templateId.ToString());

                var result = string.Empty;

                if (token.Parent != null)
                {
                    var enrollType = (token.Parent["Parameters"]?["EnrollmentType"] ?? "").Value<string>();
                    var tempXml = (token.Parent["Parameters"]?["EnrollmentTemplate"] ?? "").Value<string>();
                    var rdr = Utilities.GetTemplateCsr(templateId.ToString());
                    var csr = rdr.ReadToEnd();
                    if (enrollType == "SSLRequest")
                    {
                        var enrollment = new Enrollment<RequestSSLCertRequestType, RequestSSLCertResponse1>(BaseUrl,
                            WebServiceSigningCertDir, WebServiceSigningCertPassword);
                        result = enrollment.PerformEnrollment(tempXml, csr, productInfo);
                    }
                    else if (enrollType == "InitiateInviteRequest")
                    {
                        var enrollment = new Enrollment<InitiateInviteRequestType, InitiateInviteResponse1>(BaseUrl,
                            WebServiceSigningCertDir, WebServiceSigningCertPassword);
                        result = enrollment.PerformEnrollment(tempXml, csr, productInfo);
                    }
                }

                Console.Write(result);
            }
            else if (input != null && input.Contains("GetTemplates"))
            {
                var t = new Templates(BaseUrl, WebServiceSigningCertDir, WebServiceSigningCertPassword);
                Console.Write(t.TestGetTemplates());
            }
            else if (input != null && input.Contains("Download"))
            {
                var paramArray = input.Split(':')[1];
                var valArray = paramArray.Split(',');
                var transactionId = valArray[0];
                var emailAddress = valArray[1];
                var account = valArray[2];
                var enrollType = valArray[3];

                var actualCert = GetX509Certificate(enrollType, emailAddress, account, transactionId);
                Console.Write(actualCert.SubjectName);
            }
            else if (input != null && input.Contains("Revoke"))
            {
                var paramArray = input.Split(':')[1];
                var valArray = paramArray.Split(',');
                var transactionId = valArray[0];
                var emailAddress = valArray[1];
                var account = valArray[2];
                var enrollType = valArray[3];
                var revokeReason = valArray[4];

                var actualCert = GetX509Certificate(enrollType, emailAddress, account, transactionId);
                if (actualCert != null)
                {
                    var revoke = new Revocation(BaseUrl, WebServiceSigningCertDir, WebServiceSigningCertPassword);
                    //perform the revoke
                    Console.Write(revoke.RevokeCertificate(actualCert, account, revokeReason));
                }
            }
            else if (input != null && input.Contains("Renew"))
            {
                var paramArray = input.Split(':')[1];
                var valArray = paramArray.Split(',');
                var templateId = Convert.ToInt32(valArray[0]);
                var transactionId = valArray[1];
                var productInfo = Utilities.GetEnrollmentParameters(templateId);


                var token = obj
                    .Descendants()
                    .OfType<JProperty>()
                    .First(p => p.Value.ToString() == templateId.ToString());

                if (token.Parent != null)
                {
                    var tempXml = (token.Parent["Parameters"]?["EnrollmentTemplate"] ?? "").Value<string>();
                    var rdr = Utilities.GetTemplateCsr(templateId.ToString());

                    var renewal = new Renewal(BaseUrl, WebServiceSigningCertDir, WebServiceSigningCertPassword);
                    Console.Write(renewal.RenewCertificate(tempXml, rdr.ReadToEnd(), productInfo, transactionId));
                }
            }


            Console.ReadLine();
        }

        private static X509Certificate2 GetX509Certificate(string enrollType, string emailAddress, string account,
            string transactionId)
        {
            X509Certificate2 actualCert = null;

            if (enrollType == "SSL")
            {
                var certStatus =
                    new QuovadisCertificate<RequestSSLCertStatusRequestType, RequestSSLCertStatusResponse1>(BaseUrl,
                        WebServiceSigningCertDir, WebServiceSigningCertPassword);
                var certResponse = certStatus.RequestCertificate(emailAddress, account, transactionId);
                if (certResponse.RequestSSLCertStatusResponse.Status ==
                    StatusType.Valid &&
                    certResponse.RequestSSLCertStatusResponse.Result ==
                    StatusResultType.Success)
                {
                    var certResult =
                        new QuovadisCertificate<RetrieveSSLCertRequestType, RetrieveSSLCertResponse1>(BaseUrl,
                            WebServiceSigningCertDir, WebServiceSigningCertPassword);
                    var cert = certResult.RequestCertificate(emailAddress, account, transactionId);
                    var certString = cert.RetrieveSSLCertResponse.Certificate;
                    actualCert = new X509Certificate2(Encoding.ASCII.GetBytes(certString));
                }
            }
            else
            {
                var certStatus =
                    new QuovadisCertificate<RequestCertificateStatusRequestType, RequestCertificateStatusResponse1>(
                        BaseUrl,
                        WebServiceSigningCertDir, WebServiceSigningCertPassword);
                var certResponse = certStatus.RequestCertificate(emailAddress, account, transactionId);
                if (certResponse.RequestCertificateStatusResponse.Status ==
                    CertificateStatusType.Valid &&
                    certResponse.RequestCertificateStatusResponse.Result ==
                    CertificateStatusResultType.Success)
                {
                    var certResult =
                        new QuovadisCertificate<RetrieveCertificateRequestType, RetrieveCertificateResponse1>(BaseUrl,
                            WebServiceSigningCertDir, WebServiceSigningCertPassword);
                    var cert = certResult.RequestCertificate(emailAddress, account, transactionId);
                    var certString = cert.RetrieveCertificateResponse.Certificate;
                    actualCert = new X509Certificate2(Encoding.ASCII.GetBytes(certString));
                }
            }

            return actualCert;
        }
    }
}