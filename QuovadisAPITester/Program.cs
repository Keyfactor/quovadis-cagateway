using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Xml.Linq;
using Keyfactor.AnyGateway.Quovadis.QuovadisClient;
using Newtonsoft.Json.Linq;

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

            Console.Write("Enter Function (GetTemplates , Enroll:TemplateId):");

            var input = Console.ReadLine();

            if (input != null && input.Contains("Enroll"))
            {
                var templateId = input.Split(':')[1];
                var productInfo = Utilities.GetEnrollmentParameters(templateId);
                var token = obj
                    .Descendants()
                    .OfType<JProperty>()
                    .First(p => p.Value.ToString() == templateId);
                
                string result = string.Empty;

                if (token.Parent != null)
                {
                    var enrollType = (token.Parent["Parameters"]?["EnrollmentType"] ?? "").Value<string>();
                    var tempXml = (token.Parent["Parameters"]?["EnrollmentTemplate"] ?? "").Value<string>();
                    var rdr = Utilities.GetTemplateCsr(templateId);
                    var csr = rdr.ReadToEnd();
                    if (enrollType == "SSLRequest")
                    {
                        var enrollment = new Enrollment<RequestSSLCertRequestType, RequestSSLCertResponse1>(BaseUrl,
                            WebServiceSigningCertDir, WebServiceSigningCertPassword);
                        result=enrollment.PerformEnrollment(tempXml, csr, productInfo);
                    }
                    else if (enrollType == "InitiateInviteRequest")
                    {
                        var enrollment = new Enrollment<InitiateInviteRequestType, InitiateInviteResponse1>(BaseUrl,
                            WebServiceSigningCertDir, WebServiceSigningCertPassword);
                        result=enrollment.PerformEnrollment(tempXml, csr, productInfo);
                    }
                }
                Console.Write(result);
                XElement xElement=XElement.Parse(result);
                string transactionId = xElement.Descendants("TransactionId").FirstOrDefault()?.Value;
                File.AppendAllText($"{Directory.GetCurrentDirectory()}\\TransactionList.csv", transactionId + Environment.NewLine);

            }
            else if (input != null && input.Contains("GetTemplates"))
            {
                var t = new Templates(BaseUrl, WebServiceSigningCertDir, WebServiceSigningCertPassword);
                Console.Write(t.TestGetTemplates());
            }

            Console.ReadLine();
        }
    }
}