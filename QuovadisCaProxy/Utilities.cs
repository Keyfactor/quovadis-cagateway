﻿using System;
using System.IO;
using System.Reflection;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.RegularExpressions;
using System.Xml;
using CAProxy.AnyGateway;
using CAProxy.AnyGateway.Interfaces;
using CAProxy.AnyGateway.Models;
using CSS.PKI;
using Keyfactor.AnyGateway.Quovadis.QuovadisClient;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Pkcs;
using ContentInfo = System.Security.Cryptography.Pkcs.ContentInfo;

namespace Keyfactor.AnyGateway.Quovadis
{
    public static class Utilities
    {
        public static Func<string, string> Pemify = ss =>
            ss.Length <= 64 ? ss : ss.Substring(0, 64) + "\n" + Pemify(ss.Substring(64));

        public static string GetGatewayConnection(ICertificateDataReader cdr)
        {
            var baseType = cdr.GetType();
            var field = baseType.GetField("a", BindingFlags.NonPublic | BindingFlags.Instance);

            return ((DatabaseConfigurationProvider) field?.GetValue(cdr))?.ConnectionString;
        }

        public static string BuildSignedCmsStructure(string p12FileLocation, string p12Password, byte[] dataToSign)
        {
            //Retrieve web service signing certificate
            X509Certificate2 signingCert = null;
            var cert2Collection = new X509Certificate2Collection();
            cert2Collection.Import(p12FileLocation, p12Password, X509KeyStorageFlags.Exportable);
            foreach (var cert in cert2Collection)
            {
                if (!cert.HasPrivateKey) continue;
                signingCert = cert;
            }

            //Generate signed CMS payload
            var contentInfo = new ContentInfo(dataToSign);
            var signedCms = new SignedCms(contentInfo);
            var cmsSigner = new CmsSigner(signingCert);
            signedCms.ComputeSignature(cmsSigner);
            //Create base64 encoded signed CMS payload
            var signedStructure = signedCms.Encode();
            var encodedText = Convert.ToBase64String(signedStructure);
            return encodedText;
        }

        public static string AddSerialNumberDashes(string s, char c, int n)
        {
            var sb = new StringBuilder(s.Length + s.Length % n + 1);
            for (var i = 1; i <= s.Length; ++i)
            {
                sb.Append(s[i - 1]);
                if (i % n == 0) sb.Append(c);
            }

            return sb.ToString();
        }

        public static string GetValueFromCsr(string[] csrFieldValueArray, CertificationRequestInfo csr)
        {
            var csrVals = csr.Subject.ToString().Split(',');
            foreach (var val in csrVals)
            {
                var nmValPair = val.Split('=');

                if (csrFieldValueArray[1] == nmValPair[0]) return nmValPair[1];
            }

            return "";
        }


        public static string BuildRequestXml(string templateXml, string csrString, EnrollmentProductInfo enrollParams,
            bool isRenewal)
        {
            var pemCert = Pemify(csrString);
            pemCert = "-----BEGIN CERTIFICATE REQUEST-----\n" + pemCert;
            pemCert += "\n-----END CERTIFICATE REQUEST-----";

            using (TextReader sr = new StringReader(pemCert))
            {
                var reader = new PemReader(sr);
                var req = reader.ReadObject() as Pkcs10CertificationRequest;
                var csr = req?.GetCertificationRequestInfo();
                var finalXml = templateXml;

                var rdr = XmlReader.Create(new StringReader(templateXml));
                while (rdr.Read())
                {
                    if (rdr.NodeType == XmlNodeType.Element) Console.WriteLine("Name: " + rdr.LocalName);
                    if (rdr.NodeType == XmlNodeType.Text)
                    {
                        Console.WriteLine("Value: " + rdr.Value);
                        var currentElementValue = rdr.Value;
                        var fieldValueArray = currentElementValue.Split('|');
                        if (fieldValueArray[0].ToUpper() == "ENROLLMENT" || fieldValueArray[0] == "DateTime.Now")
                        {
                            finalXml = finalXml.Replace(currentElementValue,
                                currentElementValue == "DateTime.Now"
                                    ? DateTime.Now.ToString("yyyy-MM-ddTHH:mm:ssK")
                                    : enrollParams.ProductParameters[fieldValueArray[1]]);
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

                if (isRenewal)
                    finalXml = finalXml.Replace("RequestSSLCertRequest", "RenewSSLCertRequest");
                return finalXml;
            }
        }

        public static int MapKeyfactorCertStatus(CertificateStatusType status)
        {
            switch (status)
            {
                case CertificateStatusType.Revoked:
                    return (int) PKIConstants.Microsoft.RequestDisposition.REVOKED;
                case CertificateStatusType.Valid:
                    return (int) PKIConstants.Microsoft.RequestDisposition.ISSUED;
                default:
                    return (int) PKIConstants.Microsoft.RequestDisposition.UNKNOWN;
            }
        }

        public static int MapKeyfactorSslStatus(StatusType status)
        {
            switch (status)
            {
                case StatusType.Revoked:
                    return (int) PKIConstants.Microsoft.RequestDisposition.REVOKED;
                case StatusType.Valid:
                    return (int) PKIConstants.Microsoft.RequestDisposition.ISSUED;
                default:
                    return (int) PKIConstants.Microsoft.RequestDisposition.UNKNOWN;
            }
        }
    }
}