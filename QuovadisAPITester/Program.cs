using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using System.ServiceModel;
using System.ServiceModel.Channels;
using System.Text;
using System.Threading.Tasks;
using System.Xml;
using System.Xml.Serialization;
using Keyfactor.AnyGateway.Quovadis.QuovadisClient;

namespace QuovadisAPITester
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.Write("Enter Function (GetTemplates , InitiateInvite):");
            var input = Console.ReadLine();
            switch (input)
            {
                case "GetTemplates":
                    Console.Write(TestGetTemplates());
                    break;
                case "InitiateInvite":
                    Console.Write(TestInitiateInvite());
                    break;
            }

            Console.Read();
        }

        public static string TestGetTemplates()
        {
            GetAccountPolicyTemplateListRequestType tr = new GetAccountPolicyTemplateListRequestType();
            tr.Account = "KeyFactor";
            tr.DateTime=DateTime.Now;
            tr.Test = true;


            var x = new XmlSerializer(tr.GetType());
            byte[] bytes;
            using (MemoryStream stream = new MemoryStream())
            {
                x.Serialize(stream, tr);
                bytes = stream.ToArray();
            }

            Binding bind = new BasicHttpsBinding();
            EndpointAddress ep = new EndpointAddress("https://tlclientdev.quovadisglobal.com/ws/CertificateServices.asmx");
            var quovadisClient = new CertificateServicesSoapClient(bind, ep);

            var signedRequest = BuildSignedCmsStructure("C:\\Users\\bhill\\source\\repos\\Quovadis-AnyGateway\\QuovadisAPITester\\QV_Webservices_KeyFactor.p12", "Keyfactor2019!", bytes);

            var templatesResponse = Task.Run(async () =>
                await quovadisClient.GetAccountPolicyTemplateListAsync(APIVersion.v2_0, ContentEncoding.UTF8,
                    signedRequest)).Result;

            System.IO.StringWriter writer = new System.IO.StringWriter();
            System.Xml.Serialization.XmlSerializer serializer = new System.Xml.Serialization.XmlSerializer(typeof(GetAccountPolicyTemplateListResponse1));
            serializer.Serialize(writer, templatesResponse);
            return writer.ToString();
        }


        public static string TestInitiateInvite()
        {

            InitiateInviteRequestType ii = new InitiateInviteRequestType();
            InviteAccountInfo account = new InviteAccountInfo();
            CertContentFieldsType cf=new CertContentFieldsType();
            RegistrantInfoType rf=new RegistrantInfoType();
            ii.AdministratorEmailAddress = "brian.hill@keyfactor.com";
            rf.ConfirmPassword = "Password12!";
            rf.Password = "Password12!";
            //rf.FirstName = "Brian";
            //rf.LastName = "Hill";
            //rf.Email = "brian@boingy.com";
            //rf.PrimaryPhone = "4444441141";
            cf.CN = "testcert";
            cf.C = "US";
            cf.O = "KeyFactor";
            cf.OU = new string[]{"IT Department"};
            //cf.E = "admin@boingy.com";
            account.Name = "KeyFactor";
            account.Organisation = "KeyFactor";
            ii.Account = account;
            ii.DateTime = DateTime.Now;
            //ii.Test = true;
            ii.TemplateId = 2166;
            ii.RegistrantInfo = rf;
            ii.CertContentFields = cf;
            ii.ValidityPeriod = 1;

            var x = new XmlSerializer(ii.GetType());
            byte[] bytes;
            using (MemoryStream stream = new MemoryStream())
            {
                x.Serialize(stream, ii);
                bytes = stream.ToArray();
            }

            //var baseUrl = "https://tlclientdev.quovadisglobal.com/ws/CertificateServices.asmx";
            Binding bind = new BasicHttpsBinding();
            EndpointAddress ep = new EndpointAddress("https://tlclientdev.quovadisglobal.com/ws/CertificateServices.asmx");
            var quovadisClient = new CertificateServicesSoapClient(bind, ep);

            var signedRequest = BuildSignedCmsStructure("C:\\Users\\bhill\\source\\repos\\Quovadis-AnyGateway\\QuovadisAPITester\\QV_Webservices_KeyFactor.p12", "Keyfactor2019!", bytes);

            var initiateResponse = Task.Run(async () =>
                await quovadisClient.InitiateInviteAsync(APIVersion.v2_0, ContentEncoding.UTF8,
                    signedRequest)).Result;

            System.IO.StringWriter writer = new System.IO.StringWriter();
            System.Xml.Serialization.XmlSerializer serializer = new System.Xml.Serialization.XmlSerializer(typeof(InitiateInviteResponse1));
            serializer.Serialize(writer, initiateResponse);
            return writer.ToString();
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
            byte[] signedStructure = signedCms.Encode();
            var encodedText = Convert.ToBase64String(signedStructure);
            return encodedText;
        }
    }
}
