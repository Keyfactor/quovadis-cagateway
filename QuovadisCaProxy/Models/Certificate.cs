using System;
using System.Collections.Generic;
using System.Xml.Serialization;

namespace Keyfactor.AnyGateway.Quovadis.Models
{
    [XmlRoot(ElementName = "Certificate")]
    public class Certificate
    {

        [XmlElement(ElementName = "Id")]
        public int Id { get; set; }

        [XmlElement(ElementName = "Status")]
        public int Status { get; set; }

        [XmlElement(ElementName = "CARequestId")]
        public string CaRequestId { get; set; }

        [XmlElement(ElementName = "SubmissionDate")]
        public DateTime SubmissionDate { get; set; }

        [XmlElement(ElementName = "RequestCN")]
        public string RequestCn { get; set; }

        [XmlElement(ElementName = "RequestSubject")]
        public string RequestSubject { get; set; }

        [XmlElement(ElementName = "Attribute")]
        public List<Attribute> Attribute { get; set; }
    }
}
