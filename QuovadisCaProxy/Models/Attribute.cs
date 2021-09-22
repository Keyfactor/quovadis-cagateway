using System.Xml.Serialization;

namespace Keyfactor.AnyGateway.Quovadis.Models
{
    [XmlRoot(ElementName = "Attribute")]
    public class Attribute
    {

        [XmlElement(ElementName = "AttributeKey")]
        public string AttributeKey { get; set; }

        [XmlElement(ElementName = "AttributeValue")]
        public string AttributeValue { get; set; }
    }
}
