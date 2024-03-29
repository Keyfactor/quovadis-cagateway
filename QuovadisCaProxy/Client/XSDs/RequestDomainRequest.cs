﻿//------------------------------------------------------------------------------
// <auto-generated>
//     This code was generated by a tool.
//     Runtime Version:4.0.30319.42000
//
//     Changes to this file may cause incorrect behavior and will be lost if
//     the code is regenerated.
// </auto-generated>
//------------------------------------------------------------------------------

using System.Xml.Serialization;

namespace Keyfactor.AnyGateway.Quovadis.Client.XSDs
{
    // 
// This source code was auto-generated by xsd, Version=4.6.1590.0.
// 


    /// <remarks/>
    [System.CodeDom.Compiler.GeneratedCodeAttribute("xsd", "4.6.1590.0")]
    [System.SerializableAttribute()]
    [System.Diagnostics.DebuggerStepThroughAttribute()]
    [System.ComponentModel.DesignerCategoryAttribute("code")]
    [XmlRoot("RequestDomainRequestRequest", Namespace="", IsNullable=false)]
    public partial class RequestDomainRequestType {
    
        private System.DateTime dateTimeField;
    
        private string administratorEmailAddressField;
    
        private RequestDomainRequestAccountInfo accountField;
    
        private string domainField;
    
        private bool isSSLField;
    
        private bool isEndUserField;
    
        private bool isEVField;
    
        private DomainRequestDomainType domainTypeField;
    
        private bool testField;
    
        private bool testFieldSpecified;
    
        /// <remarks/>
        [XmlElement(Form=System.Xml.Schema.XmlSchemaForm.Unqualified)]
        public System.DateTime DateTime {
            get {
                return this.dateTimeField;
            }
            set {
                this.dateTimeField = value;
            }
        }
    
        /// <remarks/>
        [XmlElement(Form=System.Xml.Schema.XmlSchemaForm.Unqualified)]
        public string AdministratorEmailAddress {
            get {
                return this.administratorEmailAddressField;
            }
            set {
                this.administratorEmailAddressField = value;
            }
        }
    
        /// <remarks/>
        [XmlElement(Form=System.Xml.Schema.XmlSchemaForm.Unqualified)]
        public RequestDomainRequestAccountInfo Account {
            get {
                return this.accountField;
            }
            set {
                this.accountField = value;
            }
        }
    
        /// <remarks/>
        [XmlElement(Form=System.Xml.Schema.XmlSchemaForm.Unqualified)]
        public string Domain {
            get {
                return this.domainField;
            }
            set {
                this.domainField = value;
            }
        }
    
        /// <remarks/>
        [XmlElement(Form=System.Xml.Schema.XmlSchemaForm.Unqualified)]
        public bool IsSSL {
            get {
                return this.isSSLField;
            }
            set {
                this.isSSLField = value;
            }
        }
    
        /// <remarks/>
        [XmlElement(Form=System.Xml.Schema.XmlSchemaForm.Unqualified)]
        public bool IsEndUser {
            get {
                return this.isEndUserField;
            }
            set {
                this.isEndUserField = value;
            }
        }
    
        /// <remarks/>
        [XmlElement(Form=System.Xml.Schema.XmlSchemaForm.Unqualified)]
        public bool IsEV {
            get {
                return this.isEVField;
            }
            set {
                this.isEVField = value;
            }
        }
    
        /// <remarks/>
        [XmlElement(Form=System.Xml.Schema.XmlSchemaForm.Unqualified)]
        public DomainRequestDomainType DomainType {
            get {
                return this.domainTypeField;
            }
            set {
                this.domainTypeField = value;
            }
        }
    
        /// <remarks/>
        [XmlElement(Form=System.Xml.Schema.XmlSchemaForm.Unqualified)]
        public bool Test {
            get {
                return this.testField;
            }
            set {
                this.testField = value;
            }
        }
    
        /// <remarks/>
        [XmlIgnore()]
        public bool TestSpecified {
            get {
                return this.testFieldSpecified;
            }
            set {
                this.testFieldSpecified = value;
            }
        }
    }

    /// <remarks/>
    [System.CodeDom.Compiler.GeneratedCodeAttribute("xsd", "4.6.1590.0")]
    [System.SerializableAttribute()]
    [System.Diagnostics.DebuggerStepThroughAttribute()]
    [System.ComponentModel.DesignerCategoryAttribute("code")]
    public partial class RequestDomainRequestAccountInfo {
    
        private string nameField;
    
        private string organisationField;
    
        /// <remarks/>
        [XmlElement(Form=System.Xml.Schema.XmlSchemaForm.Unqualified)]
        public string Name {
            get {
                return this.nameField;
            }
            set {
                this.nameField = value;
            }
        }
    
        /// <remarks/>
        [XmlElement(Form=System.Xml.Schema.XmlSchemaForm.Unqualified)]
        public string Organisation {
            get {
                return this.organisationField;
            }
            set {
                this.organisationField = value;
            }
        }
    }

    /// <remarks/>
    [System.CodeDom.Compiler.GeneratedCodeAttribute("xsd", "4.6.1590.0")]
    [System.SerializableAttribute()]
    public enum DomainRequestDomainType {
    
        /// <remarks/>
        domain,
    
        /// <remarks/>
        ipAddress,
    }
}