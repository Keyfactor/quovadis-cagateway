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
    [XmlRoot("RetrieveCertificateRequest", Namespace="", IsNullable=false)]
    public partial class RetrieveCertificateRequestType {
    
        private System.DateTime dateTimeField;
    
        private string requestPartyEmailAddressField;
    
        private RetrieveCertificateAccountInfo accountField;
    
        private string transactionIdField;
    
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
        public string RequestPartyEmailAddress {
            get {
                return this.requestPartyEmailAddressField;
            }
            set {
                this.requestPartyEmailAddressField = value;
            }
        }
    
        /// <remarks/>
        [XmlElement(Form=System.Xml.Schema.XmlSchemaForm.Unqualified)]
        public RetrieveCertificateAccountInfo Account {
            get {
                return this.accountField;
            }
            set {
                this.accountField = value;
            }
        }
    
        /// <remarks/>
        [XmlElement(Form=System.Xml.Schema.XmlSchemaForm.Unqualified)]
        public string TransactionId {
            get {
                return this.transactionIdField;
            }
            set {
                this.transactionIdField = value;
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
    public partial class RetrieveCertificateAccountInfo {
    
        private string nameField;
    
        private string organisationField;
    
        private string organisationGuidField;
    
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
    
        /// <remarks/>
        [XmlElement(Form=System.Xml.Schema.XmlSchemaForm.Unqualified)]
        public string OrganisationGuid {
            get {
                return this.organisationGuidField;
            }
            set {
                this.organisationGuidField = value;
            }
        }
    }
}