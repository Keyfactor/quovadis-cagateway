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
    [XmlRoot("RequestOrganisationRequestStatusResponse", Namespace="", IsNullable=false)]
    public partial class RequestOrganisationRequestStatusResponseType {
    
        private OrganisationRequestStatusResultType resultField;
    
        private OrganisationRequestStatusType statusField;
    
        private System.DateTime dateTimeField;
    
        private string errorCodeField;
    
        private string messageField;
    
        private string detailsField;
    
        /// <remarks/>
        [XmlElement(Form=System.Xml.Schema.XmlSchemaForm.Unqualified)]
        public OrganisationRequestStatusResultType Result {
            get {
                return this.resultField;
            }
            set {
                this.resultField = value;
            }
        }
    
        /// <remarks/>
        [XmlElement(Form=System.Xml.Schema.XmlSchemaForm.Unqualified)]
        public OrganisationRequestStatusType Status {
            get {
                return this.statusField;
            }
            set {
                this.statusField = value;
            }
        }
    
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
        public string ErrorCode {
            get {
                return this.errorCodeField;
            }
            set {
                this.errorCodeField = value;
            }
        }
    
        /// <remarks/>
        [XmlElement(Form=System.Xml.Schema.XmlSchemaForm.Unqualified)]
        public string Message {
            get {
                return this.messageField;
            }
            set {
                this.messageField = value;
            }
        }
    
        /// <remarks/>
        [XmlElement(Form=System.Xml.Schema.XmlSchemaForm.Unqualified)]
        public string Details {
            get {
                return this.detailsField;
            }
            set {
                this.detailsField = value;
            }
        }
    }

    /// <remarks/>
    [System.CodeDom.Compiler.GeneratedCodeAttribute("xsd", "4.6.1590.0")]
    [System.SerializableAttribute()]
    public enum OrganisationRequestStatusResultType {
    
        /// <remarks/>
        Success,
    
        /// <remarks/>
        Failure,
    }

    /// <remarks/>
    [System.CodeDom.Compiler.GeneratedCodeAttribute("xsd", "4.6.1590.0")]
    [System.SerializableAttribute()]
    public enum OrganisationRequestStatusType {
    
        /// <remarks/>
        Unspecified,
    
        /// <remarks/>
        Pending,
    
        /// <remarks/>
        Approved,
    
        /// <remarks/>
        Rejected,
    }
}