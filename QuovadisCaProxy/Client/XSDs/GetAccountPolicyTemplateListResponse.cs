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
    [XmlRoot("GetAccountPolicyTemplateListResponse", Namespace="", IsNullable=false)]
    public partial class GetAccountPolicyTemplateListResponseType {
    
        private ResultType resultField;
    
        private System.DateTime dateTimeField;
    
        private string errorCodeField;
    
        private string messageField;
    
        private string detailsField;
    
        private PolicyTemplateList[] policyTemplatesField;
    
        /// <remarks/>
        [XmlElement(Form=System.Xml.Schema.XmlSchemaForm.Unqualified)]
        public ResultType Result {
            get {
                return this.resultField;
            }
            set {
                this.resultField = value;
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
    
        /// <remarks/>
        [XmlArray(Form=System.Xml.Schema.XmlSchemaForm.Unqualified)]
        [XmlArrayItem("PolicyTemplate", Form=System.Xml.Schema.XmlSchemaForm.Unqualified, IsNullable=false)]
        public PolicyTemplateList[] PolicyTemplates {
            get {
                return this.policyTemplatesField;
            }
            set {
                this.policyTemplatesField = value;
            }
        }
    }


    /// <remarks/>
    [System.CodeDom.Compiler.GeneratedCodeAttribute("xsd", "4.6.1590.0")]
    [System.SerializableAttribute()]
    [System.Diagnostics.DebuggerStepThroughAttribute()]
    [System.ComponentModel.DesignerCategoryAttribute("code")]
    public partial class PolicyTemplateList {
    
        private string nameField;
    
        private string systemTemplateField;
    
        private string pTIDField;
    
        private string typeField;
    
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
        public string SystemTemplate {
            get {
                return this.systemTemplateField;
            }
            set {
                this.systemTemplateField = value;
            }
        }
    
        /// <remarks/>
        [XmlElement(Form=System.Xml.Schema.XmlSchemaForm.Unqualified)]
        public string PTID {
            get {
                return this.pTIDField;
            }
            set {
                this.pTIDField = value;
            }
        }
    
        /// <remarks/>
        [XmlElement(Form=System.Xml.Schema.XmlSchemaForm.Unqualified)]
        public string Type {
            get {
                return this.typeField;
            }
            set {
                this.typeField = value;
            }
        }
    }
}