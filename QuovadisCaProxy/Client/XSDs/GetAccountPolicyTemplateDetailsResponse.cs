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
    [XmlRoot("GetAccountPolicyTemplateDetailsResponse", Namespace="", IsNullable=false)]
    public partial class GetAccountPolicyTemplateDetailsResponseType {
    
        private ResultType resultField;
    
        private System.DateTime dateTimeField;
    
        private string errorCodeField;
    
        private string messageField;
    
        private string detailsField;
    
        private PolicyTemplateDetailList[] policyTemplateDetailsField;
    
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
        [XmlArrayItem("PolicyTemplateDetail", Form=System.Xml.Schema.XmlSchemaForm.Unqualified, IsNullable=false)]
        public PolicyTemplateDetailList[] PolicyTemplateDetails {
            get {
                return this.policyTemplateDetailsField;
            }
            set {
                this.policyTemplateDetailsField = value;
            }
        }
    }


    /// <remarks/>
    [System.CodeDom.Compiler.GeneratedCodeAttribute("xsd", "4.6.1590.0")]
    [System.SerializableAttribute()]
    [System.Diagnostics.DebuggerStepThroughAttribute()]
    [System.ComponentModel.DesignerCategoryAttribute("code")]
    public partial class PolicyTemplateDetailList {
    
        private string fieldNameField;
    
        private string templateCaptionField;
    
        private string defaultValueField;
    
        private bool requiredField;
    
        private bool editableField;
    
        private bool fromOrgField;
    
        /// <remarks/>
        [XmlElement(Form=System.Xml.Schema.XmlSchemaForm.Unqualified)]
        public string FieldName {
            get {
                return this.fieldNameField;
            }
            set {
                this.fieldNameField = value;
            }
        }
    
        /// <remarks/>
        [XmlElement(Form=System.Xml.Schema.XmlSchemaForm.Unqualified)]
        public string TemplateCaption {
            get {
                return this.templateCaptionField;
            }
            set {
                this.templateCaptionField = value;
            }
        }
    
        /// <remarks/>
        [XmlElement(Form=System.Xml.Schema.XmlSchemaForm.Unqualified)]
        public string DefaultValue {
            get {
                return this.defaultValueField;
            }
            set {
                this.defaultValueField = value;
            }
        }
    
        /// <remarks/>
        [XmlElement(Form=System.Xml.Schema.XmlSchemaForm.Unqualified)]
        public bool Required {
            get {
                return this.requiredField;
            }
            set {
                this.requiredField = value;
            }
        }
    
        /// <remarks/>
        [XmlElement(Form=System.Xml.Schema.XmlSchemaForm.Unqualified)]
        public bool Editable {
            get {
                return this.editableField;
            }
            set {
                this.editableField = value;
            }
        }
    
        /// <remarks/>
        [XmlElement(Form=System.Xml.Schema.XmlSchemaForm.Unqualified)]
        public bool FromOrg {
            get {
                return this.fromOrgField;
            }
            set {
                this.fromOrgField = value;
            }
        }
    }
}