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

// 
// This source code was auto-generated by xsd, Version=4.6.1590.0.
// 


/// <remarks/>
[System.CodeDom.Compiler.GeneratedCodeAttribute("xsd", "4.6.1590.0")]
[System.SerializableAttribute()]
[System.Diagnostics.DebuggerStepThroughAttribute()]
[System.ComponentModel.DesignerCategoryAttribute("code")]
[System.Xml.Serialization.XmlRootAttribute("InitiateInviteRequest", Namespace="", IsNullable=false)]
public partial class InitiateInviteRequestType {
    
    private System.DateTime dateTimeField;
    
    private string administratorEmailAddressField;
    
    private int validityPeriodField;
    
    private bool validityPeriodFieldSpecified;
    
    private int templateIdField;
    
    private CertContentFieldsType certContentFieldsField;
    
    private string cSRField;
    
    private RegistrantInfoType registrantInfoField;
    
    private InviteAccountInfo accountField;
    
    private KeyValuePair[] customFieldsField;
    
    private string commentsField;
    
    private bool testField;
    
    private bool testFieldSpecified;
    
    /// <remarks/>
    [System.Xml.Serialization.XmlElementAttribute(Form=System.Xml.Schema.XmlSchemaForm.Unqualified)]
    public System.DateTime DateTime {
        get {
            return this.dateTimeField;
        }
        set {
            this.dateTimeField = value;
        }
    }
    
    /// <remarks/>
    [System.Xml.Serialization.XmlElementAttribute(Form=System.Xml.Schema.XmlSchemaForm.Unqualified)]
    public string AdministratorEmailAddress {
        get {
            return this.administratorEmailAddressField;
        }
        set {
            this.administratorEmailAddressField = value;
        }
    }
    
    /// <remarks/>
    [System.Xml.Serialization.XmlElementAttribute(Form=System.Xml.Schema.XmlSchemaForm.Unqualified)]
    public int ValidityPeriod {
        get {
            return this.validityPeriodField;
        }
        set {
            this.validityPeriodField = value;
        }
    }
    
    /// <remarks/>
    [System.Xml.Serialization.XmlIgnoreAttribute()]
    public bool ValidityPeriodSpecified {
        get {
            return this.validityPeriodFieldSpecified;
        }
        set {
            this.validityPeriodFieldSpecified = value;
        }
    }
    
    /// <remarks/>
    [System.Xml.Serialization.XmlElementAttribute(Form=System.Xml.Schema.XmlSchemaForm.Unqualified)]
    public int TemplateId {
        get {
            return this.templateIdField;
        }
        set {
            this.templateIdField = value;
        }
    }
    
    /// <remarks/>
    [System.Xml.Serialization.XmlElementAttribute(Form=System.Xml.Schema.XmlSchemaForm.Unqualified)]
    public CertContentFieldsType CertContentFields {
        get {
            return this.certContentFieldsField;
        }
        set {
            this.certContentFieldsField = value;
        }
    }
    
    /// <remarks/>
    [System.Xml.Serialization.XmlElementAttribute(Form=System.Xml.Schema.XmlSchemaForm.Unqualified)]
    public string CSR {
        get {
            return this.cSRField;
        }
        set {
            this.cSRField = value;
        }
    }
    
    /// <remarks/>
    [System.Xml.Serialization.XmlElementAttribute(Form=System.Xml.Schema.XmlSchemaForm.Unqualified)]
    public RegistrantInfoType RegistrantInfo {
        get {
            return this.registrantInfoField;
        }
        set {
            this.registrantInfoField = value;
        }
    }
    
    /// <remarks/>
    [System.Xml.Serialization.XmlElementAttribute(Form=System.Xml.Schema.XmlSchemaForm.Unqualified)]
    public InviteAccountInfo Account {
        get {
            return this.accountField;
        }
        set {
            this.accountField = value;
        }
    }
    
    /// <remarks/>
    [System.Xml.Serialization.XmlArrayAttribute(Form=System.Xml.Schema.XmlSchemaForm.Unqualified)]
    [System.Xml.Serialization.XmlArrayItemAttribute("Item", Form=System.Xml.Schema.XmlSchemaForm.Unqualified, IsNullable=false)]
    public KeyValuePair[] CustomFields {
        get {
            return this.customFieldsField;
        }
        set {
            this.customFieldsField = value;
        }
    }
    
    /// <remarks/>
    [System.Xml.Serialization.XmlElementAttribute(Form=System.Xml.Schema.XmlSchemaForm.Unqualified)]
    public string Comments {
        get {
            return this.commentsField;
        }
        set {
            this.commentsField = value;
        }
    }
    
    /// <remarks/>
    [System.Xml.Serialization.XmlElementAttribute(Form=System.Xml.Schema.XmlSchemaForm.Unqualified)]
    public bool Test {
        get {
            return this.testField;
        }
        set {
            this.testField = value;
        }
    }
    
    /// <remarks/>
    [System.Xml.Serialization.XmlIgnoreAttribute()]
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
public partial class CertContentFieldsType {
    
    private string cnField;
    
    private string snField;
    
    private string sNOField;
    
    private string cField;
    
    private string lField;
    
    private string sField;
    
    private string saField;
    
    private string oField;
    
    private string[] ouField;
    
    private string tField;
    
    private string paField;
    
    private string pcField;
    
    private string tnField;
    
    private string gnField;
    
    private string iField;
    
    private string gqField;
    
    private string dNQField;
    
    private string pField;
    
    private string eField;
    
    private string unField;
    
    private string uaField;
    
    private string uIDField;
    
    private string[] dcField;
    
    private string dField;
    
    private string oiField;
    
    private InviteSANField[] sANField;
    
    private string mSCTIField;
    
    private string mSCTNField;
    
    private string mSAPField;
    
    /// <remarks/>
    [System.Xml.Serialization.XmlElementAttribute(Form=System.Xml.Schema.XmlSchemaForm.Unqualified)]
    public string CN {
        get {
            return this.cnField;
        }
        set {
            this.cnField = value;
        }
    }
    
    /// <remarks/>
    [System.Xml.Serialization.XmlElementAttribute(Form=System.Xml.Schema.XmlSchemaForm.Unqualified)]
    public string SN {
        get {
            return this.snField;
        }
        set {
            this.snField = value;
        }
    }
    
    /// <remarks/>
    [System.Xml.Serialization.XmlElementAttribute(Form=System.Xml.Schema.XmlSchemaForm.Unqualified)]
    public string SNO {
        get {
            return this.sNOField;
        }
        set {
            this.sNOField = value;
        }
    }
    
    /// <remarks/>
    [System.Xml.Serialization.XmlElementAttribute(Form=System.Xml.Schema.XmlSchemaForm.Unqualified)]
    public string C {
        get {
            return this.cField;
        }
        set {
            this.cField = value;
        }
    }
    
    /// <remarks/>
    [System.Xml.Serialization.XmlElementAttribute(Form=System.Xml.Schema.XmlSchemaForm.Unqualified)]
    public string L {
        get {
            return this.lField;
        }
        set {
            this.lField = value;
        }
    }
    
    /// <remarks/>
    [System.Xml.Serialization.XmlElementAttribute(Form=System.Xml.Schema.XmlSchemaForm.Unqualified)]
    public string S {
        get {
            return this.sField;
        }
        set {
            this.sField = value;
        }
    }
    
    /// <remarks/>
    [System.Xml.Serialization.XmlElementAttribute(Form=System.Xml.Schema.XmlSchemaForm.Unqualified)]
    public string SA {
        get {
            return this.saField;
        }
        set {
            this.saField = value;
        }
    }
    
    /// <remarks/>
    [System.Xml.Serialization.XmlElementAttribute(Form=System.Xml.Schema.XmlSchemaForm.Unqualified)]
    public string O {
        get {
            return this.oField;
        }
        set {
            this.oField = value;
        }
    }
    
    /// <remarks/>
    [System.Xml.Serialization.XmlArrayAttribute(Form=System.Xml.Schema.XmlSchemaForm.Unqualified)]
    [System.Xml.Serialization.XmlArrayItemAttribute("Field", Form=System.Xml.Schema.XmlSchemaForm.Unqualified, IsNullable=false)]
    public string[] OU {
        get {
            return this.ouField;
        }
        set {
            this.ouField = value;
        }
    }
    
    /// <remarks/>
    [System.Xml.Serialization.XmlElementAttribute(Form=System.Xml.Schema.XmlSchemaForm.Unqualified)]
    public string T {
        get {
            return this.tField;
        }
        set {
            this.tField = value;
        }
    }
    
    /// <remarks/>
    [System.Xml.Serialization.XmlElementAttribute(Form=System.Xml.Schema.XmlSchemaForm.Unqualified)]
    public string PA {
        get {
            return this.paField;
        }
        set {
            this.paField = value;
        }
    }
    
    /// <remarks/>
    [System.Xml.Serialization.XmlElementAttribute(Form=System.Xml.Schema.XmlSchemaForm.Unqualified)]
    public string PC {
        get {
            return this.pcField;
        }
        set {
            this.pcField = value;
        }
    }
    
    /// <remarks/>
    [System.Xml.Serialization.XmlElementAttribute(Form=System.Xml.Schema.XmlSchemaForm.Unqualified)]
    public string TN {
        get {
            return this.tnField;
        }
        set {
            this.tnField = value;
        }
    }
    
    /// <remarks/>
    [System.Xml.Serialization.XmlElementAttribute(Form=System.Xml.Schema.XmlSchemaForm.Unqualified)]
    public string GN {
        get {
            return this.gnField;
        }
        set {
            this.gnField = value;
        }
    }
    
    /// <remarks/>
    [System.Xml.Serialization.XmlElementAttribute(Form=System.Xml.Schema.XmlSchemaForm.Unqualified)]
    public string I {
        get {
            return this.iField;
        }
        set {
            this.iField = value;
        }
    }
    
    /// <remarks/>
    [System.Xml.Serialization.XmlElementAttribute(Form=System.Xml.Schema.XmlSchemaForm.Unqualified)]
    public string GQ {
        get {
            return this.gqField;
        }
        set {
            this.gqField = value;
        }
    }
    
    /// <remarks/>
    [System.Xml.Serialization.XmlElementAttribute(Form=System.Xml.Schema.XmlSchemaForm.Unqualified)]
    public string DNQ {
        get {
            return this.dNQField;
        }
        set {
            this.dNQField = value;
        }
    }
    
    /// <remarks/>
    [System.Xml.Serialization.XmlElementAttribute(Form=System.Xml.Schema.XmlSchemaForm.Unqualified)]
    public string P {
        get {
            return this.pField;
        }
        set {
            this.pField = value;
        }
    }
    
    /// <remarks/>
    [System.Xml.Serialization.XmlElementAttribute(Form=System.Xml.Schema.XmlSchemaForm.Unqualified)]
    public string E {
        get {
            return this.eField;
        }
        set {
            this.eField = value;
        }
    }
    
    /// <remarks/>
    [System.Xml.Serialization.XmlElementAttribute(Form=System.Xml.Schema.XmlSchemaForm.Unqualified)]
    public string UN {
        get {
            return this.unField;
        }
        set {
            this.unField = value;
        }
    }
    
    /// <remarks/>
    [System.Xml.Serialization.XmlElementAttribute(Form=System.Xml.Schema.XmlSchemaForm.Unqualified)]
    public string UA {
        get {
            return this.uaField;
        }
        set {
            this.uaField = value;
        }
    }
    
    /// <remarks/>
    [System.Xml.Serialization.XmlElementAttribute(Form=System.Xml.Schema.XmlSchemaForm.Unqualified)]
    public string UID {
        get {
            return this.uIDField;
        }
        set {
            this.uIDField = value;
        }
    }
    
    /// <remarks/>
    [System.Xml.Serialization.XmlArrayAttribute(Form=System.Xml.Schema.XmlSchemaForm.Unqualified)]
    [System.Xml.Serialization.XmlArrayItemAttribute("Field", Form=System.Xml.Schema.XmlSchemaForm.Unqualified, IsNullable=false)]
    public string[] DC {
        get {
            return this.dcField;
        }
        set {
            this.dcField = value;
        }
    }
    
    /// <remarks/>
    [System.Xml.Serialization.XmlElementAttribute(Form=System.Xml.Schema.XmlSchemaForm.Unqualified)]
    public string D {
        get {
            return this.dField;
        }
        set {
            this.dField = value;
        }
    }
    
    /// <remarks/>
    [System.Xml.Serialization.XmlElementAttribute(Form=System.Xml.Schema.XmlSchemaForm.Unqualified)]
    public string OI {
        get {
            return this.oiField;
        }
        set {
            this.oiField = value;
        }
    }
    
    /// <remarks/>
    [System.Xml.Serialization.XmlArrayAttribute(Form=System.Xml.Schema.XmlSchemaForm.Unqualified)]
    [System.Xml.Serialization.XmlArrayItemAttribute("Field", Form=System.Xml.Schema.XmlSchemaForm.Unqualified, IsNullable=false)]
    public InviteSANField[] SAN {
        get {
            return this.sANField;
        }
        set {
            this.sANField = value;
        }
    }
    
    /// <remarks/>
    [System.Xml.Serialization.XmlElementAttribute(Form=System.Xml.Schema.XmlSchemaForm.Unqualified)]
    public string MSCTI {
        get {
            return this.mSCTIField;
        }
        set {
            this.mSCTIField = value;
        }
    }
    
    /// <remarks/>
    [System.Xml.Serialization.XmlElementAttribute(Form=System.Xml.Schema.XmlSchemaForm.Unqualified)]
    public string MSCTN {
        get {
            return this.mSCTNField;
        }
        set {
            this.mSCTNField = value;
        }
    }
    
    /// <remarks/>
    [System.Xml.Serialization.XmlElementAttribute(Form=System.Xml.Schema.XmlSchemaForm.Unqualified)]
    public string MSAP {
        get {
            return this.mSAPField;
        }
        set {
            this.mSAPField = value;
        }
    }
}

/// <remarks/>
[System.CodeDom.Compiler.GeneratedCodeAttribute("xsd", "4.6.1590.0")]
[System.SerializableAttribute()]
[System.Diagnostics.DebuggerStepThroughAttribute()]
[System.ComponentModel.DesignerCategoryAttribute("code")]
public partial class InviteSANField {
    
    private InviteSANFieldType typeField;
    
    private string valueField;
    
    /// <remarks/>
    [System.Xml.Serialization.XmlElementAttribute(Form=System.Xml.Schema.XmlSchemaForm.Unqualified)]
    public InviteSANFieldType Type {
        get {
            return this.typeField;
        }
        set {
            this.typeField = value;
        }
    }
    
    /// <remarks/>
    [System.Xml.Serialization.XmlElementAttribute(Form=System.Xml.Schema.XmlSchemaForm.Unqualified)]
    public string Value {
        get {
            return this.valueField;
        }
        set {
            this.valueField = value;
        }
    }
}

/// <remarks/>
[System.CodeDom.Compiler.GeneratedCodeAttribute("xsd", "4.6.1590.0")]
[System.SerializableAttribute()]
public enum InviteSANFieldType {
    
    /// <remarks/>
    Rfc822Name,
    
    /// <remarks/>
    UPN,
    
    /// <remarks/>
    Guid,
    
    /// <remarks/>
    Uri,
}

/// <remarks/>
[System.CodeDom.Compiler.GeneratedCodeAttribute("xsd", "4.6.1590.0")]
[System.SerializableAttribute()]
[System.Diagnostics.DebuggerStepThroughAttribute()]
[System.ComponentModel.DesignerCategoryAttribute("code")]
public partial class KeyValuePair {
    
    private string keyField;
    
    private string valueField;
    
    /// <remarks/>
    [System.Xml.Serialization.XmlElementAttribute(Form=System.Xml.Schema.XmlSchemaForm.Unqualified)]
    public string Key {
        get {
            return this.keyField;
        }
        set {
            this.keyField = value;
        }
    }
    
    /// <remarks/>
    [System.Xml.Serialization.XmlElementAttribute(Form=System.Xml.Schema.XmlSchemaForm.Unqualified)]
    public string Value {
        get {
            return this.valueField;
        }
        set {
            this.valueField = value;
        }
    }
}

/// <remarks/>
[System.CodeDom.Compiler.GeneratedCodeAttribute("xsd", "4.6.1590.0")]
[System.SerializableAttribute()]
[System.Diagnostics.DebuggerStepThroughAttribute()]
[System.ComponentModel.DesignerCategoryAttribute("code")]
public partial class InviteAccountInfo {
    
    private string nameField;
    
    private string organisationField;
    
    private string organisationGuidField;
    
    /// <remarks/>
    [System.Xml.Serialization.XmlElementAttribute(Form=System.Xml.Schema.XmlSchemaForm.Unqualified)]
    public string Name {
        get {
            return this.nameField;
        }
        set {
            this.nameField = value;
        }
    }
    
    /// <remarks/>
    [System.Xml.Serialization.XmlElementAttribute(Form=System.Xml.Schema.XmlSchemaForm.Unqualified)]
    public string Organisation {
        get {
            return this.organisationField;
        }
        set {
            this.organisationField = value;
        }
    }
    
    /// <remarks/>
    [System.Xml.Serialization.XmlElementAttribute(Form=System.Xml.Schema.XmlSchemaForm.Unqualified)]
    public string OrganisationGuid {
        get {
            return this.organisationGuidField;
        }
        set {
            this.organisationGuidField = value;
        }
    }
}

/// <remarks/>
[System.CodeDom.Compiler.GeneratedCodeAttribute("xsd", "4.6.1590.0")]
[System.SerializableAttribute()]
[System.Diagnostics.DebuggerStepThroughAttribute()]
[System.ComponentModel.DesignerCategoryAttribute("code")]
public partial class RegistrantInfoType {
    
    private string firstNameField;
    
    private string lastNameField;
    
    private string emailField;
    
    private string primaryPhoneField;
    
    private string secondaryPhoneField;
    
    private IDTypeAuditedType iDTypeAuditedField;
    
    private string thirdPartyEmailField;
    
    private SharedSecretOOBType sharedSecretOOBField;
    
    private bool sharedSecretOOBFieldSpecified;
    
    private string sharedSecretQuestionField;
    
    private string sharedSecretAnswerField;
    
    private string sharedSecretFormatField;
    
    private string passwordField;
    
    private string confirmPasswordField;
    
    /// <remarks/>
    [System.Xml.Serialization.XmlElementAttribute(Form=System.Xml.Schema.XmlSchemaForm.Unqualified)]
    public string FirstName {
        get {
            return this.firstNameField;
        }
        set {
            this.firstNameField = value;
        }
    }
    
    /// <remarks/>
    [System.Xml.Serialization.XmlElementAttribute(Form=System.Xml.Schema.XmlSchemaForm.Unqualified)]
    public string LastName {
        get {
            return this.lastNameField;
        }
        set {
            this.lastNameField = value;
        }
    }
    
    /// <remarks/>
    [System.Xml.Serialization.XmlElementAttribute(Form=System.Xml.Schema.XmlSchemaForm.Unqualified)]
    public string Email {
        get {
            return this.emailField;
        }
        set {
            this.emailField = value;
        }
    }
    
    /// <remarks/>
    [System.Xml.Serialization.XmlElementAttribute(Form=System.Xml.Schema.XmlSchemaForm.Unqualified)]
    public string PrimaryPhone {
        get {
            return this.primaryPhoneField;
        }
        set {
            this.primaryPhoneField = value;
        }
    }
    
    /// <remarks/>
    [System.Xml.Serialization.XmlElementAttribute(Form=System.Xml.Schema.XmlSchemaForm.Unqualified)]
    public string SecondaryPhone {
        get {
            return this.secondaryPhoneField;
        }
        set {
            this.secondaryPhoneField = value;
        }
    }
    
    /// <remarks/>
    [System.Xml.Serialization.XmlElementAttribute(Form=System.Xml.Schema.XmlSchemaForm.Unqualified)]
    public IDTypeAuditedType IDTypeAudited {
        get {
            return this.iDTypeAuditedField;
        }
        set {
            this.iDTypeAuditedField = value;
        }
    }
    
    /// <remarks/>
    [System.Xml.Serialization.XmlElementAttribute(Form=System.Xml.Schema.XmlSchemaForm.Unqualified)]
    public string ThirdPartyEmail {
        get {
            return this.thirdPartyEmailField;
        }
        set {
            this.thirdPartyEmailField = value;
        }
    }
    
    /// <remarks/>
    [System.Xml.Serialization.XmlElementAttribute(Form=System.Xml.Schema.XmlSchemaForm.Unqualified)]
    public SharedSecretOOBType SharedSecretOOB {
        get {
            return this.sharedSecretOOBField;
        }
        set {
            this.sharedSecretOOBField = value;
        }
    }
    
    /// <remarks/>
    [System.Xml.Serialization.XmlIgnoreAttribute()]
    public bool SharedSecretOOBSpecified {
        get {
            return this.sharedSecretOOBFieldSpecified;
        }
        set {
            this.sharedSecretOOBFieldSpecified = value;
        }
    }
    
    /// <remarks/>
    [System.Xml.Serialization.XmlElementAttribute(Form=System.Xml.Schema.XmlSchemaForm.Unqualified)]
    public string SharedSecretQuestion {
        get {
            return this.sharedSecretQuestionField;
        }
        set {
            this.sharedSecretQuestionField = value;
        }
    }
    
    /// <remarks/>
    [System.Xml.Serialization.XmlElementAttribute(Form=System.Xml.Schema.XmlSchemaForm.Unqualified)]
    public string SharedSecretAnswer {
        get {
            return this.sharedSecretAnswerField;
        }
        set {
            this.sharedSecretAnswerField = value;
        }
    }
    
    /// <remarks/>
    [System.Xml.Serialization.XmlElementAttribute(Form=System.Xml.Schema.XmlSchemaForm.Unqualified)]
    public string SharedSecretFormat {
        get {
            return this.sharedSecretFormatField;
        }
        set {
            this.sharedSecretFormatField = value;
        }
    }
    
    /// <remarks/>
    [System.Xml.Serialization.XmlElementAttribute(Form=System.Xml.Schema.XmlSchemaForm.Unqualified)]
    public string Password {
        get {
            return this.passwordField;
        }
        set {
            this.passwordField = value;
        }
    }
    
    /// <remarks/>
    [System.Xml.Serialization.XmlElementAttribute(Form=System.Xml.Schema.XmlSchemaForm.Unqualified)]
    public string ConfirmPassword {
        get {
            return this.confirmPasswordField;
        }
        set {
            this.confirmPasswordField = value;
        }
    }
}

/// <remarks/>
[System.CodeDom.Compiler.GeneratedCodeAttribute("xsd", "4.6.1590.0")]
[System.SerializableAttribute()]
public enum IDTypeAuditedType {
    
    /// <remarks/>
    Client_KYC_Record,
    
    /// <remarks/>
    Driver_License,
    
    /// <remarks/>
    Employee_ID_Card,
    
    /// <remarks/>
    Government_Issued_ID_Card,
    
    /// <remarks/>
    Military_ID_Card,
    
    /// <remarks/>
    Passport,
    
    /// <remarks/>
    Voter_Registration_Card,
}

/// <remarks/>
[System.CodeDom.Compiler.GeneratedCodeAttribute("xsd", "4.6.1590.0")]
[System.SerializableAttribute()]
public enum SharedSecretOOBType {
    
    /// <remarks/>
    Yes,
    
    /// <remarks/>
    No,
}