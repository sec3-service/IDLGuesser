use serde::Serialize;

#[derive(Debug, Serialize, PartialEq)]
pub struct Idl {
    pub address: String,
    pub metadata: Metadata,
    pub instructions: Vec<InstructionInfo>,
    #[serde(default, skip_serializing_if = "is_default")]
    pub accounts: Vec<IDLAccount>,
    #[serde(default, skip_serializing_if = "is_default")]
    pub errors: Vec<IDLError>,
    #[serde(default, skip_serializing_if = "is_default")]
    pub types: Vec<IDLType>,
}

#[derive(Debug, Serialize, PartialEq)]
pub struct Metadata {
    pub name: String,
    pub version: String,
    pub spec: String,
    pub description: String,
}

#[derive(Debug, Serialize, PartialEq)]
pub struct IDLAccount {
    pub name: String,
    pub discriminator: [u8; 8],
}

#[derive(Debug, Serialize, PartialEq)]
pub struct IDLError {
    pub code: u32,
    pub name: String,
    pub msg: String,
}

#[derive(Debug, Serialize, PartialEq)]
pub struct IDLType {
    pub name: String,
    #[serde(rename = "type")]
    pub ty: InnerType,
}

#[derive(Debug, Serialize, PartialEq)]
pub struct InnerType {
    pub kind: String,
    pub fields: Vec<ArgMeta>,
}

#[derive(Debug, Serialize, PartialEq)]
pub struct InstructionInfo {
    pub name: String,
    pub discriminator: [u8; 8],
    pub accounts: Vec<AccountMeta>,
    pub args: Vec<ArgMeta>,
}

#[derive(Debug, Serialize, Clone, PartialEq)]
pub struct ArgMeta {
    pub name: String,
    #[serde(rename = "type")]
    pub ty: String,
}

#[derive(Debug, Serialize, Clone, PartialEq)]
pub struct AccountMeta {
    pub name: String,
    #[serde(skip_serializing_if = "is_false")]
    pub writable: bool,
    #[serde(skip_serializing_if = "is_false")]
    pub signer: bool,
}

fn is_default<T: Default + PartialEq>(it: &T) -> bool {
    *it == T::default()
}

fn is_false(b: &bool) -> bool {
    !b
}
