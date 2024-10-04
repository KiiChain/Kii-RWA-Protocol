use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct Identity {
    pub address: String,
    pub keys: Vec<Key>,
    pub claims: Vec<Claim>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct Key {
    pub purpose: u64,
    pub key_type: u64,
    pub key: Vec<u8>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct Claim {
    pub topic: u64,
    pub scheme: u64,
    pub issuer: String,
    pub signature: Vec<u8>,
    pub data: Vec<u8>,
    pub uri: String,
}