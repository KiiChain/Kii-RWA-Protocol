use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use cosmwasm_std::Binary;

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
    pub key: Binary,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct Claim {
    id: String,
    topic: String,
    scheme: u8,
    issuer: String,
    signature: Binary,
    data: Binary,
    uri: String,
}