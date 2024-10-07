use cw_storage_plus::{Item, Map};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use cosmwasm_std::{Addr, Binary};
use crate::error::ContractError;

//Addr being the Key owner
pub const KEYS: Map<&Addr, Vec<Key>> = Map::new("keys");

//Addr being the Identity owner
pub const CLAIMS: Map<&Addr, Vec<Claim>> = Map::new("claims");

//Addr being the Owner of the Identity (not to be confused with the Key owner)
pub const OWNER: Item<Addr> = Item::new("owner");

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct Key {
    pub owner: Addr,
    pub key_type: KeyType,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct Claim {
    pub id: Option<String>,
    pub topic: ClaimTopic,
    pub issuer: Addr,
    pub signature: Binary,
    pub data: Binary,
    pub uri: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub enum KeyType {

    // 1: MANAGEMENT keys, which can manage the identity
    ManagementKey,

    // 2: EXECUTION keys, which perform actions in this identities name (signing, logins, transactions, etc.)
    ExecutionKey,

    // 3: CLAIM signer keys, used to sign claims on other identities which need to be revokable.
    ClaimSignerKey,
    
    // 4: ENCRYPTION keys, used to encrypt data e.g. hold in claims.
    EncryptionKey
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub enum ClaimTopic {

    // You're a person and not a business
    BiometricTopic,


    // You have a physical address or reference point
    ResidenceTopic,

    RegistryTopic,

    // TODO: social media profiles, blogs, etc.
    ProfileTopic,

    // TODO: real name, business name, nick name, brand name, alias, etc.
    LabelTopic
}

impl KeyType {
    pub fn from_str(s: &str) -> Result<Self, ContractError> {
        match s {
            "ManagementKey" => Ok(KeyType::ManagementKey),
            "ExecutionKey" => Ok(KeyType::ExecutionKey),
            "ClaimSignerKey" => Ok(KeyType::ClaimSignerKey),
            "EncryptionKey" => Ok(KeyType::EncryptionKey),
            _ => Err(ContractError::InvalidKeyPurpose {}),
        }
    }

    pub fn to_string(&self) -> String {
        match self {
            KeyType::ManagementKey => "ManagementKey".to_string(),
            KeyType::ExecutionKey => "ExecutionKey".to_string(),
            KeyType::ClaimSignerKey => "ClaimSignerKey".to_string(),
            KeyType::EncryptionKey => "EncryptionKey".to_string(),
        }
    }
}

impl ClaimTopic {
    pub fn from_str(s: &str) -> Result<Self, ContractError> {
        match s {
            "BiometricTopic" => Ok(ClaimTopic::BiometricTopic),
            "ResidenceTopic" => Ok(ClaimTopic::ResidenceTopic),
            "RegistryTopic" => Ok(ClaimTopic::RegistryTopic),
            "ProfileTopic" => Ok(ClaimTopic::ProfileTopic),
            "LabelTopic" => Ok(ClaimTopic::LabelTopic),
            _ => Err(ContractError::InvalidClaimTopic {}),
        }
    }

    pub fn to_string(&self) -> String {
        match self {
            ClaimTopic::BiometricTopic => "BiometricTopic".to_string(),
            ClaimTopic::ResidenceTopic => "ResidenceTopic".to_string(),
            ClaimTopic::RegistryTopic => "RegistryTopic".to_string(),
            ClaimTopic::ProfileTopic => "ProfileTopic".to_string(),
            ClaimTopic::LabelTopic => "LabelTopic".to_string(),
        }
    }
}