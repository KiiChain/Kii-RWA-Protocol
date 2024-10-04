use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use cosmwasm_std::{Addr, Binary, Uint256};

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct Identity {
    pub address: Addr,
    pub keys: Vec<Key>,
    pub claims: Vec<Claim>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct Key {
    pub purpose: KeyPurpose,
    pub key: Binary,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct Claim {
    topic: ClaimTopic,
    issuer: Addr,
    signature: Binary,
    data: Binary,
    uri: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
enum KeyPurpose {

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
enum ClaimTopic {

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