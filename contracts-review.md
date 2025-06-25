# General
## Deploy order
- OwnerRoles
- AgentRoles (weirdly not used by others)
- TrustedIssuers (needs owner roles)
- ClaimTopics (needs owner roles)
- OnChainId (needs trusted issuer)
- ComplianceRegistry (needs owner roles)
- ComplianceClaims (needs chainId, owner roles and claim topics)
- ComplianceCountry (needs chainId and owner roles)
- CWBase (needs compliance registry)

# Owner roles
- Stores owner, there is only a single one
- Adds verification if a specific address her a specific owner role
- Lets owner add other addresses with specific owner roles
- Stores compliance, issuer and claim registries
  - IssuersRegistryManagers can add/remove trusted issuers
  - ClaimRegistryManagers can add/remove topics
  - Looks like unfinished center hub

## Owner roles
```rust
pub enum OwnerRole {
    OwnerAdmin,
    RegistryAddressSetter,
    ComplianceSetter,
    ComplianceManager,
    ClaimRegistryManager,
    IssuersRegistryManager,
    TokenInfoManager,
}
```

# Agent roles
- Very similar to owner roles but with agent roles
  - Supply Modifiers can do mint/burn
  - Transfer manager can do transfer from
- Looks like unfinished center hub
- Has placeholder implementations
  - Is transfer allowed
  - can transfer
  - can receive
```rust
pub enum AgentRole {
    SupplyModifiers,
    Freezers,
    TransferManager,
    RecoveryAgents,
    ComplianceAgent,
    WhiteListManages,
    AgentAdmin,
}
```

# Trusted issuer
- Checks if an address is a trusted issuer
  - They are tied with a vector of claim topics
- OwnerRole::IssuersRegistryManager can change list

# on chain Identity
- Holds address, country, keys and claims for an identity
- ManagementKey can change stuff
- Needs to check if an user is trusted to allow changes to execute remove/add claims
  - Centralizes that
- I dont understand fully how to use this contract
  - Do a centralized trusted add other identities? They add themselves?

## Key types
- I dont quite get the key types
```rust
pub enum KeyType {
    // 1: MANAGEMENT keys, which can manage the identity
    ManagementKey,
    // 2: EXECUTION keys, which perform actions in this identities name (signing, logins, transactions, etc.)
    ExecutionKey,
    // 3: CLAIM signer keys, used to sign claims on other identities which need to be revokable.
    ClaimSignerKey,
    // 4: ENCRYPTION keys, used to encrypt data e.g. hold in claims.
    EncryptionKey,
}
```

# Compliance contracts
- Limit usage of a given contract
  - I.e restrict US for cw20

## Compliance Registry
- Handles compliance modules
  - When checking if compliant, checks every submodule for valid compliance
- Reqs owner roles
  - Only compliance manager can change stuff

## Compliance country restriction
- Restricts which countries comply
- Only compliance manager can add or remove restrictions
- Queries identities' country to check if valid
  - Utilizes a contract that holds identity addresses
  - OnChainId handles identities

## Compliance claims
- Restricts usage based on claim topics
- Only query to check claims and compliance
  - Compliance checks the claim topics

### Claim Topics
- Holds token address <> topic association
- Claims are a topic + active bool
- ClaimRegistryManager can change topics
- Something feels off, I didn't find out how to link a claim with an user
  - `I didn't quite get this`

# CW20 base
## Optionals
Full info: https://github.com/CosmWasm/cw-plus/blob/main/packages/cw20/README.md
- Mintable
  - Allows query of Minter
- Allowance
  - Allows query of allowance
- Enumerable
  - Allows queries of 'all'
- Marketing
  - Allows more metadata info (description, logo)
  - Download logo

## Compliance
- A token address is stored
- It is used to send a message to that address, to check compliance
  - Via smart wasm query
- On every burn, transfer, mint and sent
  - It checks if the from, to and amount complies

# Yet to Review
- Missing Executes of CW20
  - Just checked instantiate
- Usage test
