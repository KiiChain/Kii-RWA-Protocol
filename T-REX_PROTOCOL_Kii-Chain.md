
# ![kii-chain-logo](logo.png)

# CW3643 — T-REX PROTOCOL on Kii-Chain

## Overview

This document outlines the detailed implementation plan for the T-REX (Token for Regulated Exchanges) protocol using CosmWasm smart contracts on Kii-Chain. The T-REX protocol is designed for compliant issuance and management of security tokens on blockchain networks.

---

## Contracts Overview

| Contract                       | Purpose                                                                                             | Connected with                        |
| ------------------------------ | --------------------------------------------------------------------------------------------------- | ------------------------------------- |
| CW20 Base                      | Holds an asset as a CW20 token                                                                      | Owner Roles, Compliance Registry      |
| Owner Roles                    | Registers owners and special permissions for addresses                                              | -                                     |
| Compliance Registry            | Stores compliance modules and verifies compliance for each module                                   | Compliance Whitelist Wrapper          |
| Compliance Whitelist Wrapper   | A wrapper for compliance modules that whitelists certain addresses, bypassing restrictions          | Compliance Country, Compliance Claims |
| Compliance Country Restriction | A sample compliance contract that denies identities from specific countries                         | On Chain ID                           |
| Compliance Claims              | Compliance module that denies token usage by users who do not have the required claims              | Claim Topics, On Chain ID             |
| On Chain ID Contract           | Registers user identities and allows delegated management of certain aspects on their behalf        | -                                     |
| Claim Topics                   | Stores address-to-trust-level mappings used to block or allow access to tokens; only changeable by a trusted issuer | Trusted Issuers             |
| Trusted Issuer                 | Maps special addresses authorized to change claims                                                  | -                                     |
| Agent Roles                    | *(Under Development)*                                                                               | -                                     |

---

## Action Flows

The relationship between contracts can appear complex at first glance, but together they create a system where asset usage is limited to only those approved by a trusted issuer. A trusted issuer can only approve users who have explicitly agreed to trust it.

### 1️⃣ New Asset

This flow illustrates the creation of a new asset. The asset will be limited to users who have the required claim trust level, which can only be assigned by the trusted issuer. The transfer of the asset uses a token pair as an intermediary, which is trusted for compliance checks for that specific token.

- Create a new **CW20 Base**.
- Set up a token pair with liquidity of Asset <> Kii.
- Link this token to the wrapped compliance modules in the **Compliance Registry** (any number of modules).  
  - The wrapper on a compliance module allows whitelisting of the token pair, so it can handle transfers without needing an identity.
  - This action must be performed by someone with the **Compliance Manager** role.
- Define a required claim for this token and a trust level in **Claim Topics**.
  - This must be performed by someone with the **Claim Manager** role.
- Whitelist the token pair address in each **Compliance Whitelist Wrapper** (one per compliance module).
  - This must be performed by someone with the **Compliance Manager** role.

### 2️⃣ User Registration

To interact with assets, a user must register an identity, designate a trusted issuer, and receive a specific trust level from that issuer.

- User creates its own identity on the **On Chain ID** contract.
- User allows the trusted issuer to manage its claims via the **On Chain ID** contract.
- Trusted issuer issues a specific trust level for the user in the **Claim Topics** contract.

### 3️⃣ First Purchase

The purchase will be conducted via a liquidity pool that handles pricing. The user must be registered and hold a valid trust level beforehand.

- User buys the token from the liquidity pool.
- The liquidity pool transfers the asset directly to the buyer via the **CW20 Base** contract of the T-REX token.

---

## Contracts and Their Methods

### 1. CW20 T-REX Token

Extends the CW20 standard with T-REX functionalities and implements permissioned transfers.

**Storage**
- `token_info`: TokenInfo — Name, symbol, decimals, supply, optional minter (with address and optional cap)
- `balances`: Map<Addr, Uint128>
- `allowances`: Map<(Addr, Addr), AllowanceInfo> — includes allowance amount and expiration
- `identity_registry`: Addr
- `compliance`: Addr

**Execute**
- `transfer(recipient: Addr, amount: Uint128) -> Result<Response>`  
  Transfers tokens to a recipient if they are verified and compliant. Calls `is_verified` on the Identity Registry and `can_transfer` on the Modular Compliance module.

- `transfer_from(owner: Addr, recipient: Addr, amount: Uint128) -> Result<Response>`  
  Transfers tokens on behalf of the owner if the recipient is verified and compliant.

- `send(contract: Addr, amount: Uint128, msg: Binary) -> Result<Response>`  
  Sends tokens to another contract with an attached message payload.

- `burn(amount: Uint128) -> Result<Response>`  
  Burns tokens.

- `mint(contract: Addr, amount: Uint128) -> Result<Response>`  
  Mints new tokens (if minter is configured).

- `increase_allowance/decrease_allowance` — Adjust allowance and expiration.

**Query**
- `balance(address: Addr) -> BalanceResponse`
- `token_info() -> TokenInfoResponse`
- `is_verified_transfer(from: Addr, to: Addr, amount: Uint128) -> IsVerifiedTransferResponse`  
  Checks if a transfer would succeed without executing it.

### 2. Identity Registry

Manages investor identities and eligibility.

**Storage**
- `identity_storage`: Addr
- `trusted_issuers_registry`: Addr
- `claim_topics_registry`: Addr
- `agents`: Vec<Addr>

**Execute**
- `register_identity(address: Addr, identity: Addr) -> Result<Response>`
- `update_identity(address: Addr, identity: Addr) -> Result<Response>`
- `remove_identity(address: Addr) -> Result<Response>`

**Query**
- `is_verified(address: Addr) -> IsVerifiedResponse`

### 3. Identity Registry Storage

Stores the mapping of wallet addresses to identity contracts.

**Storage**
- `identities`: Map<Addr, Addr>

**Execute**
- `add_identity(address: Addr, identity: Addr) -> Result<Response>`
- `remove_identity(address: Addr) -> Result<Response>`

**Query**
- `get_identity(address: Addr) -> GetIdentityResponse`

### 4. Trusted Issuers Registry

Manages the list of trusted claim issuers. Only an `OwnerRole::IssuersRegistryManager` can modify trusted issuers.

**Storage**
- `trusted_issuers`: Map<Addr, TrustedIssuer>

**Execute**
- `add_trusted_issuer(issuer: Addr, claim_topics: Vec<u32>) -> Result<Response>`
- `remove_trusted_issuer(issuer: Addr) -> Result<Response>`

**Query**
- `is_trusted_issuer(issuer: Addr) -> IsTrustedIssuerResponse`
- `get_trusted_issuers() -> GetTrustedIssuersResponse`

### 5. Claim Topics Registry

Stores required claim topics for token eligibility. Managed by `OwnerRole::ClaimRegistryManager`.

**Storage**
- `token_claim_topics`: Vec<u32>

**Execute**
- `add_claim_topic(topic: u32) -> Result<Response>`
- `remove_claim_topic(topic: u32) -> Result<Response>`

**Query**
- `get_claims_for_token() -> StdResult<Vec<Uint128>>`

### 6. Modular Compliance

Implements transfer restriction rules. Managed by `OwnerRole::ComplianceManager`.

**Storage**
- `modules`: Vec<Addr>
- `bound_tokens`: Vec<Addr>

**Execute**
- `add_module(module: Addr) -> Result<Response>`
- `remove_module(module: Addr) -> Result<Response>`
- `bind_token(token: Addr) -> Result<Response>`

**Query**
- `can_transfer(from: Addr, to: Addr, amount: Uint128) -> CanTransferResponse`

### 7. On Chain ID

Represents user identities (similar to ERC-734/735).

**Storage**
- `keys`: Map<bytes32, Key>
- `claims`: Map<bytes32, Claim>

**Execute**
- `add_key(key: bytes32, purpose: u32, key_type: u32) -> Result<Response>`
- `remove_key(key: bytes32) -> Result<Response>`
- `add_claim(topic: u32, scheme: u32, issuer: Addr, signature: Vec<u8>, data: Vec<u8>, uri: String) -> Result<Response>`
- `remove_claim(topic: u32) -> Result<Response>`

**Query**
- `get_key(key: bytes32) -> GetKeyResponse`
- `get_claim(topic: u32) -> GetClaimResponse`

### 8. T-REX Factory

Deploys and configures T-REX token suites.

**Storage**
- `implementation_authority`: Addr
- `deployed_tokens`: Vec<Addr>

**Execute**
- `deploy_token_suite(token_info: TokenInfo, compliance_info: ComplianceInfo, identity_info: IdentityInfo) -> Result<Response>`  
  Deploys a new T-REX token suite and configures it.

**Query**
- `get_deployed_tokens() -> GetDeployedTokensResponse`

### 9. Implementation Authority

Manages contract upgrades and versioning.

**Storage**
- `versions`: Map<String, ContractVersion>
- `current_version`: String

**Execute**
- `add_version(name: String, contracts: Vec<(String, Addr)>) -> Result<Response>`
- `set_current_version(name: String) -> Result<Response>`

**Query**
- `get_current_version() -> GetCurrentVersionResponse`
- `get_version(name: String) -> GetVersionResponse`

---

## Implementation Roadmap

1. Implement CW20 T-REX Token  
2. Implement Identity Registry and Identity Registry Storage  
3. Implement Trusted Issuers Registry and Claim Topics Registry  
4. Implement Modular Compliance  
5. Implement On Chain ID  
6. Implement T-REX Factory  
7. Implement Implementation Authority  
8. Integrate all contracts and perform thorough testing  
9. Conduct security audit  
10. Deploy to Kii-Chain testnet  
11. Perform final testing and adjustments  
12. Deploy to Kii-Chain mainnet

## Testing Strategy

- Implement unit tests for each contract function.
- Develop integration tests for contract interactions.
- Create end-to-end scenarios to test the complete T-REX suite.
- Perform fuzz testing to uncover edge cases.
- Conduct governance testing to ensure proper access control.
