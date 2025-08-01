![kii-chain-logo](logo.png)

# CW3643 – T-REX Protocol on Kii-Chain

## Overview

This document outlines the implementation plan for the T-REX (Token for Regulated Exchanges) protocol using CosmWasm smart contracts on Kii-Chain. T-REX enables compliant issuance and management of security tokens on blockchain networks.

---

## 1. Contract Architecture

| Contract                        | Purpose                                                                                          | Dependencies / Interactions            |
| ------------------------------ | ------------------------------------------------------------------------------------------------ | -------------------------------------- |
| CW20 Base                      | Standard token contract holding the asset                                                        | Owner Roles, Compliance Registry       |
| Owner Roles                    | Manages permissions and roles                                                                    | -                                      |
| Compliance Registry            | Stores and verifies compliance modules                                                           | Compliance Whitelist Wrapper           |
| Compliance Whitelist Wrapper   | Whitelists specific addresses (e.g., liquidity pools) to bypass compliance checks                | Compliance Modules                     |
| Country Restriction Module     | Denies access to identities from specific countries                                              | OnChainID                              |
| Claims Compliance Module       | Restricts users without necessary compliance claims                                               | Claim Topics, OnChainID                |
| OnChainID                      | Registers identities and manages claims and permissions                                          | -                                      |
| Claim Topics                   | Maps claim topics to access levels                                                               | Trusted Issuers                        |
| Trusted Issuers                | Entities trusted to issue claims                                                                 | -                                      |
| Agent Roles                    | [In progress]                                                                                     | -                                      |

---

## 2. Action Flows

### 2.1 – Creating a New Asset

1. Deploy a new CW20 token contract (`CW20 Base`).
2. Establish a liquidity pool (Asset <> Kii).
3. Link the token to wrapped compliance modules via the `Compliance Registry`.
4. Whitelist the liquidity pool in each `Compliance Whitelist Wrapper`.
5. Define trust level requirements for the token in the `Claim Topics` contract.

*Only users with the correct claim level issued by a trusted issuer will be able to use the token.*

---

### 2.2 – User Registration

1. User registers an identity on the `OnChainID` contract.
2. User grants permission to a trusted issuer to manage claims.
3. Trusted issuer issues claim(s) with the required trust level to the user.

---

### 2.3 – First Purchase

1. User buys the asset from the liquidity pool.
2. Liquidity pool transfers the asset to the user if the compliance conditions are met.

---

## 3. Contract Specifications

### 3.1 – CW20 T-REX Token

**Extends CW20 standard with compliance features**

- **Storage**
  - `token_info`, `balances`, `allowances`
  - `identity_registry`, `compliance`
- **Execute**
  - `transfer`, `transfer_from`, `send`, `burn`, `mint`
  - `increase_allowance`, `decrease_allowance`
- **Query**
  - `balance`, `token_info`, `is_verified_transfer`

---

### 3.2 – Identity Registry

**Manages investor identities and permissions**

- Register/update/remove identities
- Check if an address is verified

---

### 3.3 – Identity Registry Storage

**Stores address-to-identity mapping**

---

### 3.4 – Trusted Issuers Registry

**Manages list of trusted claim issuers**

---

### 3.5 – Claim Topics Registry

**Maps required claims to token access**

---

### 3.6 – Modular Compliance

**Checks whether transfers meet all compliance rules**

- Can include country restriction, claim modules, etc.

---

### 3.7 – OnChainID

**Manages decentralized identity using claim-based verification**

---

### 3.8 – T-REX Factory

**Deploys and configures full T-REX token suites**

---

### 3.9 – Implementation Authority

**Manages upgrades and contract versioning**

---

## 4. Roadmap

1. Implement core contracts
2. Integrate and test interactions
3. Conduct full security audit
4. Deploy to Kii-Chain testnet
5. Final adjustments and mainnet deployment

---

## 5. Testing Strategy

- Unit tests for contract logic
- Integration tests for contract interaction
- End-to-end scenarios
- Fuzz testing
- Governance and access control tests

---

## Notes

- Only users with approved claims and trusted issuers will be able to interact with token transfers.
- All contracts are upgradable through the `Implementation Authority`.

