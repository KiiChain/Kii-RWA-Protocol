#!/usr/bin/env python3

from common import instantiate_contract, store_contract

import config

#############################
# Core Deployment Variables #
#############################

# Define the main variables for the deployment
KEY_NAME = config.OWNER_KEY_NAME
KEY_ADDRESS = config.OWNER_KEY_ADDRESS

############################
# Contract Deployment Zone #
############################

# Owner Roles Contract
print("Deploying Owner Roles contract...")
owner_roles = store_contract("artifacts/owner_roles.wasm", KEY_NAME)
print(f"Owner roles stored with code ID {owner_roles}")
owner_roles_init_msg = {
    "owner": KEY_ADDRESS,
}
owner_roles_address = instantiate_contract(
    owner_roles, owner_roles_init_msg, "OwnerRoles", KEY_NAME
)
print(f"Owner roles contract instantiated at {owner_roles_address}")

# Agent roles
print("Deploying Agent Roles contract...")
agent_roles = store_contract("artifacts/agent_roles.wasm", KEY_NAME)
print(f"Agent roles stored with code ID {agent_roles}")
agent_roles_init_msg = {
    "owner": KEY_ADDRESS,
}
agent_roles_address = instantiate_contract(
    agent_roles, agent_roles_init_msg, "AgentRoles", KEY_NAME
)
print(f"Agent roles contract instantiated at {agent_roles_address}")

# trustedIssuers
print("Deploying Trusted Issuers contract...")
trusted_issuers = store_contract("artifacts/trusted_issuers.wasm", KEY_NAME)
print(f"Trusted issuers stored with code ID {trusted_issuers}")
trusted_issuers_init_msg = {
    "owner_roles_address": owner_roles_address,
}
trusted_issuers_address = instantiate_contract(
    trusted_issuers, trusted_issuers_init_msg, "TrustedIssuers", KEY_NAME
)
print(f"Trusted issuers contract instantiated at {trusted_issuers_address}")

# Claim Topics
print("Deploying Claim Topics contract...")
claim_topics = store_contract("artifacts/claim_topics.wasm", KEY_NAME)
print(f"Claim topics stored with code ID {claim_topics}")
claim_topics_init_msg = {
    "owner_roles_address": owner_roles_address,
}
claim_topics_address = instantiate_contract(
    claim_topics, claim_topics_init_msg, "ClaimTopics", KEY_NAME
)
print(f"Claim topics contract instantiated at {claim_topics_address}")

# On Chain ID
print("Deploying On Chain ID contract...")
on_chain_id = store_contract("artifacts/on_chain_id.wasm", KEY_NAME)
print(f"On Chain ID stored with code ID {on_chain_id}")
on_chain_id_init_msg = {
    "trusted_issuer_addr": trusted_issuers_address,
    "owner": KEY_ADDRESS,
}
on_chain_id_address = instantiate_contract(
    on_chain_id, on_chain_id_init_msg, "OnChainID", KEY_NAME
)
print(f"On Chain ID contract instantiated at {on_chain_id_address}")

# Compliance registry
print("Deploying Compliance Registry contract...")
compliance_registry = store_contract("artifacts/compliance_registry.wasm", KEY_NAME)
print(f"Compliance Registry stored with code ID {compliance_registry}")
compliance_registry_init_msg = {
    "owner_roles_address": owner_roles_address,
}
compliance_registry_address = instantiate_contract(
    compliance_registry, compliance_registry_init_msg, "ComplianceRegistry", KEY_NAME
)
print(f"Compliance Registry contract instantiated at {compliance_registry_address}")

# Compliance claims
print("Deploying Compliance Claims contract...")
compliance_claims = store_contract("artifacts/compliance_claims.wasm", KEY_NAME)
print(f"Compliance Claims stored with code ID {compliance_claims}")
compliance_claims_init_msg = {
    "identity_address": on_chain_id_address,
    "owner_roles_address": owner_roles_address,
    "claim_topics_address": claim_topics_address,
}
compliance_claims_address = instantiate_contract(
    compliance_claims, compliance_claims_init_msg, "ComplianceClaims", KEY_NAME
)
print(f"Compliance Claims contract instantiated at {compliance_claims_address}")

# Compliance country restriction
print("Deploying Compliance Country Restriction contract...")
compliance_country_restriction = store_contract(
    "artifacts/compliance_country_restriction.wasm", KEY_NAME
)
print(
    f"Compliance Country Restriction stored with code ID {compliance_country_restriction}"
)
compliance_country_restriction_init_msg = {
    "identity_address": on_chain_id_address,
    "owner_roles_address": owner_roles_address,
}
compliance_country_restriction_address = instantiate_contract(
    compliance_country_restriction,
    compliance_country_restriction_init_msg,
    "ComplianceCountryRestriction",
    KEY_NAME,
)
print(
    f"Compliance Country Restriction contract instantiated at {compliance_country_restriction_address}"
)

# Compliance wrapper for country and claims
print("Deploying Compliance wrapper")
compliance_wrapper = store_contract(
    "artifacts/compliance_wrapper.wasm", KEY_NAME
)
print(
    f"Compliance wrapper stored with code ID {compliance_wrapper}"
)

# Country wrapper
compliance_wrapper_country_init_msg = {
    "module_address": compliance_country_restriction_address,
    "owner_roles_address": owner_roles_address,
}
compliance_wrapper_country_address = instantiate_contract(
    compliance_wrapper,
    compliance_wrapper_country_init_msg,
    "ComplianceCountryWrapper",
    KEY_NAME,
)
print(
    f"Compliance Country Wrapper contract instantiated at {compliance_wrapper_country_address}"
)
# Claims wrapper
compliance_wrapper_claims_init_msg = {
    "module_address": compliance_claims_address,
    "owner_roles_address": owner_roles_address,
}
compliance_wrapper_claims_address = instantiate_contract(
    compliance_wrapper,
    compliance_wrapper_claims_init_msg,
    "ComplianceClaimsWrapper",
    KEY_NAME,
)
print(
    f"Compliance Claims Wrapper contract instantiated at {compliance_wrapper_claims_address}"
)

# CW20 base for test token
print("Deploying CW20 Base contract...")
cw20_base = store_contract("artifacts/cw20_base.wasm", KEY_NAME)
print(f"CW20 Base stored with code ID {cw20_base}")
cw20_base_init_msg = {
    "token_info": {
        "name": "Test Token",
        "symbol": "TEST",
        "decimals": 6,
        "initial_balances": [{"address": KEY_ADDRESS, "amount": "1000000"}],
    },
    "registries": {
        "compliance_address": compliance_registry_address,
    },
}
cw20_base_address = instantiate_contract(
    cw20_base, cw20_base_init_msg, "CW20Base", KEY_NAME
)
print(f"CW20 Base contract instantiated at {cw20_base_address}")
