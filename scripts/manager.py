#!/usr/bin/env python3

import json

from common import execute_contract, get_key_address, query_contract

#############################
# Core Deployment Variables #
#############################

TRUSTED_ISSUE_KEY_NAME = "trusted_issuer"
TRUSTED_ISSUE_KEY_ADDRESS = get_key_address(TRUSTED_ISSUE_KEY_NAME)
OWNER_KEY_NAME = "rwa"
OWNER_KEY_ADDRESS = get_key_address(OWNER_KEY_NAME)
CONTRACTS = {
    "owner_roles_address": "kii1hez8n9mnljtca28xrg4a54p4cdharlsg0vku0008ng64ldgfapdqsqctag",
    "agent_roles_address": "kii14tzdqsgsdfcgxy0zu2vqcaj347lv5xpelpadusrspnkxddc53fhq9vc0h8",
    "trusted_issuers_address": "kii17xsl3q2p3elhh747r3ttn08j2p95jsd3c7rfmuc5rws5a20u9kqqrrx0nd",
    "claim_topics_address": "kii17k6uthn6ymd3ta25glx6qpa2sfz2hkt5a22lynzdm7xgk7kklckqc4gytm",
    "on_chain_id_address": "kii1y8s38zn7ry7xc95ej2z08eq520y4v9qdsysfgkfwelhh635e4t2qq8xxp5",
    "compliance_registry_address": "kii1dpws8lmu2l4awdau6zhezxm97tshu427aulr2xwp7uarpd8jqu7srjz2gm",
    "compliance_claims_address": "kii12n3frtnx8mh2vpvzk7mqkr6yqkfe77339c7uakzqqa4pv46zdr9qt020h3",
    "compliance_country_restriction_address": "kii1k4j6gr75k23tvqjdw9zvtrdxh7pxtexy5pdk7xjmwf385msx75fsz470kz",
    "cw20_base_address": "kii1zvjy36ysunq56dhgyxggp5gwrymxjs95twj5lgcpqujftppn739s83aym4",
}

########
# Call #
########

# Setup the owner roles
has_issuers_registry_manager = query_contract(
    CONTRACTS["owner_roles_address"],
    {"is_owner": {"owner": OWNER_KEY_ADDRESS, "role": "issuers_registry_manager"}},
)
if not has_issuers_registry_manager["data"]["is_owner"]:
    print(
        f"Key {OWNER_KEY_NAME} is not an issuers registry manager. Creating a new role..."
    )

    # Create a new role for the owner
    res = execute_contract(
        CONTRACTS["owner_roles_address"],
        {
            "add_owner_role": {
                "owner": OWNER_KEY_ADDRESS,
                "role": "issuers_registry_manager",
            }
        },
        OWNER_KEY_NAME,
    )

    print("Role created")
print(f"Key {OWNER_KEY_NAME} is an issuers registry manager.")

# Setup the claim registry manager
has_claim_registry_manager = query_contract(
    CONTRACTS["owner_roles_address"],
    {"is_owner": {"owner": OWNER_KEY_ADDRESS, "role": "claim_registry_manager"}},
)
if not has_claim_registry_manager["data"]["is_owner"]:
    print(f"Key {OWNER_KEY_NAME} is not a claim registry manager. Creating a new role...")

    # Create a new role for the owner
    res = execute_contract(
        CONTRACTS["owner_roles_address"],
        {
            "add_owner_role": {
                "owner": OWNER_KEY_ADDRESS,
                "role": "claim_registry_manager",
            }
        },
        OWNER_KEY_NAME,
    )

    print("Role created")
print(f"Key {OWNER_KEY_NAME} is a claim registry manager.")

# Check if a address is a trusted issuer
is_trusted_issuer = query_contract(
    CONTRACTS["trusted_issuers_address"],
    {"is_trusted_issuer": {"issuer": TRUSTED_ISSUE_KEY_ADDRESS}},
)
if not is_trusted_issuer["data"]:
    print(
        f"Key {TRUSTED_ISSUE_KEY_NAME} is not a trusted issuer. Creating a new trusted issuer..."
    )

    # Create a new trusted issuer
    res = execute_contract(
        CONTRACTS["trusted_issuers_address"],
        {
            "add_trusted_issuer": {
                "issuer": TRUSTED_ISSUE_KEY_ADDRESS,
                "claim_topics": ["1"],
            }
        },
        OWNER_KEY_NAME,
    )

    print("Trusted issuer created")
print (f"Key {TRUSTED_ISSUE_KEY_NAME} is a trusted issuer.")

# Add a claim topic to the CW20 token
claim_topics_for_token = query_contract(
    CONTRACTS["claim_topics_address"],
    {"get_claims_for_token": {"token_addr": CONTRACTS["cw20_base_address"]
    }},
)
if len(claim_topics_for_token["data"]) == 0:
    print(
        f"Token {CONTRACTS['cw20_base_address']} has no claim topics. Adding a claim topic..."
    )

    # Add a claim topic to the token
    res = execute_contract(
        CONTRACTS["claim_topics_address"],
        {
            "add_claim_topic_for_token": {
                "token_addr": CONTRACTS["cw20_base_address"],
                "topic": "1",
            }
        },
        OWNER_KEY_NAME,
    )

    print("Claim topic added")
print(f"Token {CONTRACTS['cw20_base_address']} has claim topics")

