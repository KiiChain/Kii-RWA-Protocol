#!/usr/bin/env python3

import config
from common import execute_contract, query_contract

#############################
# Import Core Variables #
#############################

TRUSTED_ISSUER_KEY_NAME = config.TRUSTED_ISSUER_KEY_NAME
TRUSTED_ISSUER_KEY_ADDRESS = config.TRUSTED_ISSUER_KEY_ADDRESS
CONTRACTS = config.CONTRACTS
USER_KEY_NAME = config.USER_KEY_NAME
USER_KEY_ADDRESS = config.USER_KEY_ADDRESS

########
# Call #
########

# 1. User creates own identity
# Checks if identity exists
has_identity = query_contract(
    CONTRACTS["on_chain_id_address"],
    {"get_identity": {"identity_owner": USER_KEY_ADDRESS}},
)
if not has_identity["data"]:
    print(
        f"Key {USER_KEY_NAME} has no identity. Creating a new Brazilian identity..."
    )

    # Create a new identity for the owner
    res = execute_contract(
        CONTRACTS["on_chain_id_address"],
        {
            "add_identity": {
                "country": "BR"
            }
        },
        USER_KEY_NAME,
    )

    print("Identity created")
else:
    print(f"Key {USER_KEY_NAME} has an identity.")

# 2. User gives permission for trusted issuer to add claims
# Check if permission already exists
issuer_has_claim_signer = query_contract(
    CONTRACTS["on_chain_id_address"],
    {"get_key": {
        "key_owner": TRUSTED_ISSUE_KEY_ADDRESS,
        "key_type" : "ClaimSignerKey",
        "identity_owner": USER_KEY_ADDRESS
        }},
)
if not issuer_has_claim_signer["data"]:
    print(
        f"Key {TRUSTED_ISSUE_KEY_NAME} has no permission to add claims to key {USER_KEY_NAME}. Adding permission..."
    )

    # Give permission to trusted issuer to add claims
    res = execute_contract(
        CONTRACTS["on_chain_id_address"],
        {
            "add_key": {
              "key_owner": TRUSTED_ISSUE_KEY_ADDRESS,
              "key_type" : "ClaimSignerKey",
              "identity_owner": USER_KEY_ADDRESS
            }
        },
        USER_KEY_ADDRESS,
    )

    print("Permission created")
else:
    print(f"Key {TRUSTED_ISSUE_KEY_NAME} has permission to add claims to key {USER_KEY_NAME}.")


# 3. Trusted issuer creates a claim for the user
# Check if claim already exists
has_claim = query_contract(
    CONTRACTS["on_chain_id_address"],
    {"verify_claim": {
        "claim_id": "1",
        "identity_owner": USER_KEY_ADDRESS
        }},
)
if not has_claim["data"]:
    print(
        f"Key {USER_KEY_NAME} has no claims to topic 1. Adding claim..."
    )

    # Give permission to trusted issuer to add claims
    res = execute_contract(
        CONTRACTS["on_chain_id_address"],
        {
            "add_claim": {
                "claim" : {
                  "token_addr": CONTRACTS["cw20_base_address"],
                  "topic": "1"
                },
                "identity_owner": USER_KEY_ADDRESS
            }
        },
        TRUSTED_ISSUE_KEY_NAME,
    )

    print("Claim created")
else:
    print(f"Key {USER_KEY_NAME} has claim to topic 1.")



