#!/usr/bin/env python3

import config
from common import execute_contract, query_contract

#############################
# Import Core Variables #
#############################

TRUSTED_ISSUER_KEY_NAME = config.TRUSTED_ISSUER_KEY_NAME
TRUSTED_ISSUER_KEY_ADDRESS = config.TRUSTED_ISSUER_KEY_ADDRESS
OWNER_KEY_NAME = config.OWNER_KEY_NAME
OWNER_KEY_ADDRESS = config.OWNER_KEY_ADDRESS
CONTRACTS = config.CONTRACTS

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
else:
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
else:
    print(f"Key {OWNER_KEY_NAME} is a claim registry manager.")

# Check if a address is a trusted issuer
is_trusted_issuer = query_contract(
    CONTRACTS["trusted_issuers_address"],
    {"is_trusted_issuer": {"issuer": TRUSTED_ISSUER_KEY_ADDRESS}},
)
if not is_trusted_issuer["data"]:
    print(
        f"Key {TRUSTED_ISSUER_KEY_NAME} is not a trusted issuer. Creating a new trusted issuer..."
    )

    # Create a new trusted issuer
    res = execute_contract(
        CONTRACTS["trusted_issuers_address"],
        {
            "add_trusted_issuer": {
                "issuer": TRUSTED_ISSUER_KEY_ADDRESS,
                "claim_topics": ["1"],
            }
        },
        OWNER_KEY_NAME,
    )

    print("Trusted issuer created")
else:
    print (f"Key {TRUSTED_ISSUER_KEY_NAME} is a trusted issuer.")

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
else:
    print(f"Token {CONTRACTS['cw20_base_address']} has claim topics")

# Add identity to trusted issuer
try:
  has_identity = query_contract(
      CONTRACTS["on_chain_id_address"],
      {"get_identity": {"identity_owner": TRUSTED_ISSUER_KEY_ADDRESS}},
  )
  print(f"Key {TRUSTED_ISSUER_KEY_NAME} has an identity.")
except:
  print(
      f"Key {TRUSTED_ISSUER_KEY_NAME} has no identity. Creating a new Brazilian identity..."
  )

  # Create a new identity for the owner
  res = execute_contract(
      CONTRACTS["on_chain_id_address"],
      {
          "add_identity": {
              "country": "BR"
          }
      },
      TRUSTED_ISSUER_KEY_NAME,
  )

  print("Identity created")
