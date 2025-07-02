#!/usr/bin/env python3

import config
import sys
from common import execute_contract, get_key_address, query_contract

# User and trusted issuer needs to have balance in account

#############################
# Import Core Variables #
#############################

TRUSTED_ISSUER_KEY_NAME = config.TRUSTED_ISSUER_KEY_NAME
TRUSTED_ISSUER_KEY_ADDRESS = config.TRUSTED_ISSUER_KEY_ADDRESS
CONTRACTS = config.CONTRACTS

#############
# Functions #
#############

def setup_user(user_name):
  USER_KEY_NAME = user_name
  USER_KEY_ADDRESS = get_key_address(USER_KEY_NAME)

  # 1. User creates own identity
  # Checks if identity exists
  try:
    has_identity = query_contract(
        CONTRACTS["on_chain_id_address"],
        {"get_identity": {"identity_owner": USER_KEY_ADDRESS}},
    )
    print(f"Key {USER_KEY_NAME} has an identity.")
  except:
    # Create a new identity for the owner
    print(f"Key {USER_KEY_NAME} has no identity. Creating a new Brazilian identity...")
    execute_contract(
        CONTRACTS["on_chain_id_address"],
        {
            "add_identity": {
                "country": "BR"
            }
        },
        USER_KEY_NAME,
    )
    print("Identity created")

  # 2. User gives permission for trusted issuer to add claims
  # Check if permission already exists
  try:
    issuer_has_claim_signer = query_contract(
      CONTRACTS["on_chain_id_address"],
      {"get_key": {
          "key_owner": TRUSTED_ISSUER_KEY_ADDRESS,
          "key_type" : "ClaimSignerKey",
          "identity_owner": USER_KEY_ADDRESS
          }},
    )
    print(f"Key {TRUSTED_ISSUER_KEY_NAME} has permission to add claims to key {USER_KEY_NAME}.")
  except:
    # Give permission to trusted issuer to add claims
    print(f"Key {TRUSTED_ISSUER_KEY_NAME} has no permission to add claims to key {USER_KEY_NAME}. Adding permission...")
    execute_contract(
        CONTRACTS["on_chain_id_address"],
        {
            "add_key": {
              "key_owner": TRUSTED_ISSUER_KEY_ADDRESS,
              "key_type" : "ClaimSignerKey",
              "identity_owner": USER_KEY_ADDRESS
            }
        },
        USER_KEY_ADDRESS,
    )
    print("Permission created")

  # 3. Trusted issuer creates a claim for the user
  # Check if claim already exists
  try:
    has_claim = query_contract(
        CONTRACTS["on_chain_id_address"],
        {"verify_claim": {
            "claim_id": "1",
            "identity_owner": USER_KEY_ADDRESS
            }},
    )
    print(f"Key {USER_KEY_NAME} has claim to topic 1.")
  except:
    # Give permission to trusted issuer to add claims
    print(f"Key {USER_KEY_NAME} has no claims to topic 1. Adding claim...")
    execute_contract(
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
        TRUSTED_ISSUER_KEY_NAME,
    )
    print("Claim created")

########
# Call #
########

if len(sys.argv) > 1:
    name = sys.argv[1]
    print(f"Setting up user key: {name}")
    setup_user(name)
else:
    print("Please provide the user key name when calling the script")
