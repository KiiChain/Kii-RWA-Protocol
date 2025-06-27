const { deployContract, setupWallet, executeContract, queryContract } = require("./utils");
const assert = require('assert');

describe("CW3643 Token", function() {
    this.timeout(60000); // Increase timeout to 60 seconds for the entire test suite

    let owner, ownerClient;
    let recipient, recipientClient;
    let issuer, issuerClient;
    let contracts = {};

    before(async function() {
        ({ account: owner, client: ownerClient } = await setupWallet());
        ({ account: recipient, client: recipientClient } = await setupWallet());
        ({ account: issuer, client: issuerClient } = await setupWallet());

        // Deploy contracts in the correct order
        contracts.ownerRoles = await deployContract(ownerClient, owner.address, "owner_roles", { owner: owner.address });
        contracts.agentRoles = await deployContract(ownerClient, owner.address, "agent_roles", { owner: owner.address });
        contracts.trustedIssuers = await deployContract(ownerClient, owner.address, "trusted_issuers", {
            owner_roles_address: contracts.ownerRoles.contractAddress
        });
        contracts.claimTopics = await deployContract(ownerClient, owner.address, "claim_topics", {
            owner_roles_address: contracts.ownerRoles.contractAddress
        });
        contracts.onChainId = await deployContract(ownerClient, owner.address, "on_chain_id", { owner: owner.address,
            trusted_issuer_addr: contracts.trustedIssuers.contractAddress
        });
        contracts.complianceRegistry = await deployContract(ownerClient, owner.address, "compliance_registry", {
            owner_roles_address: contracts.ownerRoles.contractAddress,
        });
        contracts.complianceClaims = await deployContract(ownerClient, owner.address, "compliance_claims", {
            identity_address: contracts.onChainId.contractAddress,
            owner_roles_address: contracts.ownerRoles.contractAddress,
            claim_topics_address: contracts.claimTopics.contractAddress
        });
        contracts.complianceCountry = await deployContract(ownerClient, owner.address, "compliance_country_restriction", {
            identity_address: contracts.onChainId.contractAddress,
            owner_roles_address: contracts.ownerRoles.contractAddress
        });
        contracts.cw20Base = await deployContract(ownerClient, owner.address, "cw20_base", {
            token_info: {
                name: "Test Token",
                symbol: "TEST",
                decimals: 18,
                initial_balances: [{ address: owner.address, amount: "1000000000" }]
            },
            registeries: {
                compliance_address: contracts.complianceRegistry.contractAddress
            }
        });
    });

    describe("Contract Deployment", function() {
        it("should deploy all contracts successfully", async function() {
            for (const [name, contract] of Object.entries(contracts)) {
                assert(contract.contractAddress, `${name} contract address should be defined`);
                assert(contract.contractCodeId, `${name} contract code ID should be defined`);
            }
        });
    });

    describe("Owner Roles Setup", function() {
        it("should set up owner roles", async function() {
            await executeContract(ownerClient, owner.address, contracts.ownerRoles.contractAddress, {
                add_owner_role: {
                    role: "compliance_manager",
                    owner: owner.address
                }
            });

            await executeContract(ownerClient, owner.address, contracts.ownerRoles.contractAddress, {
                add_owner_role: {
                    role: "issuers_registry_manager",
                    owner: owner.address
                }
            });

            await executeContract(ownerClient, owner.address, contracts.ownerRoles.contractAddress, {
                add_owner_role: {
                    role: "issuers_registry_manager",
                    owner: issuer.address
                }
            });

            await executeContract(ownerClient, owner.address, contracts.ownerRoles.contractAddress, {
                add_owner_role: {
                    role: "claim_registry_manager",
                    owner: owner.address
                }
            });

            const response1 = await queryContract(ownerClient, contracts.ownerRoles.contractAddress, {
                is_owner: {
                    role: "compliance_manager",
                    owner: owner.address
                }
            });

            const response2 = await queryContract(ownerClient, contracts.ownerRoles.contractAddress, {
                is_owner: {
                    role: "issuers_registry_manager",
                    owner: owner.address
                }
            });

            const response3 = await queryContract(ownerClient, contracts.ownerRoles.contractAddress, {
                is_owner: {
                    role: "issuers_registry_manager",
                    owner: issuer.address
                }
            });

            const response4 = await queryContract(ownerClient, contracts.ownerRoles.contractAddress, {
                is_owner: {
                    role: "claim_registry_manager",
                    owner: owner.address
                }
            });

            assert.strictEqual(response1.is_owner, true);
            assert.strictEqual(response2.is_owner, true);
            assert.strictEqual(response3.is_owner, true);
            assert.strictEqual(response4.is_owner, true);
        });
    });

    describe("Trusted Issuer and Claim Topics", function() {
        it("should add a trusted issuer", async function() {
            await executeContract(ownerClient, owner.address, contracts.trustedIssuers.contractAddress, {
                add_trusted_issuer: {
                    issuer: issuer.address,
                    claim_topics: ["1", "2"]
                }
            });
            const response = await queryContract(ownerClient, contracts.trustedIssuers.contractAddress, {
                is_trusted_issuer: {
                    issuer: issuer.address
                }
            });
            assert.strictEqual(response, true);
        });

        it("should add a claim topic", async function() {
            await executeContract(ownerClient, owner.address, contracts.claimTopics.contractAddress, {
                add_claim_topic_for_token: {
                    token_addr: contracts.cw20Base.contractAddress,
                    topic: "1"
                }
            });

            const response = await queryContract(ownerClient, contracts.claimTopics.contractAddress, {
                get_claims_for_token: {
                    token_addr: contracts.cw20Base.contractAddress
                }
            });

            assert.deepStrictEqual(response, ["1"]);
        });
    });

    describe("Identity Management", function() {
        it("should add an identity for recipient", async function() {
            await executeContract(recipientClient, recipient.address, contracts.onChainId.contractAddress, {
                add_identity: {
                    country: "US"
                }
            });

            const response = await queryContract(recipientClient, contracts.onChainId.contractAddress, {
                get_identity: {
                    identity_owner: recipient.address
                }
            });

            assert.strictEqual(response.country, "US");
        });

        it("should add an identity for owner", async function() {
            await executeContract(ownerClient, owner.address, contracts.onChainId.contractAddress, {
                add_identity: {
                    country: "CA"
                }
            });

            const response = await queryContract(ownerClient, contracts.onChainId.contractAddress, {
                get_identity: {
                    identity_owner: owner.address
                }
            });

            assert.strictEqual(response.country, "CA");
        });

        it("should add an identity for issuer", async function() {
            await executeContract(issuerClient, issuer.address, contracts.onChainId.contractAddress, {
                add_identity: {
                    country: "CA"
                }
            });

            const response = await queryContract(issuerClient, contracts.onChainId.contractAddress, {
                get_identity: {
                    identity_owner: issuer.address
                }
            });

            assert.strictEqual(response.country, "CA");
        });

        it("should add a claim to an identity", async function() {
            // First, add a ClaimSignerKey for the issuer to the recipient's identity
            await executeContract(recipientClient, recipient.address, contracts.onChainId.contractAddress, {
                add_key: {
                    key_owner: issuer.address,
                    key_type: "ClaimSignerKey",
                    identity_owner: recipient.address
                }
            });

            // Now the issuer can add a claim to the recipient's identity
            await executeContract(issuerClient, issuer.address, contracts.onChainId.contractAddress, {
                add_claim: {
                    claim: {
                        topic: "1",
                        issuer: issuer.address,
                        data: Buffer.from("claim data").toString('base64'),
                        uri: "https://example.com/claim"
                    },
                    identity_owner: recipient.address
                }
            });

            const response = await queryContract(recipientClient, contracts.onChainId.contractAddress, {
                get_validated_claims_for_user: {
                    identity_owner: recipient.address
                }
            });

            assert.strictEqual(response.length, 1);
            assert.strictEqual(response[0].topic, "1");
        });
    });

    describe("Compliance Setup", function() {
        it("should add country restriction", async function() {
            await executeContract(ownerClient, owner.address, contracts.complianceCountry.contractAddress, {
                add_country_restriction: {
                    token_address: contracts.cw20Base.contractAddress,
                    country: "US",  // Change this to US (not allowed)
                    active: true
                }
            });
        });

        it ("owner should be compliant", async function() {
            const response = await queryContract(ownerClient, contracts.complianceCountry.contractAddress, {
                check_token_compliance: {
                    token_address: contracts.cw20Base.contractAddress,
                    from: owner.address,
                    to: null,
                    amount: null
                }
            });

            assert.strictEqual(response, true);  // Should be true because owner is still in CA

        });

        it ("issuer should be compliant", async function() {
            const response = await queryContract(issuerClient, contracts.complianceCountry.contractAddress, {
                check_token_compliance: {
                    token_address: contracts.cw20Base.contractAddress,
                    from: issuer.address,
                    to: null,
                    amount: null
                }
            });

            assert.strictEqual(response, true);  // Should be true because issuer is still in CA

        });

        it ("recipient should not be compliant", async function() {
            const response = await queryContract(recipientClient, contracts.complianceCountry.contractAddress, {
                check_token_compliance: {
                    token_address: contracts.cw20Base.contractAddress,
                    from: recipient.address,
                    to: null,
                    amount: null
                }
            });

            assert.strictEqual(response, false);
        });

        it("should add a compliance module", async function() {
            await executeContract(ownerClient, owner.address, contracts.complianceRegistry.contractAddress, {
                add_compliance_module: {
                    token_address: contracts.cw20Base.contractAddress,
                    module_address: contracts.complianceCountry.contractAddress,
                    module_name: "CountryRestrictionCompliance"
                }
            });
        });

        it ("owner should be compliant with compliance module", async function() {
            // Query to check if the compliance module was added
            const response = await queryContract(ownerClient, contracts.complianceRegistry.contractAddress, {
                check_token_compliance: {
                    token_address: contracts.cw20Base.contractAddress,
                    from: owner.address,
                    to: null,
                    amount: null
                }
            });

            assert.strictEqual(response, true);
        });

        it ("issuer should be compliant with compliance module", async function() {
            // Query to check if the compliance module was added
            const response = await queryContract(issuerClient, contracts.complianceRegistry.contractAddress, {
                check_token_compliance: {
                    token_address: contracts.cw20Base.contractAddress,
                    from: issuer.address,
                    to: null,
                    amount: null
                }
            });

            assert.strictEqual(response, true);
        });

        it ("recipient should not be compliant with compliance module", async function() {
            const response = await queryContract(recipientClient, contracts.complianceRegistry.contractAddress, {
                check_token_compliance: {
                    token_address: contracts.cw20Base.contractAddress,
                    from: recipient.address,
                    to: null,
                    amount: null
                }
            });

            assert.strictEqual(response, false);
        });
    });

    describe("Token Transfers", function() {
        it("should transfer tokens with compliance check", async function() {
            const transferAmount = "1000";
            await executeContract(ownerClient, owner.address, contracts.cw20Base.contractAddress, {
                transfer: {
                    recipient: issuer.address,
                    amount: transferAmount
                }
            });

            const balance = await queryContract(ownerClient, contracts.cw20Base.contractAddress, {
                balance: {
                    address: issuer.address
                }
            });

            assert.strictEqual(balance.balance, transferAmount);
        });

        it("should fail transfer due to compliance check", async function() {
            const transferAmount = "1000";

            // Get initial balance of recipient
            const initialBalance = await queryContract(ownerClient, contracts.cw20Base.contractAddress, {
                balance: {
                    address: recipient.address
                }
            });

            // Change the recipient's country to a restricted country (US)
            await executeContract(recipientClient, recipient.address, contracts.onChainId.contractAddress, {
                update_country: {
                    new_country: "US",
                    identity_owner: recipient.address
                }
            });

            try {
                await executeContract(ownerClient, owner.address, contracts.cw20Base.contractAddress, {
                    transfer: {
                        recipient: recipient.address,
                        amount: transferAmount
                    }
                });
            } catch (error) {
                assert(error.message.includes("Compliance check failed"), "Expected ComplianceCheckFailed error");
            }

            // Check that the balance didn't change
            const finalBalance = await queryContract(ownerClient, contracts.cw20Base.contractAddress, {
                balance: {
                    address: recipient.address
                }
            });

            assert.strictEqual(finalBalance.balance, initialBalance.balance, "Balance should not have changed after failed transfer");
        });
    });

    describe("Additional Owner Roles Tests", function() {
        it("should not allow non-owner to add owner role", async function() {
            try {
                await executeContract(recipientClient, recipient.address, contracts.ownerRoles.contractAddress, {
                    add_owner_role: {
                        role: "compliance_manager",
                        owner: recipient.address
                    }
                });
                assert.fail("Should not allow non-owner to add owner role");
            } catch (error) {
                assert(error.message.includes("Unauthorized"));
            }
        });

        it("should allow owner to remove owner role", async function() {
            await executeContract(ownerClient, owner.address, contracts.ownerRoles.contractAddress, {
                remove_owner_role: {
                    role: "compliance_manager",
                    owner: owner.address
                }
            });

            const response = await queryContract(ownerClient, contracts.ownerRoles.contractAddress, {
                is_owner: {
                    role: "compliance_manager",
                    owner: owner.address
                }
            });

            assert.strictEqual(response.is_owner, false);
        });

        // Add the role back for subsequent tests
        after(async function() {
            await executeContract(ownerClient, owner.address, contracts.ownerRoles.contractAddress, {
                add_owner_role: {
                    role: "compliance_manager",
                    owner: owner.address
                }
            });
        });
    });

    describe("Additional Trusted Issuer Tests", function() {
        it("should update issuer claim topics", async function() {
            await executeContract(ownerClient, owner.address, contracts.trustedIssuers.contractAddress, {
                update_issuer_claim_topics: {
                    issuer: issuer.address,
                    claim_topics: ["1", "2", "3"]
                }
            });

            const response = await queryContract(ownerClient, contracts.trustedIssuers.contractAddress, {
                get_issuer_claim_topics: {
                    issuer: issuer.address
                }
            });

            assert.deepStrictEqual(response, ["1", "2", "3"]);
        });

        it("should remove trusted issuer", async function() {
            await executeContract(ownerClient, owner.address, contracts.trustedIssuers.contractAddress, {
                remove_trusted_issuer: {
                    issuer: issuer.address
                }
            });

            const response = await queryContract(ownerClient, contracts.trustedIssuers.contractAddress, {
                is_trusted_issuer: {
                    issuer: issuer.address
                }
            });

            assert.strictEqual(response, false);
        });

        // Add the issuer back for subsequent tests
        after(async function() {
            await executeContract(ownerClient, owner.address, contracts.trustedIssuers.contractAddress, {
                add_trusted_issuer: {
                    issuer: issuer.address,
                    claim_topics: ["1", "2", "3"]
                }
            });
        });
    });

    describe("Additional Identity Management Tests", function() {
        it("should update identity country", async function() {
            await executeContract(recipientClient, recipient.address, contracts.onChainId.contractAddress, {
                update_country: {
                    new_country: "CA",
                    identity_owner: recipient.address
                }
            });

            const response = await queryContract(recipientClient, contracts.onChainId.contractAddress, {
                get_identity: {
                    identity_owner: recipient.address
                }
            });

            assert.strictEqual(response.country, "CA");
        });

        it("should remove a claim from an identity", async function() {
            await executeContract(issuerClient, issuer.address, contracts.onChainId.contractAddress, {
                remove_claim: {
                    claim_topic: "1",
                    identity_owner: recipient.address
                }
            });

            const response = await queryContract(recipientClient, contracts.onChainId.contractAddress, {
                get_validated_claims_for_user: {
                    identity_owner: recipient.address
                }
            });

            assert.strictEqual(response.length, 0);
        });

        // Add the claim back for subsequent tests
        after(async function() {
            await executeContract(issuerClient, issuer.address, contracts.onChainId.contractAddress, {
                add_claim: {
                    claim: {
                        topic: "1",
                        issuer: issuer.address,
                        data: Buffer.from("claim data").toString('base64'),
                        uri: "https://example.com/claim"
                    },
                    identity_owner: recipient.address
                }
            });
        });
    });

    describe("Additional Compliance Tests", function() {

        it("should remove compliance module", async function() {
            await executeContract(ownerClient, owner.address, contracts.complianceRegistry.contractAddress, {
                remove_compliance_module: {
                    token_address: contracts.cw20Base.contractAddress,
                    module_address: contracts.complianceCountry.contractAddress
                }
            });

            // All transfers should now be compliant
            const response = await queryContract(recipientClient, contracts.complianceRegistry.contractAddress, {
                check_token_compliance: {
                    token_address: contracts.cw20Base.contractAddress,
                    from: recipient.address,
                    to: null,
                    amount: null
                }
            });

            assert.strictEqual(response, true);
        });
    });

    describe("Additional Token Transfer Tests", function() {
        it("should allow transfer after compliance update", async function() {
            const transferAmount = "500";
            await executeContract(ownerClient, owner.address, contracts.cw20Base.contractAddress, {
                transfer: {
                    recipient: recipient.address,
                    amount: transferAmount
                }
            });

            const balance = await queryContract(ownerClient, contracts.cw20Base.contractAddress, {
                balance: {
                    address: recipient.address
                }
            });

            assert.strictEqual(balance.balance, transferAmount);
        });

        // Reset recipient's country for subsequent tests
        after(async function() {
            await executeContract(recipientClient, recipient.address, contracts.onChainId.contractAddress, {
                update_country: {
                    new_country: "CA",
                    identity_owner: recipient.address
                }
            });
        });
    });

    describe("Combined Compliance Tests", function() {
        before(async function() {
            // Set up initial compliance configuration
            await setupCompliance();
        });

        async function setupCompliance() {
            // Remove all existing claim topics for the token
            const existingClaimTopics = await queryContract(ownerClient, contracts.claimTopics.contractAddress, {
                get_claims_for_token: { token_addr: contracts.cw20Base.contractAddress }
            });

            for (const topic of existingClaimTopics) {
                await executeContract(ownerClient, owner.address, contracts.claimTopics.contractAddress, {
                    remove_claim_topic_for_token: {
                        token_addr: contracts.cw20Base.contractAddress,
                        topic: topic
                    }
                });
            }

            // Add KYC claim topic
            await executeContract(ownerClient, owner.address, contracts.claimTopics.contractAddress, {
                add_claim_topic_for_token: {
                    token_addr: contracts.cw20Base.contractAddress,
                    topic: "2" // KYC claim topic
                }
            });

            // Add compliance modules
            await executeContract(ownerClient, owner.address, contracts.complianceRegistry.contractAddress, {
                add_compliance_module: {
                    token_address: contracts.cw20Base.contractAddress,
                    module_address: contracts.complianceClaims.contractAddress,
                    module_name: "ClaimsCompliance"
                }
            });

            await executeContract(ownerClient, owner.address, contracts.complianceRegistry.contractAddress, {
                add_compliance_module: {
                    token_address: contracts.cw20Base.contractAddress,
                    module_address: contracts.complianceCountry.contractAddress,
                    module_name: "CountryRestrictionCompliance"
                }
            });

            // Ensure participants have required claims
            await addRequiredClaims(issuer, issuerClient, "Issuer");
            await addRequiredClaims(recipient, recipientClient, "Recipient");
        }

        async function addRequiredClaims(identity, client, role) {
            const existingClaims = await queryContract(client, contracts.onChainId.contractAddress, {
                get_validated_claims_for_user: {
                    identity_owner: identity.address
                }
            });

            // Remove any existing claims that are not KYC (topic "2")
            for (const claim of existingClaims) {
                if (claim.topic !== "2") {
                    await executeContract(issuerClient, issuer.address, contracts.onChainId.contractAddress, {
                        remove_claim: {
                            claim_topic: claim.topic,
                            identity_owner: identity.address
                        }
                    });
                }
            }

            // Add KYC claim if it doesn't exist
            if (!existingClaims.some(claim => claim.topic === "2")) {
                await executeContract(issuerClient, issuer.address, contracts.onChainId.contractAddress, {
                    add_claim: {
                        claim: {
                            topic: "2",
                            issuer: issuer.address,
                            data: Buffer.from(`KYC approved for ${role}`).toString('base64'),
                            uri: `https://example.com/${role.toLowerCase()}-kyc-claim`
                        },
                        identity_owner: identity.address
                    }
                });
            }

            // Verify claims
            const claims = await queryContract(client, contracts.onChainId.contractAddress, {
                get_validated_claims_for_user: {
                    identity_owner: identity.address
                }
            });
            assert(claims.some(claim => claim.topic === "2"), `${role} does not have KYC claim (topic 2)`);
            assert(claims.length === 1, `${role} should only have one claim (KYC)`);
        }

        it("should verify claim topics for the token", async function() {
            const response = await queryContract(ownerClient, contracts.claimTopics.contractAddress, {
                get_claims_for_token: { token_addr: contracts.cw20Base.contractAddress }
            });
            assert(response.includes("2"), "KYC claim topic not found for token");
        });

        it("should allow transfer when all compliance requirements are met", async function() {
            const transferAmount = "100";

            // Update recipient's country to non-restricted
            await executeContract(recipientClient, recipient.address, contracts.onChainId.contractAddress, {
                update_country: {
                    new_country: "CA",
                    identity_owner: recipient.address
                }
            });
            // Verify recipient's identity and claims
            const recipientIdentity = await queryContract(recipientClient, contracts.onChainId.contractAddress, {
                get_identity: { identity_owner: recipient.address }
            });
            assert.strictEqual(recipientIdentity.country, "CA", "Recipient country should be CA");

            const recipientClaims = await queryContract(recipientClient, contracts.onChainId.contractAddress, {
                get_validated_claims_for_user: { identity_owner: recipient.address }
            });
            assert(recipientClaims.some(claim => claim.topic === "2"), "Recipient does not have KYC claim");
            // Attempt transfer
            await executeContract(recipientClient, recipient.address, contracts.cw20Base.contractAddress, {
                transfer: {
                    recipient: issuer.address,
                    amount: transferAmount
                }
            });
            // Check balance after transfer
            const balance = await queryContract(ownerClient, contracts.cw20Base.contractAddress, {
                balance: { address: issuer.address }
            });
            assert.strictEqual(balance.balance, (parseInt(transferAmount) + 1000).toString(), "Incorrect balance after transfer");
        });

        it("should fail transfer when sender lacks required claim", async function() {
            const transferAmount = "100";

            // Remove KYC claim from recipient
            await executeContract(issuerClient, issuer.address, contracts.onChainId.contractAddress, {
                remove_claim: {
                    claim_topic: "2",
                    identity_owner: recipient.address
                }
            });

            try {
                await executeContract(recipientClient, recipient.address, contracts.cw20Base.contractAddress, {
                    transfer: {
                        recipient: issuer.address,
                        amount: transferAmount
                    }
                });
                assert.fail("Should not allow transfer from sender without required claim");
            } catch (error) {
                assert(error.message.includes("Compliance check failed"));
            }

            // Restore KYC claim for recipient
            await addRequiredClaims(recipient, recipientClient, "Recipient");
        });

        it("should fail transfer when recipient is from restricted country", async function() {
            const transferAmount = "50";

            // Update recipient's country to restricted
            await executeContract(recipientClient, recipient.address, contracts.onChainId.contractAddress, {
                update_country: {
                    new_country: "US",
                    identity_owner: recipient.address
                }
            });

            try {
                await executeContract(issuerClient, issuer.address, contracts.cw20Base.contractAddress, {
                    transfer: {
                        recipient: recipient.address,
                        amount: transferAmount
                    }
                });
                assert.fail("Should not allow transfer to recipient from restricted country");
            } catch (error) {
                assert(error.message.includes("Compliance check failed"));
            }

            // Reset recipient's country
            await executeContract(recipientClient, recipient.address, contracts.onChainId.contractAddress, {
                update_country: {
                    new_country: "CA",
                    identity_owner: recipient.address
                }
            });
        });

        after(async function() {
            // Remove compliance modules
            await executeContract(ownerClient, owner.address, contracts.complianceRegistry.contractAddress, {
                remove_compliance_module: {
                    token_address: contracts.cw20Base.contractAddress,
                    module_address: contracts.complianceCountry.contractAddress
                }
            });
            await executeContract(ownerClient, owner.address, contracts.complianceRegistry.contractAddress, {
                remove_compliance_module: {
                    token_address: contracts.cw20Base.contractAddress,
                    module_address: contracts.complianceClaims.contractAddress
                }
            });
        });
    });
});
