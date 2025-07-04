# Compliance Whitelist Wrapper

This contract wraps other compliance contracts, filtering what is sent to them. If it finds an address that is in the whitelist, it will substitute it with None before forwarding it to the wrapped compliance module.

Only addresses with the OwnerRole ComplianceManager can add or remove addresses from the whitelist. Each compliance contract should have its own wrapper.
