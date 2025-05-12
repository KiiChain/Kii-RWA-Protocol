use cosmwasm_std::Addr;
use cw_storage_plus::Item;
use utils::RoleManagement;

pub const OWNER_ROLES: RoleManagement = RoleManagement::new("owner_roles");
pub const OWNER: Item<Addr> = Item::new("owner");
pub const COMPLIANCE_REGISTRY: Item<Addr> = Item::new("compliance");
pub const CLAIM_TOPICS_REGISTRY: Item<Addr> = Item::new("claim_topic");
pub const TRUSTED_ISSUERS_REGISTRY: Item<Addr> = Item::new("issuer");
