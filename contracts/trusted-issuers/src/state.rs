use cosmwasm_std::Addr;
use cw_storage_plus::{Item, Map};

use super::msg::TrustedIssuer;
pub const OWNER_ROLES_ADDRESS: Item<Addr> = Item::new("owner_role_addr");
pub const TRUSTED_ISSUERS: Map<Addr, TrustedIssuer> = Map::new("trusted_issuers");
