use cosmwasm_std::Addr;
use cw_storage_plus::{Item, Map};

use super::msg::RestrictedCountry;

pub const OWNER_ROLES_ADDRESS: Item<Addr> = Item::new("owner_role_contract_address");
pub const IDENTITY_ADDRESS: Item<Addr> = Item::new("identity_addr");
pub const RESTRICTED_COUNTRY: Map<(Addr, String), RestrictedCountry> =
    Map::new("token_compliance_modules");
