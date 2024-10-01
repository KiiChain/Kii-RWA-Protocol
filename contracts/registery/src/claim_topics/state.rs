use cosmwasm_std::Addr;
use cw_storage_plus::{Item, Map};

pub const OWNER_ROLES_ADDRESS: Item<Addr> = Item::new("owner_role_addr");
pub const CLAIM_TOPICS: Map<u128, bool> = Map::new("claim_topics");
