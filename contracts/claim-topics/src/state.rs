use cosmwasm_std::Addr;
use cw_storage_plus::{Item, Map};

use crate::msg::Claim;

pub const OWNER_ROLES_ADDRESS: Item<Addr> = Item::new("owner_role_addr");
pub const TOKEN_CLAIM_TOPICS: Map<(Addr, u128), Claim> = Map::new("token_claim_topics");
