use cosmwasm_std::Addr;
use cw_storage_plus::{Item, Map};

// Owner, (identity address, country)
pub const IDENTITIES: Map<Addr, (Addr, String)> = Map::new("identities");

// Contract owner
pub const OWNER: Item<Addr> = Item::new("owner");
