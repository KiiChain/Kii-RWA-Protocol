use cosmwasm_std::Addr;
use cw_storage_plus::{Item, Map};

// Owner, (identity address, country)
pub const IDENTITIES: Map<Addr, (Addr, String)> = Map::new("identities");

// Owner, Vec<AgentAddress>
pub const AGENTS: Map<Addr, Vec<Addr>> = Map::new("agents");

// Contract owner
pub const OWNER: Item<Addr> = Item::new("owner");