use cosmwasm_std::Addr;
use cw_storage_plus::Item;
use utils::RoleManagement;

pub const AGENT_ROLES: RoleManagement = RoleManagement::new("agent_roles");
pub const OWNER: Item<Addr> = Item::new("owner");
pub const TOKEN: Item<Addr> = Item::new("token");
