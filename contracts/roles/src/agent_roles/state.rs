use crate::role_management::RoleManagement;
use cosmwasm_std::Addr;
use cw_storage_plus::Item;

pub const AGENT_ROLES: RoleManagement = RoleManagement::new("agent_roles");
pub const OWNER: Item<Addr> = Item::new("owner");
pub const TOKEN: Item<Addr> = Item::new("token");
