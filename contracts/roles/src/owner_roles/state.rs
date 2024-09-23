use crate::role_management::RoleManagement;
use cosmwasm_std::Addr;
use cw_storage_plus::Item;

pub const OWNER_ROLES: RoleManagement = RoleManagement::new("owner_roles");
pub const OWNER: Item<Addr> = Item::new("owner");
