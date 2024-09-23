use cosmwasm_std::{Addr, StdResult, Storage};
use cw_storage_plus::Map;

pub struct RoleManagement {
    roles: Map<(String, Addr), bool>,
}

impl RoleManagement {
    pub const fn new(namespace: &'static str) -> Self {
        Self {
            roles: Map::new(namespace),
        }
    }

    pub fn add_role(
        &self,
        storage: &mut dyn Storage,
        role: String,
        address: Addr,
    ) -> StdResult<()> {
        self.roles.save(storage, (role, address), &true)
    }

    pub fn remove_role(
        &self,
        storage: &mut dyn Storage,
        role: String,
        address: Addr,
    ) -> StdResult<()> {
        self.roles.remove(storage, (role, address));
        Ok(())
    }

    pub fn has_role(&self, storage: &dyn Storage, role: String, address: Addr) -> StdResult<bool> {
        Ok(self
            .roles
            .may_load(storage, (role, address))?
            .unwrap_or(false))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cosmwasm_std::testing::MockStorage;

    #[test]
    fn test_add_role() {
        let mut storage = MockStorage::new();
        let role_management = RoleManagement::new("roles");
        let role = "admin".to_string();
        let address = Addr::unchecked("user1");

        assert!(role_management
            .add_role(&mut storage, role.clone(), address.clone())
            .is_ok());
        assert!(role_management.has_role(&storage, role, address).unwrap());
    }

    #[test]
    fn test_remove_role() {
        let mut storage = MockStorage::new();
        let role_management = RoleManagement::new("roles");
        let role = "admin".to_string();
        let address = Addr::unchecked("user1");

        role_management
            .add_role(&mut storage, role.clone(), address.clone())
            .unwrap();
        assert!(role_management
            .remove_role(&mut storage, role.clone(), address.clone())
            .is_ok());
        assert!(!role_management.has_role(&storage, role, address).unwrap());
    }

    #[test]
    fn test_has_role() {
        let mut storage = MockStorage::new();
        let role_management = RoleManagement::new("roles");
        let role = "admin".to_string();
        let address = Addr::unchecked("user1");

        assert!(!role_management
            .has_role(&storage, role.clone(), address.clone())
            .unwrap());
        role_management
            .add_role(&mut storage, role.clone(), address.clone())
            .unwrap();
        assert!(role_management.has_role(&storage, role, address).unwrap());
    }
}
