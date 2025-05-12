use cosmwasm_std::{Addr, StdResult, Storage};
use cw_storage_plus::Map;

/// RoleManagement struct provides a reusable way to manage roles within CosmWasm contracts.
/// It uses a Map to store role assignments, where each entry associates a (role, address) pair
/// with a boolean value indicating whether the address has the role.
pub struct RoleManagement {
    roles: Map<(String, Addr), bool>,
}

impl RoleManagement {
    /// Creates a new instance of RoleManagement.
    ///
    /// # Arguments
    ///
    /// * `namespace` - A string slice that holds the namespace for this instance.
    ///   This allows multiple contracts to use RoleManagement without conflicting storage.
    ///
    /// # Returns
    ///
    /// A new instance of RoleManagement.
    pub const fn new(namespace: &'static str) -> Self {
        Self {
            roles: Map::new(namespace),
        }
    }

    /// Adds a role to an address.
    ///
    /// # Arguments
    ///
    /// * `storage` - A mutable reference to the contract's storage.
    /// * `role` - The role to be assigned.
    /// * `address` - The address to which the role is being assigned.
    ///
    /// # Returns
    ///
    /// A `StdResult<()>` which is Ok if the operation was successful, Err otherwise.
    pub fn add_role(
        &self,
        storage: &mut dyn Storage,
        role: String,
        address: Addr,
    ) -> StdResult<()> {
        self.roles.save(storage, (role, address), &true)
    }

    /// Removes a role from an address.
    ///
    /// # Arguments
    ///
    /// * `storage` - A mutable reference to the contract's storage.
    /// * `role` - The role to be removed.
    /// * `address` - The address from which the role is being removed.
    ///
    /// # Returns
    ///
    /// A `StdResult<()>` which is Ok if the operation was successful, Err otherwise.
    pub fn remove_role(
        &self,
        storage: &mut dyn Storage,
        role: String,
        address: Addr,
    ) -> StdResult<()> {
        self.roles.remove(storage, (role, address));
        Ok(())
    }

    /// Checks if an address has a specific role.
    ///
    /// # Arguments
    ///
    /// * `storage` - A reference to the contract's storage.
    /// * `role` - The role to check for.
    /// * `address` - The address to check.
    ///
    /// # Returns
    ///
    /// A `StdResult<bool>` which is Ok(true) if the address has the role, Ok(false) otherwise.
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
