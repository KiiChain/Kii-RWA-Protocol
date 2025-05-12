use cosmwasm_std::Addr;
use cw_storage_plus::Item;

pub const OWNER_ROLES_ADDRESS: Item<Addr> = Item::new("owner_role_contract_address");
pub const IDENTITY_ADDRESS: Item<Addr> = Item::new("identity_addr");
pub const CLAIM_TOPICS_ADDRESS: Item<Addr> = Item::new("claims_topics");
