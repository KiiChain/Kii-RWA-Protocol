use cw_storage_plus::{Item, Map};
use crate::types::{Identity, Key, Claim};

pub const IDENTITY: Map<&[u8], Identity> = Map::new("identity");
pub const KEYS: Map<(&[u8], &[u8]), Key> = Map::new("keys");
pub const CLAIMS: Map<(&[u8], &[u8]), Claim> = Map::new("claims");
