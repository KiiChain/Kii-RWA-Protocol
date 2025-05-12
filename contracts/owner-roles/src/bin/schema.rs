use cosmwasm_schema::write_api;
use owner_roles::{ExecuteMsg, InstantiateMsg};
use utils::owner_roles::QueryMsg;

fn main() {
    write_api! {
        instantiate: InstantiateMsg,
        execute: ExecuteMsg,
        query: QueryMsg,
    }
}
