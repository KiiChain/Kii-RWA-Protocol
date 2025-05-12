use agent_roles::{ExecuteMsg, InstantiateMsg};
use cosmwasm_schema::write_api;
use utils::agent_roles::QueryMsg;

fn main() {
    write_api! {
        instantiate: InstantiateMsg,
        execute: ExecuteMsg,
        query: QueryMsg,
    }
}
