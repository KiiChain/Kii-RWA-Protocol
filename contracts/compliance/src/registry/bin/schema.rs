use cosmwasm_schema::write_api;

use compliance::{
    msg::{ExecuteMsg, InstantiateMsg},
    QueryMsg,
};

fn main() {
    write_api! {
        instantiate: InstantiateMsg,
        execute: ExecuteMsg,
        query: QueryMsg,
    }
}
