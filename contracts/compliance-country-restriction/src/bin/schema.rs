use compliance_country_restriction::{ExecuteMsg, InstantiateMsg};
use cosmwasm_schema::write_api;
use utils::compliance::QueryMsg;

fn main() {
    write_api! {
        instantiate: InstantiateMsg,
        execute: ExecuteMsg,
        query: QueryMsg,
    }
}
