#[cfg(not(feature = "library"))]
use cosmwasm_std::entry_point;
use cosmwasm_std::{to_binary, Binary, Deps, DepsMut, Env, MessageInfo, Response, StdResult};

use crate::error::ContractError;
use crate::msg::{ExecuteMsg, InstantiateMsg, QueryMsg};
use crate::state::{COUNTER_VALUE};


#[cfg_attr(not(feature = "library"), entry_point)]
pub fn instantiate(
    _deps: DepsMut,
    _env: Env,
    _info: MessageInfo,
    _msg: InstantiateMsg,
) -> Result<Response, ContractError> {
    // let counter:Uint256 = Uint256::zero();
    // COUNTER_VALUE.save(deps.storage, &counter)?;
    Ok(Response::new())
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn execute(
    deps: DepsMut,
    _env: Env,
    _info: MessageInfo,
    msg: ExecuteMsg,
) -> Result<Response, ContractError> {
    match msg {
        ExecuteMsg::Add { delta } => try_add(deps,delta),
        ExecuteMsg::Subtract {} => try_sub(deps),
    }
}

pub fn try_add(deps: DepsMut,delta:i32) -> Result<Response, ContractError> {
    COUNTER_VALUE.save(deps.storage,delta,&delta)?;
    Ok(Response::new().add_attribute("Added", "123"))
}

pub fn try_sub(_deps: DepsMut) -> Result<Response, ContractError> {
    Ok(Response::new())
}


#[cfg_attr(not(feature = "library"), entry_point)]
pub fn query(deps: Deps, _env: Env, msg: QueryMsg) -> StdResult<Binary> {
    match msg {
        QueryMsg::GetCounter {delta} => to_binary(&query_count(deps,delta)?),
    }
}
fn query_count(deps: Deps,delta:i32) -> StdResult<i32> {
    if let Some(info) = COUNTER_VALUE.may_load(deps.storage, delta)? {
        Ok(info)
    } else {
        Ok(0)
    }
}
