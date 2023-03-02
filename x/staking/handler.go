package staking

import (
	"fmt"

	sdk "github.com/okex/exchain/libs/cosmos-sdk/types"
	tmtypes "github.com/okex/exchain/libs/tendermint/types"
	"github.com/okex/exchain/x/staking/keeper"
	"github.com/okex/exchain/x/staking/types"
)

// NewHandler manages all tx treatment
func NewHandler(k keeper.Keeper) sdk.Handler {
	return func(ctx sdk.Context, msg sdk.Msg) (*sdk.Result, error) {
		ctx.SetEventManager(sdk.NewEventManager())
		errMsg := fmt.Sprintf("unrecognized staking message type: %T", msg)

		if !k.CheckEnabled(ctx) {
			return nil, types.ErrCodeDisabledOperate()
		}

		switch msg := msg.(type) {
		case types.MsgCreateValidator:
			if !k.GetParams(ctx).EnableOperation {
				return nil, types.ErrDisableOperation
			}
			return handleMsgCreateValidator(ctx, msg, k)
		case types.MsgEditValidator:
			return handleMsgEditValidator(ctx, msg, k)
		case types.MsgEditValidatorCommissionRate:
			if !k.GetParams(ctx).EnableOperation {
				return nil, types.ErrDisableOperation
			}
			return handleMsgEditValidatorCommissionRate(ctx, msg, k)
		case types.MsgDeposit:
			if !k.GetParams(ctx).EnableOperation {
				return nil, types.ErrDisableOperation
			}
			return handleMsgDeposit(ctx, msg, k)
		case types.MsgWithdraw:
			return handleMsgWithdraw(ctx, msg, k)
		case types.MsgAddShares:
			if !k.GetParams(ctx).EnableOperation {
				return nil, types.ErrDisableOperation
			}
			return handleMsgAddShares(ctx, msg, k)
		//case types.MsgBindProxy:
		//	return handleMsgBindProxy(ctx, msg, k)
		//case types.MsgUnbindProxy:
		//	return handleMsgUnbindProxy(ctx, msg, k)
		//case types.MsgRegProxy:
		//	return handleRegProxy(ctx, msg, k)
		case types.MsgDestroyValidator:
			return handleMsgDestroyValidator(ctx, msg, k)
		default:
			return sdk.ErrUnknownRequest(errMsg).Result()
		}
	}
}

// StringInSlice returns true if a is found the list.
func StringInSlice(a string, list []string) bool {
	for _, b := range list {
		if b == a {
			return true
		}
	}
	return false
}

// These functions assumes everything has been authenticated, now we just perform action and save
func handleMsgCreateValidator(ctx sdk.Context, msg types.MsgCreateValidator, k keeper.Keeper) (*sdk.Result, error) {
	if _, found := k.GetValidator(ctx, msg.ValidatorAddress); found {
		return nil, ErrValidatorOwnerExists()
	}
	if _, found := k.GetValidatorByConsAddr(ctx, sdk.GetConsAddress(msg.PubKey)); found {
		return nil, ErrValidatorPubKeyExists()
	}
	if msg.MinSelfDelegation.Denom != k.BondDenom(ctx) {
		return nil, ErrBadDenom()
	}

	if _, err := msg.Description.EnsureLength(); err != nil {
		return nil, err
	}
	if ctx.ConsensusParams() != nil {
		tmPubKey := tmtypes.TM2PB.PubKey(msg.PubKey)
		if !StringInSlice(tmPubKey.Type, ctx.ConsensusParams().Validator.PubKeyTypes) {
			return nil, ErrValidatorPubKeyTypeNotSupported(tmPubKey.Type,
				ctx.ConsensusParams().Validator.PubKeyTypes)
		}
	}

	minSelfDelegation := k.ParamsMinSelfDelegation(ctx)
	validator := NewValidator(msg.ValidatorAddress, msg.PubKey, msg.Description, minSelfDelegation)
	commission := NewCommission(sdk.NewDec(1), sdk.NewDec(1), sdk.NewDec(0))
	validator, err := validator.SetInitialCommission(commission)
	if err != nil {
		return nil, err
	}
	k.SetValidator(ctx, validator)
	k.SetValidatorByConsAddr(ctx, validator)
	k.SetNewValidatorByPowerIndex(ctx, validator)
	// add shares of equal value of msd for validator itself
	defaultMinSelfDelegationToken := sdk.NewDecCoinFromDec(k.BondDenom(ctx), validator.MinSelfDelegation)
	if err = k.AddSharesAsMinSelfDelegation(ctx, msg.DelegatorAddress, &validator, defaultMinSelfDelegationToken); err != nil {
		return nil, err
	}
	k.AfterValidatorCreated(ctx, validator.OperatorAddress)
	ctx.EventManager().EmitEvents(sdk.Events{
		sdk.NewEvent(types.EventTypeCreateValidator,
			sdk.NewAttribute(types.AttributeKeyValidator, msg.ValidatorAddress.String()),
			sdk.NewAttribute(sdk.AttributeKeyAmount, msg.MinSelfDelegation.Amount.String())),
		sdk.NewEvent(sdk.EventTypeMessage,
			sdk.NewAttribute(sdk.AttributeKeyModule, types.AttributeValueCategory),
			sdk.NewAttribute(sdk.AttributeKeySender, msg.DelegatorAddress.String())),
	})
	return &sdk.Result{Events: ctx.EventManager().Events()}, nil
}

func handleMsgEditValidator(ctx sdk.Context, msg types.MsgEditValidator, k keeper.Keeper) (*sdk.Result, error) {
	// validator must already be registered
	validator, found := k.GetValidator(ctx, msg.ValidatorAddress)
	if !found {
		return nil, ErrNoValidatorFound(msg.ValidatorAddress.String())
	}

	// replace all editable fields (clients should autofill existing values)
	description, err := validator.Description.UpdateDescription(msg.Description)
	if err != nil {
		return nil, err
	}

	validator.Description = description

	k.SetValidator(ctx, validator)

	ctx.EventManager().EmitEvents(sdk.Events{
		sdk.NewEvent(types.EventTypeEditValidator,
			sdk.NewAttribute(types.AttributeKeyMinSelfDelegation, validator.MinSelfDelegation.String()),
		),
		sdk.NewEvent(sdk.EventTypeMessage,
			sdk.NewAttribute(sdk.AttributeKeyModule, types.AttributeValueCategory),
			sdk.NewAttribute(sdk.AttributeKeySender, msg.ValidatorAddress.String()),
		),
	})

	return &sdk.Result{Events: ctx.EventManager().Events()}, nil
}
