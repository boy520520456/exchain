package keeper

import (
	"fmt"
	"github.com/nacos-group/nacos-sdk-go/common/logger"
	sdk "github.com/okex/exchain/libs/cosmos-sdk/types"
	tmtypes "github.com/okex/exchain/libs/tendermint/types"

	"github.com/okex/exchain/x/distribution/types"
	"github.com/okex/exchain/x/staking/exported"
)

// initialize rewards for a new validator
func (k Keeper) initializeValidator(ctx sdk.Context, val exported.ValidatorI) {
	if !tmtypes.HigherThanSaturn1(ctx.BlockHeight()) || !k.HasInitAllocateValidator(ctx) {
		// set accumulated commissions
		k.SetValidatorAccumulatedCommission(ctx, val.GetOperator(), types.InitialValidatorAccumulatedCommission())
		return
	}

	// set initial historical rewards (period 0) with reference count of 1
	k.SetValidatorHistoricalRewards(ctx, val.GetOperator(), 0, types.NewValidatorHistoricalRewards(sdk.SysCoins{}, 1))

	// set current rewards (starting at period 1)
	k.SetValidatorCurrentRewards(ctx, val.GetOperator(), types.NewValidatorCurrentRewards(sdk.SysCoins{}, 1))

	// set accumulated commissions
	k.SetValidatorAccumulatedCommission(ctx, val.GetOperator(), types.InitialValidatorAccumulatedCommission())

	// set outstanding rewards
	k.SetValidatorOutstandingRewards(ctx, val.GetOperator(), sdk.SysCoins{})
}

func (k Keeper) checkNotExistAndInitializeValidator(ctx sdk.Context, val exported.ValidatorI) {
	if k.HasValidatorOutstandingRewards(ctx, val.GetOperator()) {
		logger.Debug(fmt.Sprintf("has validator, %s", val.GetOperator().String()))
		return
	}

	// set initial historical rewards (period 0) with reference count of 1
	k.SetValidatorHistoricalRewards(ctx, val.GetOperator(), 0, types.NewValidatorHistoricalRewards(sdk.SysCoins{}, 1))

	// set current rewards (starting at period 1)
	k.SetValidatorCurrentRewards(ctx, val.GetOperator(), types.NewValidatorCurrentRewards(sdk.SysCoins{}, 1))

	// get accumulated commissions
	commission := k.GetValidatorAccumulatedCommission(ctx, val.GetOperator())

	// set outstanding rewards with commission
	k.SetValidatorOutstandingRewards(ctx, val.GetOperator(), commission)

	logger.Debug(fmt.Sprintf("set val: %s, commission:%s, historical reward period: 0, cur.", val.GetOperator().String(), commission.String()))
}

// increment validator period, returning the period just ended
func (k Keeper) incrementValidatorPeriod(ctx sdk.Context, val exported.ValidatorI) uint64 {
	if !tmtypes.HigherThanSaturn1(ctx.BlockHeight()) || !k.HasInitAllocateValidator(ctx) {
		return 0
	}

	logger := k.Logger(ctx)
	// fetch current rewards
	rewards := k.GetValidatorCurrentRewards(ctx, val.GetOperator())

	logger.Debug(fmt.Sprintf("increment val period %s, cur period:%d, cur reward:%s", val.GetOperator().String(), rewards.Period, rewards.Rewards.String()))

	// calculate current ratio
	var current sdk.SysCoins
	if val.GetDelegatorShares().IsZero() {
		// can't calculate ratio for zero-shares validators
		// ergo we instead add to the community pool
		feePool := k.GetFeePool(ctx)
		outstanding := k.GetValidatorOutstandingRewards(ctx, val.GetOperator())
		feePool.CommunityPool = feePool.CommunityPool.Add(rewards.Rewards...)
		outstanding = outstanding.Sub(rewards.Rewards)
		k.SetFeePool(ctx, feePool)
		k.SetValidatorOutstandingRewards(ctx, val.GetOperator(), outstanding)

		current = sdk.SysCoins{}
		logger.Debug(fmt.Sprintf("delegator shares is zero, add to the community pool, val:%s", val.GetOperator().String()))
	} else {
		// note: necessary to truncate so we don't allow withdrawing more rewards than owed
		current = rewards.Rewards.QuoDecTruncate(val.GetDelegatorShares())
	}

	// fetch historical rewards for last period
	historical := k.GetValidatorHistoricalRewards(ctx, val.GetOperator(), rewards.Period-1).CumulativeRewardRatio

	// decrement reference count
	k.decrementReferenceCount(ctx, val.GetOperator(), rewards.Period-1)

	// set new historical rewards with reference count of 1
	k.SetValidatorHistoricalRewards(ctx, val.GetOperator(), rewards.Period, types.NewValidatorHistoricalRewards(historical.Add(current...), 1))

	// set current rewards, incrementing period by 1
	k.SetValidatorCurrentRewards(ctx, val.GetOperator(), types.NewValidatorCurrentRewards(sdk.SysCoins{}, rewards.Period+1))

	logger.Debug(fmt.Sprintf("increment period val:%s, current reward ratio:%s, historical:%s, val shares:%s",
		val.GetOperator().String(), current.String(), historical.String(), val.GetDelegatorShares()))
	return rewards.Period
}

// increment the reference count for a historical rewards value
func (k Keeper) incrementReferenceCount(ctx sdk.Context, valAddr sdk.ValAddress, period uint64) {
	historical := k.GetValidatorHistoricalRewards(ctx, valAddr, period)
	if historical.ReferenceCount > 2 {
		panic("reference count should never exceed 2")
	}
	historical.ReferenceCount++
	logger := k.Logger(ctx)
	logger.Debug(fmt.Sprintf("increment reference count, val:%s, period:%d, count:%d", valAddr.String(), period, historical.ReferenceCount))
	k.SetValidatorHistoricalRewards(ctx, valAddr, period, historical)
}

// increment the reference count for a historical rewards value for old delegator
func (k Keeper) incrementReferenceCountOldDelegator(ctx sdk.Context, valAddr sdk.ValAddress, period uint64) {
	historical := k.GetValidatorHistoricalRewards(ctx, valAddr, period)
	if historical.ReferenceCount > 3 {
		panic("reference count should never exceed 3")
	}
	historical.ReferenceCount += 2
	logger := k.Logger(ctx)
	logger.Debug(fmt.Sprintf("increment reference count, val:%s, period:%d, count:%d", valAddr.String(), period, historical.ReferenceCount))
	k.SetValidatorHistoricalRewards(ctx, valAddr, period, historical)
}

// decrement the reference count for a historical rewards value, and delete if zero references remain
func (k Keeper) decrementReferenceCount(ctx sdk.Context, valAddr sdk.ValAddress, period uint64) {
	historical := k.GetValidatorHistoricalRewards(ctx, valAddr, period)
	if historical.ReferenceCount == 0 {
		panic("cannot set negative reference count")
	}
	historical.ReferenceCount--
	logger := k.Logger(ctx)
	logger.Debug(fmt.Sprintf("increment reference count, val:%s, period:%d, count:%d", valAddr.String(), period, historical.ReferenceCount))
	if historical.ReferenceCount == 0 {
		k.DeleteValidatorHistoricalReward(ctx, valAddr, period)
	} else {
		k.SetValidatorHistoricalRewards(ctx, valAddr, period, historical)
	}
}
