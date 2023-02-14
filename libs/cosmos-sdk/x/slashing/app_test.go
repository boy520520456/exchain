// nolint
// DONTCOVER
package slashing

import (
	"errors"
	"testing"

	abci "github.com/okex/exchain/libs/tendermint/abci/types"
	"github.com/okex/exchain/libs/tendermint/crypto/secp256k1"
	"github.com/stretchr/testify/require"

	sdk "github.com/okex/exchain/libs/cosmos-sdk/types"
	"github.com/okex/exchain/libs/cosmos-sdk/x/auth"
	authexported "github.com/okex/exchain/libs/cosmos-sdk/x/auth/exported"
	"github.com/okex/exchain/libs/cosmos-sdk/x/bank"
	"github.com/okex/exchain/libs/cosmos-sdk/x/mock"
	"github.com/okex/exchain/libs/cosmos-sdk/x/staking"
	"github.com/okex/exchain/libs/cosmos-sdk/x/staking/types"
	"github.com/okex/exchain/libs/cosmos-sdk/x/supply"
	supplyexported "github.com/okex/exchain/libs/cosmos-sdk/x/supply/exported"
)

var (
	priv1 = secp256k1.GenPrivKey()
	addr1 = sdk.AccAddress(priv1.PubKey().Address())
	coins = sdk.Coins{sdk.NewInt64Coin("foocoin", 10)}
)

// initialize the mock application for this module
func getMockApp(t *testing.T) (*mock.App, staking.Keeper, Keeper) {
	mapp := mock.NewApp()

	RegisterCodec(mapp.Cdc.GetCdc())
	staking.RegisterCodec(mapp.Cdc.GetCdc())
	supply.RegisterCodec(mapp.Cdc.GetCdc())

	keyStaking := sdk.NewKVStoreKey(staking.StoreKey)
	keySlashing := sdk.NewKVStoreKey(StoreKey)
	keySupply := sdk.NewKVStoreKey(supply.StoreKey)

	feeCollector := supply.NewEmptyModuleAccount(auth.FeeCollectorName)
	notBondedPool := supply.NewEmptyModuleAccount(types.NotBondedPoolName, supply.Burner, supply.Staking)
	bondPool := supply.NewEmptyModuleAccount(types.BondedPoolName, supply.Burner, supply.Staking)

	blacklistedAddrs := make(map[string]bool)
	blacklistedAddrs[feeCollector.GetAddress().String()] = true
	blacklistedAddrs[notBondedPool.GetAddress().String()] = true
	blacklistedAddrs[bondPool.GetAddress().String()] = true

	bankKeeper := bank.NewBaseKeeper(mapp.AccountKeeper, mapp.ParamsKeeper.Subspace(bank.DefaultParamspace), blacklistedAddrs)
	maccPerms := map[string][]string{
		auth.FeeCollectorName:     nil,
		staking.NotBondedPoolName: {supply.Burner, supply.Staking},
		staking.BondedPoolName:    {supply.Burner, supply.Staking},
	}
	supplyKeeper := supply.NewKeeper(mapp.Cdc.GetCdc(), keySupply, mapp.AccountKeeper, bank.NewBankKeeperAdapter(bankKeeper), maccPerms)
	stakingKeeper := staking.NewKeeper(mapp.Cdc.GetCdc(), keyStaking, supplyKeeper, mapp.ParamsKeeper.Subspace(staking.DefaultParamspace))
	keeper := NewKeeper(mapp.Cdc.GetCdc(), keySlashing, stakingKeeper, mapp.ParamsKeeper.Subspace(DefaultParamspace))
	mapp.Router().AddRoute(staking.RouterKey, staking.NewHandler(stakingKeeper))
	mapp.Router().AddRoute(RouterKey, NewHandler(keeper))

	mapp.SetEndBlocker(getEndBlocker(stakingKeeper))
	mapp.SetInitChainer(getInitChainer(mapp, stakingKeeper, mapp.AccountKeeper, supplyKeeper,
		[]supplyexported.ModuleAccountI{feeCollector, notBondedPool, bondPool}))

	require.NoError(t, mapp.CompleteSetup(keyStaking, keySupply, keySlashing))

	return mapp, stakingKeeper, keeper
}

// staking endblocker
func getEndBlocker(keeper staking.Keeper) sdk.EndBlocker {
	return func(ctx sdk.Context, req abci.RequestEndBlock) abci.ResponseEndBlock {
		validatorUpdates := staking.EndBlocker(ctx, keeper)
		return abci.ResponseEndBlock{
			ValidatorUpdates: validatorUpdates,
		}
	}
}

// overwrite the mock init chainer
func getInitChainer(mapp *mock.App, keeper staking.Keeper, accountKeeper types.AccountKeeper, supplyKeeper types.SupplyKeeper,
	blacklistedAddrs []supplyexported.ModuleAccountI) sdk.InitChainer {
	return func(ctx sdk.Context, req abci.RequestInitChain) abci.ResponseInitChain {
		// set module accounts
		for _, macc := range blacklistedAddrs {
			supplyKeeper.SetModuleAccount(ctx, macc)
		}

		mapp.InitChainer(ctx, req)
		stakingGenesis := staking.DefaultGenesisState()
		validators := staking.InitGenesis(ctx, keeper, accountKeeper, supplyKeeper, stakingGenesis)
		return abci.ResponseInitChain{
			Validators: validators,
		}
	}
}

func checkValidator(t *testing.T, mapp *mock.App, keeper staking.Keeper,
	addr sdk.AccAddress, expFound bool) staking.Validator {
	ctxCheck := mapp.BaseApp.NewContext(true, abci.Header{})
	validator, found := keeper.GetValidator(ctxCheck, sdk.ValAddress(addr1))
	require.Equal(t, expFound, found)
	return validator
}

func checkValidatorSigningInfo(t *testing.T, mapp *mock.App, keeper Keeper,
	addr sdk.ConsAddress, expFound bool) ValidatorSigningInfo {
	ctxCheck := mapp.BaseApp.NewContext(true, abci.Header{})
	signingInfo, found := keeper.GetValidatorSigningInfo(ctxCheck, addr)
	require.Equal(t, expFound, found)
	return signingInfo
}

func TestSlashingMsgs(t *testing.T) {
	mapp, stakingKeeper, keeper := getMockApp(t)

	genTokens := sdk.TokensFromConsensusPower(42)
	bondTokens := sdk.TokensFromConsensusPower(10)
	genCoin := sdk.NewCoin(sdk.DefaultBondDenom(), genTokens)
	bondCoin := sdk.NewCoin(sdk.DefaultBondDenom(), bondTokens)

	acc1 := &auth.BaseAccount{
		Address: addr1,
		Coins:   sdk.Coins{genCoin},
	}
	accs := []authexported.Account{acc1}
	mock.SetGenesis(mapp, accs)
	mapp.BeginBlock(abci.RequestBeginBlock{Header: abci.Header{Height: mapp.LastBlockHeight() + 1}})
	mapp.EndBlock(abci.RequestEndBlock{})
	mapp.Commit(abci.RequestCommit{})

	description := staking.NewDescription("foo_moniker", "", "", "", "")
	commission := staking.NewCommissionRates(sdk.ZeroDec(), sdk.ZeroDec(), sdk.ZeroDec())

	createValidatorMsg := staking.NewMsgCreateValidator(
		sdk.ValAddress(addr1), priv1.PubKey(), bondCoin, description, commission, sdk.OneInt(),
	)

	header := abci.Header{Height: mapp.LastBlockHeight() + 1}
	mock.SignCheckDeliver(t, mapp.Cdc.GetCdc(), mapp.BaseApp, header, []sdk.Msg{createValidatorMsg}, []uint64{0}, []uint64{0}, true, true, priv1)
	mock.CheckBalance(t, mapp, addr1, sdk.Coins{genCoin.Sub(bondCoin).Sub(sdk.NewDecCoin(sdk.DefaultBondDenom(), sdk.OneInt()))})

	header = abci.Header{Height: mapp.LastBlockHeight() + 1}
	mapp.BeginBlock(abci.RequestBeginBlock{Header: header})

	validator := checkValidator(t, mapp, stakingKeeper, addr1, true)
	require.Equal(t, sdk.ValAddress(addr1), validator.OperatorAddress)
	require.Equal(t, sdk.Bonded, validator.Status)
	require.True(sdk.IntEq(t, bondTokens, validator.BondedTokens()))
	unjailMsg := MsgUnjail{ValidatorAddr: sdk.ValAddress(validator.ConsPubKey.Address())}

	// no signing info yet
	checkValidatorSigningInfo(t, mapp, keeper, sdk.ConsAddress(addr1), false)

	// unjail should fail with unknown validator
	header = abci.Header{Height: mapp.LastBlockHeight() + 1}
	_, res, err := mock.SignCheckDeliver(t, mapp.Cdc.GetCdc(), mapp.BaseApp, header, []sdk.Msg{unjailMsg}, []uint64{0}, []uint64{1}, false, false, priv1)
	require.Error(t, err)
	require.Nil(t, res)
	require.True(t, errors.Is(ErrValidatorNotJailed, err))
}
