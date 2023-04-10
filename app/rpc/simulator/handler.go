package simulator

import (
	sdk "github.com/okex/exchain/libs/cosmos-sdk/types"
)

type Simulator interface {
	Simulate([]sdk.Msg) (*sdk.Result, error)
	Context() *sdk.Context
	Release()
	Reset()
}

var NewWasmSimulator func() Simulator
