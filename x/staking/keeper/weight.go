package keeper

import (
	"fmt"
	"math"

	sdk "github.com/okex/exchain/libs/cosmos-sdk/types"
	types2 "github.com/okex/exchain/libs/tendermint/types"
	"github.com/okex/exchain/x/staking/types"
)

const (
	// UTC Time: 2000/1/1 00:00:00
	blockTimestampEpoch = int64(946684800)
	secondsPerWeek      = int64(60 * 60 * 24 * 7)
	weeksPerYear        = float64(52)
	NewTimeStamp        = int64(1672502400)
)

func calculateWeight(nowTime int64, tokens sdk.Dec, height int64) (shares types.Shares, sdkErr error) {
	var nowWeek int64
	if types2.HigherThanVenus4(height) {
		nowWeek = (NewTimeStamp - blockTimestampEpoch) / secondsPerWeek
	} else {
		nowWeek = (nowTime - blockTimestampEpoch) / secondsPerWeek
	}

	rate := float64(nowWeek) / weeksPerYear
	weight := math.Pow(float64(2), rate)

	precision := fmt.Sprintf("%d", sdk.Precision)

	weightByDec, sdkErr := sdk.NewDecFromStr(fmt.Sprintf("%."+precision+"f", weight))
	if sdkErr == nil {
		shares = tokens.Mul(weightByDec)
	}
	return
}

func SimulateWeight(nowTime int64, tokens sdk.Dec, height int64) (votes types.Shares, sdkErr error) {
	return calculateWeight(nowTime, tokens, height)
}
