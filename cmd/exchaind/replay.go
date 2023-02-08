package main

import (
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/okex/exchain/app"
	"github.com/okex/exchain/cmd/exchaind/base"
	sdkerrors "github.com/okex/exchain/libs/cosmos-sdk/types/errors"
	"log"
	"math/big"
	"net/http"
	_ "net/http/pprof"
	"os"
	"path/filepath"
	"runtime"
	"runtime/pprof"
	"sync"
	"time"

	evmtypes "github.com/okex/exchain/x/evm/types"
	"github.com/okex/exchain/x/evm/watcher"

	"github.com/gogo/protobuf/jsonpb"
	okxCodeC "github.com/okex/exchain/app/codec"
	"github.com/okex/exchain/app/config"
	"github.com/okex/exchain/libs/cosmos-sdk/baseapp"
	"github.com/okex/exchain/libs/cosmos-sdk/client/lcd"
	"github.com/okex/exchain/libs/cosmos-sdk/codec"
	"github.com/okex/exchain/libs/cosmos-sdk/server"
	sdk "github.com/okex/exchain/libs/cosmos-sdk/types"
	"github.com/okex/exchain/libs/iavl"
	"github.com/okex/exchain/libs/system/trace"
	abci "github.com/okex/exchain/libs/tendermint/abci/types"
	tcmd "github.com/okex/exchain/libs/tendermint/cmd/tendermint/commands"
	"github.com/okex/exchain/libs/tendermint/global"
	"github.com/okex/exchain/libs/tendermint/mock"
	"github.com/okex/exchain/libs/tendermint/node"
	"github.com/okex/exchain/libs/tendermint/proxy"
	sm "github.com/okex/exchain/libs/tendermint/state"
	"github.com/okex/exchain/libs/tendermint/store"
	"github.com/okex/exchain/libs/tendermint/types"
	dbm "github.com/okex/exchain/libs/tm-db"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

const (
	replayedBlockDir = "replayed_block_dir"
	applicationDB    = "application"
	blockStoreDB     = "blockstore"
	stateDB          = "state"

	pprofAddrFlag       = "pprof_addr"
	runWithPprofFlag    = "gen_pprof"
	runWithPprofMemFlag = "gen_pprof_mem"
	FlagEnableRest      = "rest"

	saveBlock = "save_block"

	defaulPprofFileFlags = os.O_RDWR | os.O_CREATE | os.O_APPEND
	defaultPprofFilePerm = 0644
)

func replayCmd(ctx *server.Context, registerAppFlagFn func(cmd *cobra.Command),
	cdc *codec.CodecProxy, appCreator server.AppCreator, registry jsonpb.AnyResolver,
	registerRoutesFn func(restServer *lcd.RestServer)) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "replay",
		Short: "Replay blocks from local db",
		PreRunE: func(cmd *cobra.Command, args []string) error {
			// set external package flags
			//log.Println("--------- replay preRun ---------")
			//err := sanity.CheckStart()
			//if err != nil {
			//	fmt.Println(err)
			//	return err
			//}
			//iavl.SetEnableFastStorage(appstatus.IsFastStorageStrategy())
			//server.SetExternalPackageValue(cmd)
			//types.InitSignatureCache()
			return nil
		},
		Run: func(cmd *cobra.Command, args []string) {
			log.Println("--------- replay start ---------")
			pprofAddress := viper.GetString(pprofAddrFlag)
			go func() {
				err := http.ListenAndServe(pprofAddress, nil)
				if err != nil {
					fmt.Println(err)
				}
			}()
			dataDir := viper.GetString(replayedBlockDir)

			var node *node.Node
			if viper.GetBool(FlagEnableRest) {
				var err error
				log.Println("--------- StartRestWithNode ---------")
				node, err = server.StartRestWithNode(ctx, cdc, dataDir, registry, appCreator, registerRoutesFn)
				if err != nil {
					fmt.Println(err)
					return
				}

			}

			ts := time.Now()
			replayBlock(ctx, dataDir, node)
			log.Println("--------- replay success ---------", "Time Cost", time.Now().Sub(ts).Seconds())
		},
		PostRun: func(cmd *cobra.Command, args []string) {
			if viper.GetBool(runWithPprofMemFlag) {
				log.Println("--------- gen pprof mem start ---------")
				err := dumpMemPprof()
				if err != nil {
					log.Println(err)
				} else {
					log.Println("--------- gen pprof mem success ---------")
				}
			}
		},
	}

	server.RegisterServerFlags(cmd)
	registerAppFlagFn(cmd)
	// add support for all Tendermint-specific command line options
	tcmd.AddNodeFlags(cmd)
	registerReplayFlags(cmd)
	return cmd
}

func checkerr(err error) {
	if err != nil {
		panic(err)
	}
}

func getSenderFromEvent(events []abci.Event) (string, error) {
	for _, ev := range events {
		if ev.Type == sdk.EventTypeMessage {
			fromAddr := ""
			realEvmTx := false
			for _, attr := range ev.Attributes {
				if string(attr.Key) == sdk.AttributeKeySender {
					fromAddr = string(attr.Value)
				}
				if string(attr.Key) == sdk.AttributeKeyModule &&
					string(attr.Value) == evmtypes.AttributeValueCategory { // to avoid the evm to cm tx enter
					realEvmTx = true
				}
				// find the sender
				if fromAddr != "" && realEvmTx {
					return fromAddr, nil
				}
			}
		}
	}
	return "", errors.New("No sender in Event")
}

// RawTxToEthTx returns a evm MsgEthereum transaction from raw tx bytes.
func RawTxToEthTx(clientCtx *codec.Codec, bz []byte, height int64) (*evmtypes.MsgEthereumTx, error) {
	tx, err := evmtypes.TxDecoder(clientCtx)(bz, height)
	if err != nil {
		return nil, sdkerrors.Wrap(sdkerrors.ErrJSONUnmarshal, err.Error())
	}

	ethTx, ok := tx.(*evmtypes.MsgEthereumTx)
	if !ok {
		return nil, fmt.Errorf("invalid transaction type %T, expected %T", tx, evmtypes.MsgEthereumTx{})
	}
	return ethTx, nil
}
func makeResult(tx types.Tx, height int64) (sender string, to common.Address, payLoad []byte, err error) {
	codecProxy, _ := okxCodeC.MakeCodecSuit(app.ModuleBasics)

	ethTx, err := RawTxToEthTx(codecProxy.GetCdc(), tx, height)
	if err != nil {
		return "", common.Address{}, nil, err
	}

	toAddr := common.Address{}
	if ethTx.To() != nil {
		toAddr = *ethTx.To()
	}
	return ethTx.GetFrom(), toAddr, ethTx.Data.Payload, nil
}
func makeResultWithoutSender(tx types.Tx, height int64) (sender common.Address, to common.Address, payLoad []byte, err error) {
	codecProxy, _ := okxCodeC.MakeCodecSuit(app.ModuleBasics)

	ethTx, err := RawTxToEthTx(codecProxy.GetCdc(), tx, height)
	if err != nil {
		return common.Address{}, common.Address{}, nil, err
	}

	toAddr := common.Address{}
	if ethTx.To() != nil {
		toAddr = *ethTx.To()
	}
	return common.Address{}, toAddr, ethTx.Data.Payload, nil
}

type A struct {
	Height int
	Txs    types.Txs
}

type M struct {
	mintList map[common.Address]bool

	useMapHash    map[common.Address]common.Hash
	useMapCnt     map[common.Address]int
	coinToolAddrs map[common.Address]bool

	contractType map[common.Hash]int
	mu           sync.Mutex

	activeMu  sync.Mutex
	activeCnt int
	activeMp  map[int]map[int]int

	coinToolMu         sync.Mutex
	activeCointoolsCnt int
	activeCoinToolsMp  map[int]map[int]int

	robotXenMu        sync.Mutex
	activeRobotXenCnt int
	activeRobotXenMp  map[int]map[int]int
}

func (m *M) AddGuoqiCnt(ts time.Time) {
	year := ts.Year()
	month := int(ts.Month())
	m.activeMu.Lock()
	if _, ok := m.activeMp[year]; !ok {
		m.activeMp[year] = make(map[int]int)
	}
	m.activeMp[year][month]++
	m.activeCnt++
	m.activeMu.Unlock()
}

func (m *M) AddGuoqiCointool(ts time.Time) {
	year := ts.Year()
	month := int(ts.Month())
	m.coinToolMu.Lock()
	if _, ok := m.activeCoinToolsMp[year]; !ok {
		m.activeCoinToolsMp[year] = make(map[int]int)
	}
	m.activeCoinToolsMp[year][month]++
	m.activeCointoolsCnt++
	m.coinToolMu.Unlock()
}

func (m *M) AddGUoqiRobotXen(ts time.Time) {
	year := ts.Year()
	month := int(ts.Month())
	m.robotXenMu.Lock()
	if _, ok := m.activeRobotXenMp[year]; !ok {
		m.activeRobotXenMp[year] = make(map[int]int)
	}
	m.activeRobotXenMp[year][month]++
	m.activeRobotXenCnt++
	m.robotXenMu.Unlock()
}

func (m *M) AddUseList(addr common.Address, txHash common.Hash) {
	m.mu.Lock()
	m.useMapCnt[addr]++

	m.useMapHash[addr] = txHash
	m.mu.Unlock()
}

func (m *M) AddMinted(addr common.Address) {
	m.mu.Lock()
	m.mintList[addr] = true
	m.mu.Unlock()
}
func (m *M) AddCoinToolSender(address common.Address, txHash common.Hash) {
	m.mu.Lock()
	m.coinToolAddrs[address] = true
	m.contractType[txHash] = 1
	m.mu.Unlock()
}

func (m *M) AddRobotXenFunc(txHash common.Hash) {
	m.mu.Lock()

	m.contractType[txHash] = 2
	m.mu.Unlock()
}

var (
	tmSender = &M{
		mintList:      make(map[common.Address]bool, 0),
		useMapCnt:     make(map[common.Address]int, 0),
		useMapHash:    make(map[common.Address]common.Hash, 0),
		coinToolAddrs: make(map[common.Address]bool, 0),
		contractType:  make(map[common.Hash]int, 0),

		activeMp:          make(map[int]map[int]int, 0),
		activeCoinToolsMp: make(map[int]map[int]int, 0),
		activeRobotXenMp:  make(map[int]map[int]int, 0),
		mu:                sync.Mutex{},
		activeMu:          sync.Mutex{},
		coinToolMu:        sync.Mutex{},
		robotXenMu:        sync.Mutex{},
	}
)

func makeKey(addr common.Address) common.Hash {
	ans := make([]byte, 0)

	for index := 0; index < 12; index++ {
		ans = append(ans, []byte{0}...)
	}
	ans = append(ans, addr.Bytes()...)
	for index := 0; index < 31; index++ {
		ans = append(ans, []byte{0}...)
	}
	ans = append(ans, []byte{9}...)

	kh := crypto.NewKeccakState()
	kh.Reset()
	kh.Write(ans)
	h := common.Hash{}
	kh.Read(h[:])
	return h
}

type Manager struct {
	start      int
	end        int
	tree       *iavl.MutableTree
	blockStore *store.BlockStore
	stateStore dbm.DB
}

func NewManager(originDataDir string, start, end int) *Manager {
	originBlockStoreDB, err := sdk.NewDB(blockStoreDB, originDataDir)
	panicError(err)
	originBlockStore := store.NewBlockStore(originBlockStoreDB)

	db, err := base.OpenDB(originDataDir+"/application.db", dbm.BackendType("rocksdb"))
	if err != nil {
		panic(err)
	}

	tree, err := ReadTree(db, 0, []byte(fmt.Sprintf("s/k:%s/", "evm")), DefaultCacheSize)
	if err != nil {
		panic(err)
	}

	// load state
	stateStoreDB, err := sdk.NewDB(stateDB, originDataDir)

	return &Manager{
		start:      start,
		end:        end,
		tree:       tree,
		blockStore: originBlockStore,
		stateStore: stateStoreDB,
	}
}

func (m *Manager) GetMaturityTs(addr common.Address) *big.Int {
	userAddr := makeKey(addr) // 9
	maturityTs := new(big.Int).Add(new(big.Int).SetBytes(userAddr.Bytes()), new(big.Int).SetInt64(2))

	realKey := evmtypes.GetStorageByAddressKey(common.HexToAddress("0x1cC4D981e897A3D2E7785093A648c0a75fAd0453").Bytes(), maturityTs.Bytes())

	keyInDB := make([]byte, 0)
	preInStore, _ := hex.DecodeString("051cC4D981e897A3D2E7785093A648c0a75fAd0453")
	keyInDB = append(keyInDB, preInStore...)
	keyInDB = append(keyInDB, realKey.Bytes()...)
	_, value := m.tree.GetWithIndex(keyInDB)
	return new(big.Int).SetBytes(value)
}

func (m *Manager) RangeBlock() {

	res := make(chan int64, 500000)

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		for height := m.start; height <= m.end; height++ {
			res <- int64(height)
		}
		wg.Done()
		close(res)
	}()

	for index := 0; index < 64; index++ {
		wg.Add(1)
		go func() {
			for height := range res {
				resp, err := sm.LoadABCIResponses(m.stateStore, height)
				checkerr(err)
				for _, v := range resp.DeliverTxs {
					if len(v.Data) == 0 {
						continue
					}
					data, err := evmtypes.DecodeResultData(v.Data)
					if err != nil {
						continue
					}
					checkerr(err)
					for _, logs := range data.Logs {
						if logs.Topics[0].String() == "0xe9149e1b5059238baed02fa659dbf4bd932fbcf760a431330df4d934bc942f37" {
							tmSender.AddUseList(common.BytesToAddress(logs.Topics[1].Bytes()), data.TxHash)
						}
						if logs.Topics[0].String() == "0xd74752b13281df13701575f3a507e9b1242e0b5fb040143211c481c1fce573a6" {
							tmSender.AddMinted(common.BytesToAddress(logs.Topics[1].Bytes()))
						}
					}
				}
				if height%50000 == 0 {
					fmt.Println("cal abci", height)
				}
			}
			wg.Done()
		}()
	}
	wg.Wait()

	cnt := 0
	for _, v := range tmSender.useMapCnt {
		cnt += v
	}
	fmt.Println("allCnt", cnt, "lenMinted", len(tmSender.mintList), "left", cnt-len(tmSender.mintList))
}

func (m *Manager) GetCoinToolsSenderList() {

	resChan := make(chan int64, 500000)

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		for height := m.start; height <= m.end; height++ {
			resChan <- int64(height)
		}
		wg.Done()
		close(resChan)
	}()

	for index := 0; index < 64; index++ {
		wg.Add(1)
		go func() {
			for height := range resChan {
				res := m.blockStore.LoadBlock(height)
				for _, v := range res.Txs {
					txHash := common.BytesToHash(v.Hash(height))
					sender, b, c, _ := makeResultWithoutSender(v, height)
					if b.String() == "0x6f0a55cd633Cc70BeB0ba7874f3B010C002ef59f" { // coinTools
						if len(c) >= 4 && hex.EncodeToString(c[:4]) == "b1ae2ed1" { //claimBatch
							tmSender.AddCoinToolSender(sender, txHash)
						}
					}
					if b.String() == "0x97FAaB98f1A9E5C803C43a6293759FcC7eD000b9" { // robotXen
						if len(c) >= 4 && hex.EncodeToString(c[:4]) == "a0712d68" { //mint
							tmSender.AddRobotXenFunc(txHash)
						}
					}
				}
				if height%50000 == 0 {
					fmt.Println("cal sender", height)
				}
			}
			wg.Done()
		}()
	}
	wg.Wait()

}

type calStruct struct {
	addr common.Address
	hash common.Hash
	cnt  int
}

func (m *Manager) cal() {
	res := make(chan calStruct, 500000)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		cnt := 0
		for addr, hash := range tmSender.useMapHash {
			res <- calStruct{
				addr: addr,
				hash: hash,
				cnt:  cnt,
			}
			cnt++
		}
		wg.Done()
		close(res)
	}()

	tt := time.Now()
	for index := 0; index < 9000; index++ {
		go func() {
			wg.Add(1)
			for c := range res {
				if c.cnt%100000 == 0 {
					fmt.Println("cal guoqi", c.cnt, len(tmSender.useMapHash), tmSender.activeCnt, tmSender.activeCointoolsCnt, tmSender.activeRobotXenCnt, time.Now().Sub(tt).Seconds())
				}
				if tmSender.useMapCnt[c.addr] == 1 && tmSender.mintList[c.addr] {
					continue
				}
				ts := m.GetMaturityTs(c.addr)
				guoqiTs := time.Unix(ts.Int64(), 0)
				if ts.Int64() != 0 {
					tmSender.AddGuoqiCnt(guoqiTs)

					if tmSender.contractType[c.hash] == 1 {
						tmSender.AddGuoqiCointool(guoqiTs)
					} else if tmSender.contractType[c.hash] == 2 {
						tmSender.AddGUoqiRobotXen(guoqiTs)
					}
				}
			}
			wg.Done()
		}()
	}
	wg.Wait()

	fmt.Println("guoqi", "all", tmSender.activeCnt, "coinTool", tmSender.activeCointoolsCnt, "robotXen", tmSender.activeRobotXenCnt)
	fmt.Println("detail-all", tmSender.activeMp)
	fmt.Println("detail-cointools", tmSender.activeCoinToolsMp)
	fmt.Println("detail-robotXen", tmSender.activeRobotXenMp)

}

// replayBlock replays blocks from db, if something goes wrong, it will panic with error message.
func replayBlock(ctx *server.Context, originDataDir string, tmNode *node.Node) {

	manager := NewManager(originDataDir, 15414660, 17200533)
	//manager := NewManager(originDataDir, 15414660, 15444660)

	ts := manager.GetMaturityTs(common.HexToAddress("0x45b7e4f75d658b5e02811f68fdd71094af03f06e"))
	time.Unix(ts.Int64(), 0).Year()
	fmt.Println("ts", ts, time.Unix(ts.Int64(), 0).Year(), time.Unix(ts.Int64(), 0).Month(), time.Unix(ts.Int64(), 0).Day())

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		manager.RangeBlock()
		wg.Done()
	}()

	go func() {
		manager.GetCoinToolsSenderList()
		fmt.Println("len(sender)", len(tmSender.coinToolAddrs))
		wg.Done()
	}()
	wg.Wait()
	manager.cal()

}

func registerReplayFlags(cmd *cobra.Command) *cobra.Command {
	cmd.Flags().StringP(replayedBlockDir, "d", ".exchaind/data", "Directory of block data to be replayed")
	cmd.Flags().StringP(pprofAddrFlag, "p", "0.0.0.0:26661", "Address and port of pprof HTTP server listening")
	cmd.Flags().BoolVarP(&sm.IgnoreSmbCheck, "ignore-smb", "i", false, "ignore state machine broken")
	cmd.Flags().Bool(runWithPprofFlag, false, "Dump the pprof of the entire replay process")
	cmd.Flags().Bool(runWithPprofMemFlag, false, "Dump the mem profile of the entire replay process")
	cmd.Flags().Bool(saveBlock, false, "save block when replay")
	cmd.Flags().Bool(FlagEnableRest, false, "start rest service when replay")

	return cmd
}

func setReplayDefaultFlag() {
	if len(os.Args) > 1 && os.Args[1] == "replay" {
		viper.SetDefault(watcher.FlagFastQuery, false)
		viper.SetDefault(evmtypes.FlagEnableBloomFilter, false)
		viper.SetDefault(iavl.FlagIavlCommitAsyncNoBatch, true)
	}
}

// panic if error is not nil
func panicError(err error) {
	if err != nil {
		panic(err)
	}
}

func createProxyApp(ctx *server.Context) (proxy.AppConns, error) {
	rootDir := ctx.Config.RootDir
	dataDir := filepath.Join(rootDir, "data")
	db, err := sdk.NewDB(applicationDB, dataDir)
	panicError(err)
	app := newApp(ctx.Logger, db, nil)
	clientCreator := proxy.NewLocalClientCreator(app)
	return createAndStartProxyAppConns(clientCreator)
}

func createAndStartProxyAppConns(clientCreator proxy.ClientCreator) (proxy.AppConns, error) {
	proxyApp := proxy.NewAppConns(clientCreator)
	if err := proxyApp.Start(); err != nil {
		return nil, fmt.Errorf("error starting proxy app connections: %v", err)
	}
	return proxyApp, nil
}

func initChain(state sm.State, stateDB dbm.DB, genDoc *types.GenesisDoc, proxyApp proxy.AppConns) error {
	validators := make([]*types.Validator, len(genDoc.Validators))
	for i, val := range genDoc.Validators {
		validators[i] = types.NewValidator(val.PubKey, val.Power)
	}
	validatorSet := types.NewValidatorSet(validators)
	nextVals := types.TM2PB.ValidatorUpdates(validatorSet)
	csParams := types.TM2PB.ConsensusParams(genDoc.ConsensusParams)
	req := abci.RequestInitChain{
		Time:            genDoc.GenesisTime,
		ChainId:         genDoc.ChainID,
		ConsensusParams: csParams,
		Validators:      nextVals,
		AppStateBytes:   genDoc.AppState,
	}
	res, err := proxyApp.Consensus().InitChainSync(req)
	if err != nil {
		return err
	}

	if state.LastBlockHeight == types.GetStartBlockHeight() { //we only update state when we are in initial state
		// If the app returned validators or consensus params, update the state.
		if len(res.Validators) > 0 {
			vals, err := types.PB2TM.ValidatorUpdates(res.Validators)
			if err != nil {
				return err
			}
			state.Validators = types.NewValidatorSet(vals)
			state.NextValidators = types.NewValidatorSet(vals)
		} else if len(genDoc.Validators) == 0 {
			// If validator set is not set in genesis and still empty after InitChain, exit.
			return fmt.Errorf("validator set is nil in genesis and still empty after InitChain")
		}

		if res.ConsensusParams != nil {
			state.ConsensusParams = state.ConsensusParams.Update(res.ConsensusParams)
		}
		sm.SaveState(stateDB, state)
	}
	return nil
}

var (
	alreadyInit  bool
	stateStoreDb *store.BlockStore
)

// TODO need delete
func SaveBlock(ctx *server.Context, originDB *store.BlockStore, height int64) {
	if !alreadyInit {
		alreadyInit = true
		dataDir := filepath.Join(ctx.Config.RootDir, "data")
		blockStoreDB, err := sdk.NewDB(blockStoreDB, dataDir)
		panicError(err)
		stateStoreDb = store.NewBlockStore(blockStoreDB)
	}

	block := originDB.LoadBlock(height)
	meta := originDB.LoadBlockMeta(height)
	seenCommit := originDB.LoadSeenCommit(height)

	ps := types.NewPartSetFromHeader(meta.BlockID.PartsHeader)
	for index := 0; index < ps.Total(); index++ {
		ps.AddPart(originDB.LoadBlockPart(height, index))
	}

	stateStoreDb.SaveBlock(block, ps, seenCommit)
}

func doReplay(ctx *server.Context, state sm.State, stateStoreDB dbm.DB, blockStore *store.BlockStore,
	proxyApp proxy.AppConns, originDataDir string, lastAppHash []byte, lastBlockHeight int64) {

	trace.GetTraceSummary().Init(
		trace.Abci,
		//trace.ValTxMsgs,
		trace.RunAnte,
		trace.RunMsg,
		trace.Refund,
		//trace.SaveResp,
		trace.Persist,
		//trace.Evpool,
		//trace.SaveState,
		//trace.FireEvents,
	)

	defer trace.GetTraceSummary().Dump("Replay")

	var originBlockStore *store.BlockStore
	var err error
	if blockStore == nil {
		originBlockStoreDB, err := sdk.NewDB(blockStoreDB, originDataDir)
		panicError(err)
		originBlockStore = store.NewBlockStore(originBlockStoreDB)
	} else {
		originBlockStore = blockStore
	}
	originLatestBlockHeight := originBlockStore.Height()
	log.Println("origin latest block height", "height", originLatestBlockHeight)

	haltheight := viper.GetInt64(server.FlagHaltHeight)
	if haltheight == 0 {
		haltheight = originLatestBlockHeight
	}
	if haltheight <= lastBlockHeight+1 {
		panic("haltheight <= startBlockHeight please check data or height")
	}

	log.Println("replay stop block height", "height", haltheight)

	// Replay blocks up to the latest in the blockstore.
	if lastBlockHeight == state.LastBlockHeight+1 {
		global.SetGlobalHeight(lastBlockHeight)
		abciResponses, err := sm.LoadABCIResponses(stateStoreDB, lastBlockHeight)
		panicError(err)
		mockApp := newMockProxyApp(lastAppHash, abciResponses)
		block := originBlockStore.LoadBlock(lastBlockHeight)
		meta := originBlockStore.LoadBlockMeta(lastBlockHeight)
		blockExec := sm.NewBlockExecutor(stateStoreDB, ctx.Logger, mockApp, mock.Mempool{}, sm.MockEvidencePool{})
		config.GetOecConfig().SetDeliverTxsExecuteMode(0) // mockApp not support parallel tx
		state, _, err = blockExec.ApplyBlockWithTrace(state, meta.BlockID, block)
		config.GetOecConfig().SetDeliverTxsExecuteMode(viper.GetInt(sm.FlagDeliverTxsExecMode))
		panicError(err)
	}

	blockExec := sm.NewBlockExecutor(stateStoreDB, ctx.Logger, proxyApp.Consensus(), mock.Mempool{}, sm.MockEvidencePool{})
	if viper.GetBool(runWithPprofFlag) {
		startDumpPprof()
		defer stopDumpPprof()
	}
	//Async save db during replay
	blockExec.SetIsAsyncSaveDB(true)
	baseapp.SetGlobalMempool(mock.Mempool{}, ctx.Config.Mempool.SortTxByGp, ctx.Config.Mempool.EnablePendingPool)
	needSaveBlock := viper.GetBool(saveBlock)
	global.SetGlobalHeight(lastBlockHeight + 1)
	for height := lastBlockHeight + 1; height <= haltheight; height++ {
		block := originBlockStore.LoadBlock(height)
		meta := originBlockStore.LoadBlockMeta(height)
		state, _, err = blockExec.ApplyBlockWithTrace(state, meta.BlockID, block)
		panicError(err)
		if needSaveBlock {
			SaveBlock(ctx, originBlockStore, height)
		}
	}

}

func dumpMemPprof() error {
	fileName := fmt.Sprintf("replay_pprof_%s.mem.bin", time.Now().Format("20060102150405"))
	f, err := os.Create(fileName)
	if err != nil {
		return fmt.Errorf("create mem pprof file %s error: %w", fileName, err)
	}
	defer f.Close()
	runtime.GC() // get up-to-date statistics
	if err = pprof.WriteHeapProfile(f); err != nil {
		return fmt.Errorf("could not write memory profile: %w", err)
	}
	return nil
}

func startDumpPprof() {
	var (
		binarySuffix = time.Now().Format("20060102150405") + ".bin"
	)
	fileName := fmt.Sprintf("replay_pprof_%s", binarySuffix)
	bf, err := os.OpenFile(fileName, defaulPprofFileFlags, defaultPprofFilePerm)
	if err != nil {
		fmt.Printf("open pprof file(%s) error:%s\n", fileName, err.Error())
		return
	}

	err = pprof.StartCPUProfile(bf)
	if err != nil {
		fmt.Printf("dump pprof StartCPUProfile error:%s\n", err.Error())
		return
	}
	fmt.Printf("start to dump pprof file(%s)\n", fileName)
}

func stopDumpPprof() {
	pprof.StopCPUProfile()
	fmt.Printf("dump pprof successfully\n")
}

func newMockProxyApp(appHash []byte, abciResponses *sm.ABCIResponses) proxy.AppConnConsensus {
	clientCreator := proxy.NewLocalClientCreator(&mockProxyApp{
		appHash:       appHash,
		abciResponses: abciResponses,
	})
	cli, _ := clientCreator.NewABCIClient()
	err := cli.Start()
	if err != nil {
		panic(err)
	}
	return proxy.NewAppConnConsensus(cli)
}

type mockProxyApp struct {
	abci.BaseApplication

	appHash       []byte
	txCount       int
	abciResponses *sm.ABCIResponses
}

func (mock *mockProxyApp) DeliverTx(req abci.RequestDeliverTx) abci.ResponseDeliverTx {
	r := mock.abciResponses.DeliverTxs[mock.txCount]
	mock.txCount++
	if r == nil { //it could be nil because of amino unMarshall, it will cause an empty ResponseDeliverTx to become nil
		return abci.ResponseDeliverTx{}
	}
	return *r
}

func (mock *mockProxyApp) EndBlock(req abci.RequestEndBlock) abci.ResponseEndBlock {
	mock.txCount = 0
	return *mock.abciResponses.EndBlock
}

func (mock *mockProxyApp) Commit(req abci.RequestCommit) abci.ResponseCommit {
	return abci.ResponseCommit{Data: mock.appHash}
}
