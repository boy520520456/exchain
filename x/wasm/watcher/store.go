package watcher

import (
	"encoding/json"
	"log"
	"path/filepath"
	"sync"

	"github.com/okex/exchain/app/types"
	"github.com/okex/exchain/libs/cosmos-sdk/client/flags"
	"github.com/okex/exchain/libs/cosmos-sdk/store/dbadapter"
	"github.com/okex/exchain/libs/cosmos-sdk/store/prefix"
	sdk "github.com/okex/exchain/libs/cosmos-sdk/types"
	dbm "github.com/okex/exchain/libs/tm-db"
	"github.com/okex/exchain/x/evm/watcher"
	"github.com/spf13/viper"
)

const (
	watchDBName = "wasm-watcher"
)

var (
	checkOnce     sync.Once
	checked       bool
	enableWatcher bool
	db            dbm.DB
	// used for parallel deliver txs mode
	txCacheMtx      sync.Mutex
	txStateCache    []*WatchMessage
	blockStateCache = make(map[string]*WatchMessage)

	accountKeyPrefix = []byte("wasm-account-")
)

func Enable() bool {
	checkOnce.Do(func() {
		checked = true
		if viper.GetBool(watcher.FlagFastQuery) {
			enableWatcher = true
			InitDB()
		}
	})
	return enableWatcher
}

func ensureChecked() {
	if !checked {
		panic("fast query should be checked at init")
	}
}

func InitDB() {
	homeDir := viper.GetString(flags.FlagHome)
	dbPath := filepath.Join(homeDir, watcher.WatchDbDir)

	var err error
	db, err = sdk.NewDB(watchDBName, dbPath)
	if err != nil {
		panic(err)
	}
	go taskRoutine()
}

func AccountKey(addr []byte) []byte {
	return append(accountKeyPrefix, addr...)
}
func GetAccount(addr sdk.WasmAddress) (*types.EthAccount, error) {
	if !Enable() {
		return nil, nil
	}
	b, err := db.Get(AccountKey(addr.Bytes()))
	if err != nil {
		return nil, err
	}

	var acc types.EthAccount
	err = json.Unmarshal(b, &acc)
	if err != nil {
		return nil, err
	}
	return &acc, nil

}

func SetAccount(acc *types.EthAccount) error {
	if !Enable() {
		return nil
	}
	b, err := json.Marshal(acc)
	if err != nil {
		return err
	}
	return db.Set(AccountKey(acc.Address.Bytes()), b)
}

func DeleteAccount(addr sdk.WasmAddress) {
	if !Enable() {
		return
	}
	if err := db.Delete(AccountKey(addr.Bytes())); err != nil {
		log.Println("wasm watchDB delete account error", addr.String())
	}
}

var (
	dbStore = dbadapter.Store{DB: db}
)

func NewReadStore(s sdk.KVStore, pre []byte, onlyReadFromWatchDB bool) sdk.KVStore { // only for wasm simulate and grpc query
	if onlyReadFromWatchDB {
		return &readStore{
			dbStore,
		}
	}
	newStore := &readStore{
		s,
	}
	if len(pre) != 0 {
		return prefix.NewStore(newStore, pre)
	}
	return newStore

}

type Adapter struct{} // only for wasm simulate

func (a Adapter) NewStore(_ sdk.GasMeter, s sdk.KVStore, pre []byte) sdk.KVStore {
	return NewReadStore(s, pre, false)
}

type readStore struct {
	sdk.KVStore
}

func (r *readStore) Get(key []byte) []byte {
	if value := r.KVStore.Get(key); len(value) != 0 {
		return value
	}
	if value := dbStore.Get(key); len(value) != 0 {
		return value
	}
	return nil
}
