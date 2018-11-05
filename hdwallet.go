package swa

import hd "github.com/symphonyprotocol/sutil/hdkeychain"
import ec "github.com/symphonyprotocol/sutil/elliptic"
import "fmt"
import bip39 "github.com/symphonyprotocol/sutil/bip39"
import "strings"
import "math/big"
import "math"

type Wallet struct{
	mnemonic  string
	masterKey *hd.ExtendedKey
	seed      []byte
}

func newWallet(seed []byte) (*Wallet, error) {
	masterKey, err := hd.NewMaster(seed)
	if err != nil {
		return nil, err
	}

	wallet := Wallet{
			masterKey: masterKey,
			seed: seed,
	}
	return &wallet, nil
}

func (w *Wallet)GetMasterKey() *hd.ExtendedKey{
	return w.masterKey
}

func NewFromMnemonic(mnemonic string, pwd string) (*Wallet, error) {
	bip39.SetWordList(bip39.English)
	if mnemonic == "" {
		return nil, fmt.Errorf("mnemonic is required")
	}

	if !bip39.IsMnemonicValid(mnemonic) {
		return nil, fmt.Errorf("mnemonic is invalid")
	}

	seed, err := bip39.NewSeed(mnemonic, pwd)
	if err != nil {
		return nil, err
	}

	wallet, err := newWallet(seed)
	if err != nil {
		return nil, err
	}
	wallet.mnemonic = mnemonic

	return wallet, nil
}

func GenMnemonic()(string, error){
	bip39.SetWordList(bip39.English)
	mnemonic, err := bip39.NewMnemonic(128)
	return mnemonic, err
}

// 解析路径
// 0到2^{31}-1之间的索引号（0x0到0x7FFFFFFF）仅用于正常推导
// 2^31和2^{32}-1 之间的索引号（0x80000000至0xFFFFFFFF）仅用于强化推导
func ParseDerivationPath(path string) ([]uint32, error) {
	var result []uint32

	// Handle absolute or relative paths
	components := strings.Split(path, "/")
	switch {
	case len(components) == 0:
		return nil, fmt.Errorf("empty derivation path")

	case strings.TrimSpace(components[0]) == "":
		return nil, fmt.Errorf("ambiguous path: use 'm/' prefix for absolute paths, or no leading '/' for relative ones")

	case strings.TrimSpace(components[0]) == "m":
		components = components[1:]

	default:
		break
	}
	// All remaining components are relative, append one by one
	if len(components) == 0 {
		return nil, fmt.Errorf("empty derivation path") // Empty relative paths
	}
	for _, component := range components {
		// Ignore any user added whitespace
		component = strings.TrimSpace(component)
		var value uint32

		// Handle hardened paths
		if strings.HasSuffix(component, "'") {
			value = 0x80000000
			component = strings.TrimSpace(strings.TrimSuffix(component, "'"))
		}
		// Handle the non hardened component
		bigval, ok := new(big.Int).SetString(component, 0)
		if !ok {
			return nil, fmt.Errorf("invalid component: %s", component)
		}
		max := math.MaxUint32 - value
		if bigval.Sign() < 0 || bigval.Cmp(big.NewInt(int64(max))) > 0 {
			if value == 0 {
				return nil, fmt.Errorf("component %v out of allowed range [0, %d]", bigval, max)
			}
			return nil, fmt.Errorf("component %v out of allowed hardened range [0, %d]", bigval, max)
		}
		value += uint32(bigval.Uint64())

		// Append and repeat
		result = append(result, value)
	}
	return result, nil
}


func MakePath(path [] uint32) string{
	result := "m"
	for _, component := range path {
		var hardened bool
		if component >= 0x80000000 {
			component -= 0x80000000
			hardened = true
		}
		result = fmt.Sprintf("%s/%d", result, component)
		if hardened {
			result += "'"
		}
	}
	return result
}

func (w *Wallet) deriveKey(path []uint32) (*ec.PrivateKey, *ec.PublicKey, error) {
	var err error
	key := w.masterKey
	for _, n := range path {
		key, err = key.Child(n)
		if err != nil {
			return nil, nil, err
		}
	}

	privateKey, err2 := key.ECPrivKey()
	if err2 != nil {
		return nil, nil,  err
	}

	publicKey, err3 := key.ECPubKey()
	if err3 != nil{
		return nil, nil, err
	}

	return privateKey, publicKey, nil
}

func (w *Wallet) DeriveKey(path string) (*ec.PrivateKey, *ec.PublicKey, error) {
	path_uints, err := ParseDerivationPath(path)
	if err != nil{
		return nil, nil, err
	}
	prikey, pubkey, err2 := w.deriveKey(path_uints)
	return prikey, pubkey, err2
}