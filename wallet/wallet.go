package main
import "crypto/ecdsa"


type Wallet struct {
	PrivateKey ecdsa.PrivateKey
	Publickey ecdsa.PublicKey
}


func NewWallet () *Wallet  {
	privateKey := newKeyPair()
	publickey := privateKey.PublicKey
	return &Wallet{privateKey, publickey}
}

// 从WIF 导入
func WalletFromWIF(wif string) (* Wallet){
	if wal, err := FromWIF(wif); err ==nil {
		return wal
	}
	return nil
}