package main
import "fmt"
import "os"

func main(){
	var wallet *Wallet

	// import WIF from first argument
	if len(os.Args) > 1 {
		wallet = WalletFromWIF(os.Args[1])
	} else {
		wallet = NewWallet()
	}

	address_compress := wallet.ToAddressCompressed()
	address := wallet.ToAddress()
	public_key_str := wallet.ToPublicKey()
	public_key_compress_str := wallet.ToPublicKeyCompressed()
	priv_key_str := wallet.ToPrivateKey()
	wif := wallet.ToWIF()
	wifc := wallet.ToWIFCompressed()
	bip38 := wallet.ToBip38Encrypt("hahaha")
	decode_bip38 := Bip38Decrypt(bip38, "hahaha")

	fmt.Printf("address compressed         :%s\n", address_compress)
	fmt.Printf("address                    :%s\n", address)
	fmt.Printf("public key                 :%s\n", public_key_str)
	fmt.Printf("public key compressed      :%s\n", public_key_compress_str)
	fmt.Printf("private key                :%s\n", priv_key_str)
	fmt.Printf("wif                        :%s\n", wif)
	fmt.Printf("wif compressed             :%s\n", wifc)
	fmt.Printf("bip38                      :%s\n", bip38)
	fmt.Printf("decode_bip38               :%s\n", decode_bip38)
}