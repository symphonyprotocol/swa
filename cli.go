package swa

import "flag"
import "log"
import "fmt"
import "os"
import "github.com/symphonyprotocol/sutil/utils"

type CLI struct{}

func (cli *CLI) CreateMnemonic() string{
	mnemonic, err := GenMnemonic()
	if err != nil{
		log.Panic(err)
	}
	fmt.Printf("Mnemonic is: %s\n", mnemonic)
	return mnemonic
} 
func (cli *CLI) GetKey(mnemonic string, pwd string){
	wallet, _ := NewFromMnemonic(mnemonic, pwd)
	master_private, _ := wallet.masterKey.ECPrivKey()
	master_public, _ := wallet.masterKey.ECPubKey()

	pub_bytes_compressed := master_public.SerializeCompressed()
	pub_bytes_uncompressed := master_public.SerializeUncompressed()

	pub_str_compressed := utils.BytesToString(pub_bytes_compressed)
	pub_str_uncompressed := utils.BytesToString(pub_bytes_uncompressed)

	pub_address := master_public.ToAddress()
	pub_address_compressed := master_public.ToAddressCompressed()

	wif := master_private.ToWIF()
	wif_compressed := master_private.ToWIFCompressed()
	priv_key_bytes := master_private.PrivatekeyToBytes()
	priv_key_str := utils.BytesToString(priv_key_bytes)

	fmt.Printf("master public key compressed           :%s\n", pub_str_compressed)
	fmt.Printf("master public key un compressed        :%s\n", pub_str_uncompressed)
	fmt.Printf("master public key address              :%s\n", pub_address)
	fmt.Printf("master public key address compressed   :%s\n", pub_address_compressed)
	fmt.Printf("master private key wif                 :%s\n", wif)
	fmt.Printf("master private key wif compressed      :%s\n", wif_compressed)
	fmt.Printf("master private key str                 :%s\n", priv_key_str)

}

func (cli *CLI) DeriveKey(mnemonic string, pwd string, path string){
	wallet, _ := NewFromMnemonic(mnemonic, pwd)
	pri, pub, _ := wallet.DeriveKey(path)
	pub_bytes_compressed := pub.SerializeCompressed()
	pub_bytes_uncompressed := pub.SerializeUncompressed()

	pub_str_compressed := utils.BytesToString(pub_bytes_compressed)
	pub_str_uncompressed := utils.BytesToString(pub_bytes_uncompressed)

	pub_address := pub.ToAddress()
	pub_address_compressed := pub.ToAddressCompressed()

	wif := pri.ToWIF()
	wif_compressed := pri.ToWIFCompressed()
	priv_key_bytes := pri.PrivatekeyToBytes()
	priv_key_str := utils.BytesToString(priv_key_bytes)

	fmt.Printf("derive public key compressed           :%s\n", pub_str_compressed)
	fmt.Printf("derive public key un compressed        :%s\n", pub_str_uncompressed)
	fmt.Printf("derive public key address              :%s\n", pub_address)
	fmt.Printf("derive public key address compressed   :%s\n", pub_address_compressed)
	fmt.Printf("derive private key wif                 :%s\n", wif)
	fmt.Printf("derive private key wif compressed      :%s\n", wif_compressed)
	fmt.Printf("derive private key str                 :%s\n", priv_key_str)
}

func (cli *CLI) Run() {
	createMnemonicCmd := flag.NewFlagSet("newmnemonic", flag.ExitOnError)
	getkeyCmd := flag.NewFlagSet("getkey", flag.ExitOnError)
	getkeyMnemonic := getkeyCmd.String("m", "", "The mnemonic you have got")
	getkeypwd := getkeyCmd.String("p", "", "The password you want to use")

	deriveKeyCmd := flag.NewFlagSet("derivekey", flag.ExitOnError)
	deriveKeyMnemonic := deriveKeyCmd.String("m", "", "The mnemonic you have got")
	deriveKeypwd := deriveKeyCmd.String("pwd", "", "The password you want to use")
	deriveKeyPath := deriveKeyCmd.String("path", "", "The path you want to derive the key")



	switch os.Args[1]{
	case "newmnemonic":
		err := createMnemonicCmd.Parse(os.Args[2:])
		if err != nil {
			log.Panic(err)
		}
	case "getkey":
		err := getkeyCmd.Parse(os.Args[2:])
		if err != nil {
			log.Panic(err)
		}
	case "derivekey":
		err := deriveKeyCmd.Parse(os.Args[2:])
		if err != nil {
			log.Panic(err)
		}
	}

	if createMnemonicCmd.Parsed(){
		cli.CreateMnemonic()
	}
	if getkeyCmd.Parsed() {
		if *getkeyMnemonic == "" {
			getkeyCmd.Usage()
			os.Exit(1)
		}
		cli.GetKey(*getkeyMnemonic, *getkeypwd)
	}
	if deriveKeyCmd.Parsed() {
		if *deriveKeyMnemonic == "" ||  *deriveKeyPath == ""{
			deriveKeyCmd.Usage()
			os.Exit(1)
		}
		cli.DeriveKey(*deriveKeyMnemonic, *deriveKeypwd, *deriveKeyPath)
	}
}