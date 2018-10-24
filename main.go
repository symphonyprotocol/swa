package main

import (
	// "bytes"
	// "compress/zlib"
	// "encoding/base64"
	// "fmt"
	// "log"
	// "os"
)
// import  "github.com/symphonyprotocol/sutil/utils"
// import "github.com/symphonyprotocol/sutil/hdkeychain"


func main(){
	cli := CLI{}
	cli.Run()
	// mnemonic, err := GenMnemonic()
	// fmt.Print(mnemonic)
	// fmt.Print(err)

	// wallet, _ := NewFromMnemonic("sugar reveal festival company axis broom snow grocery cash sunset thank trade", "fuckit")
	
	// master_private, _ := wallet.masterKey.ECPrivKey()
	// master_public, _ := wallet.masterKey.ECPubKey()

	// pub_bytes_compressed := master_public.SerializeCompressed()
	// pub_bytes_uncompressed := master_public.SerializeUncompressed()

	// pub_str_compressed := utils.BytesToString(pub_bytes_compressed)
	// pub_str_uncompressed := utils.BytesToString(pub_bytes_uncompressed)

	// pub_address := master_public.ToAddress()
	// pub_address_compressed := master_public.ToAddressCompressed()

	// wif := master_private.ToWIF()
	// wif_compressed := master_private.ToWIFCompressed()
	// priv_key_bytes := master_private.PrivatekeyToBytes()
	// priv_key_str := utils.BytesToString(priv_key_bytes)

	// bip38 := master_private.ToBip38Encrypt("hahaha")
	// decode_bip38 := ec.Bip38Decrypt(bip38, "hahaha")

	// fmt.Printf("master public key compressed             :%s\n", pub_str_compressed)
	// fmt.Printf("master public key un compressed          :%s\n", pub_str_uncompressed)
	// fmt.Printf("master public key address      	         :%s\n", pub_address)
	// fmt.Printf("master public key address compressed     :%s\n", pub_address_compressed)
	// fmt.Printf("master private key wif      			 :%s\n", wif)
	// fmt.Printf("master private key wif compressed        :%s\n", wif_compressed)
	// fmt.Printf("master private key str       			 :%s\n", priv_key_str)
	// fmt.Printf("master private bip38 str       			 :%s\n", bip38)
	// fmt.Printf("master private bip38 decode              :%s\n", decode_bip38)
	

	// neuter_extend_key, _ := wallet.masterKey.Neuter()
	// neuter_extend_child0, _ := neuter_extend_key.Child(0)
	// priv_extend_child0, _ := wallet.masterKey.Child(0)
	// neuter_extend_child1, _ := neuter_extend_key.Child(1)
	// priv_extend_child1, _ := wallet.masterKey.Child(1)


	// neuter_extend_sun1, _ := neuter_extend_child0.Child(0)
	// priv_extend_sun1, _ := priv_extend_child0.Child(0)

	// fmt.Print(neuter_extend_child0)
	// fmt.Print(priv_extend_child0)
	// fmt.Print(neuter_extend_child1)
	// fmt.Print(priv_extend_child1)
	// fmt.Print(neuter_extend_sun1)
	// fmt.Print(priv_extend_sun1)

	// pri, pub, _ := wallet.DeriveKey("m/0")
	// der_pub := BytesToString(pub.SerializeCompressed())
	// der_pri := BytesToString(pri.PrivatekeyToBytes())

	// real_child_pub, _:= neuter_extend_child0.ECPubKey()
	// real_child_pri, _:= priv_extend_child0.ECPrivKey()

	// real_child_pub_compress := BytesToString(real_child_pub.SerializeCompressed())
	// real_child_pri_key := BytesToString(real_child_pri.PrivatekeyToBytes())

	// fmt.Print("----------------------------------------------\n")
	// fmt.Printf("derive pub key compressed  :%s\n", der_pub)
	// fmt.Printf("derive priv key            :%s\n", der_pri)
	// fmt.Print("...\n")
	// fmt.Printf("real pub key compressed  :%s\n", real_child_pub_compress)
	// fmt.Printf("real priv key            :%s\n", real_child_pri_key)


}
