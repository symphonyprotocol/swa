package main
// import bip39 "wallet/bip39" 
// // import "os"
import (
	"bytes"
	"compress/zlib"
	"encoding/base64"
	"fmt"
	"log"
	"os"
)
import ec "wallet/elliptic"


func main(){
	mnemonic, err := GenMnemonic()
	fmt.Print(mnemonic)
	fmt.Print(err)

	wallet, _ := NewFromMnemonic(mnemonic, "fuckit")
	
	master_private, _ := wallet.masterKey.ECPrivKey()
	master_public, _ := wallet.masterKey.ECPubKey()

	pub_bytes_compressed := master_public.SerializeCompressed()
	pub_bytes_uncompressed := master_public.SerializeUncompressed()

	pub_str_compressed := BytesToString(pub_bytes_compressed)
	pub_str_uncompressed := BytesToString(pub_bytes_uncompressed)

	pub_address := master_public.ToAddress()
	pub_address_compressed := master_public.ToAddressCompressed()

	wif := master_private.ToWIF()
	wif_compressed := master_private.ToWIFCompressed()
	priv_key_bytes := master_private.PrivatekeyToBytes()
	priv_key_str := BytesToString(priv_key_bytes)

	bip38 := master_private.ToBip38Encrypt("hahaha")
	decode_bip38 := ec.Bip38Decrypt(bip38, "hahaha")

	fmt.Printf("master public key compressed             :%s\n", pub_str_compressed)
	fmt.Printf("master public key un compressed          :%s\n", pub_str_uncompressed)
	fmt.Printf("master public key address      	         :%s\n", pub_address)
	fmt.Printf("master public key address compressed     :%s\n", pub_address_compressed)
	fmt.Printf("master private key wif      			 :%s\n", wif)
	fmt.Printf("master private key wif compressed        :%s\n", wif_compressed)
	fmt.Printf("master private key str       			 :%s\n", priv_key_str)
	fmt.Printf("master private bip38 str       			 :%s\n", bip38)
	fmt.Printf("master private bip38 decode              :%s\n", decode_bip38)
	

	neuter_extend_key, _ := wallet.masterKey.Neuter()
	neuter_extend_child0, _ := neuter_extend_key.Child(0)
	priv_extend_child0, _ := wallet.masterKey.Child(0)
	neuter_extend_child1, _ := neuter_extend_key.Child(1)
	priv_extend_child1, _ := wallet.masterKey.Child(1)


	neuter_extend_sun1, _ := neuter_extend_child0.Child(0)
	priv_extend_sun1, _ := priv_extend_child0.Child(0)

	fmt.Print(neuter_extend_child0)
	fmt.Print(priv_extend_child0)
	fmt.Print(neuter_extend_child1)
	fmt.Print(priv_extend_child1)
	fmt.Print(neuter_extend_sun1)
	fmt.Print(priv_extend_sun1)

	pri, pub, _ := wallet.DeriveKey("m/0")
	der_pub := BytesToString(pub.SerializeCompressed())
	der_pri := BytesToString(pri.PrivatekeyToBytes())

	real_child_pub, _:= neuter_extend_child0.ECPubKey()
	real_child_pri, _:= priv_extend_child0.ECPrivKey()

	real_child_pub_compress := BytesToString(real_child_pub.SerializeCompressed())
	real_child_pri_key := BytesToString(real_child_pri.PrivatekeyToBytes())

	fmt.Print("----------------------------------------------\n")
	fmt.Printf("derive pub key compressed  :%s\n", der_pub)
	fmt.Printf("derive priv key            :%s\n", der_pri)
	fmt.Print("...\n")
	fmt.Printf("real pub key compressed  :%s\n", real_child_pub_compress)
	fmt.Printf("real priv key            :%s\n", real_child_pri_key)


}

func gensecp256k1() {
	fi, err := os.Create("secp256k1.go")
	if err != nil {
		log.Fatal(err)
	}
	defer fi.Close()

	// Compress the serialized byte points.
	serialized := ec.S256().SerializedBytePoints()
	var compressed bytes.Buffer
	w := zlib.NewWriter(&compressed)
	if _, err := w.Write(serialized); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	w.Close()
	// Encode the compressed byte points with base64.
	encoded := make([]byte, base64.StdEncoding.EncodedLen(compressed.Len()))
	base64.StdEncoding.Encode(encoded, compressed.Bytes())

	fmt.Fprintln(fi, "// Copyright (c) 2015 The btcsuite developers")
	fmt.Fprintln(fi, "// Use of this source code is governed by an ISC")
	fmt.Fprintln(fi, "// license that can be found in the LICENSE file.")
	fmt.Fprintln(fi)
	fmt.Fprintln(fi, "package elliptic")
	fmt.Fprintln(fi)
	fmt.Fprintln(fi, "// Auto-generated file (see genprecomps.go)")
	fmt.Fprintln(fi, "// DO NOT EDIT")
	fmt.Fprintln(fi)
	fmt.Fprintf(fi, "var secp256k1BytePoints = %q\n", string(encoded))

	a1, b1, a2, b2 := ec.S256().EndomorphismVectors()
	fmt.Println("The following values are the computed linearly " +
		"independent vectors needed to make use of the secp256k1 " +
		"endomorphism:")
	fmt.Printf("a1: %x\n", a1)
	fmt.Printf("b1: %x\n", b1)
	fmt.Printf("a2: %x\n", a2)
	fmt.Printf("b2: %x\n", b2)
}