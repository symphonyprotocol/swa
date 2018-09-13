package main

import "bytes"
import "crypto/sha256"
import "golang.org/x/crypto/ripemd160"
import "math/big"
import "strings"
import "fmt"
import "log"
import "crypto/elliptic"
import "crypto/ecdsa"
import "crypto/rand"
import "crypto/aes"
import "golang.org/x/crypto/scrypt"


type BIP38Key struct {
	Flag byte
	Hash [4]byte
	Data [32]byte
}


/* b58encode encodes a byte slice b into a base-58 encoded string.
   https://en.bitcoin.it/wiki/Base58Check_encoding */
func b58encode(b []byte) (s string) {

	const BITCOIN_BASE58_TABLE = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

	x := new(big.Int).SetBytes(b)

	r := new(big.Int)
	m := big.NewInt(58)
	zero := big.NewInt(0)
	s = ""

	for x.Cmp(zero) > 0 {
		x.QuoRem(x, m, r)
		s = string(BITCOIN_BASE58_TABLE[r.Int64()]) + s
	}
	
	return s
}
// b58decode decodes a base-58 encoded string into a byte slice b.
func b58decode(s string) (b []byte, err error) {
	/* See https://en.bitcoin.it/wiki/Base58Check_encoding */

	const BITCOIN_BASE58_TABLE = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

	/* Initialize */
	x := big.NewInt(0)
	m := big.NewInt(58)

	/* Convert string to big int */
	for i := 0; i < len(s); i++ {
		b58index := strings.IndexByte(BITCOIN_BASE58_TABLE, s[i])
		if b58index == -1 {
			return nil, fmt.Errorf("Invalid base-58 character encountered: '%c', index %d.", s[i], i)
		}
		b58value := big.NewInt(int64(b58index))
		x.Mul(x, m)
		x.Add(x, b58value)
	}

	/* Convert big int to big endian bytes */
	b = x.Bytes()

	return b, nil
}

func byteToString(b []byte) (s string) {
	s = ""
	for i := 0; i < len(b); i++ {
		s += fmt.Sprintf("%02X", b[i])
	}
	return s
}

// Compress wallet public key to a 33 bytes 
func (wal * Wallet) publickeyToBytesCompressed() ([]byte) {

	x := wal.Publickey.X.Bytes()

	// pad x to 32 bytes
	padded_x := append(bytes.Repeat([]byte{0x00}, 32-len(x)), x...)

	if wal.Publickey.X.Bit(0) == 0 {
		return append([] byte{PUBKEY_COMPRESSED_EVEN}, padded_x...)
	}else{
		return append([] byte{PUBKEY_COMPRESSED_ODD}, padded_x...)
	}
}

func(wal *Wallet) publickeyToBytes()([] byte){
	x := wal.Publickey.X.Bytes()
	y := wal.Publickey.Y.Bytes()

	padded_x := append(bytes.Repeat([]byte{0x00}, 32-len(x)), x...)
	padded_y := append(bytes.Repeat([]byte{0x00}, 32-len(y)), y...)

	return append([]byte{PUBKEY_NOT_COMPRESSED_FLAG}, append(padded_x, padded_y...)...)
}

func (wal *Wallet) privatekeyToBytes() ([] byte){
	pri_bytes := wal.PrivateKey.D.Bytes()
	padding_pri_bytes := append(bytes.Repeat([]byte{0x00}, 32-len(pri_bytes)), pri_bytes...)
	return padding_pri_bytes
}

func base58CheckEncode(version uint8, bytes []byte) (res string){

	// Add version byte in front
	ver_bytes := append([]byte{version}, bytes...)
	
	// Perform SHA-256 hash
	s := sha256.New()
	s.Reset()
	s.Write(ver_bytes)
	hash1 := s.Sum(nil)

	// Perform SHA-256 hash
	s.Reset()
	s.Write(hash1)
	hash2 := s.Sum(nil)

	// Take the first checksum bytes of the second SHA-256 hash. This is the address checksum
	// Add the checksum bytes  at the end of vercode bytes
	checksum_bytes := append(ver_bytes, hash2[0:CHECKSUM_LEN]...)
	res = b58encode(checksum_bytes)


	for _, v := range checksum_bytes {
		if v != 0 {
			break
		}
		res = "1" + res
	}

	return res
}

func base58CheckDecode(s string)(version uint8, res []byte, err error){
	res, err = b58decode(s)
	if err != nil {
		return 0, nil, err
	}
	for i := 0; i < len(s); i++ {
		if s[i] != '1' {
			break
		}
		res = append([]byte{0x00}, res...)
	}
	
	if len(res) <= CHECKSUM_LEN{
		return 0, nil, fmt.Errorf("invalid base58 string, missing checksum")
	}

	sha := sha256.New()
	sha.Reset()
	sha.Write(res[0 : len(res) - CHECKSUM_LEN])
	hash1 := sha.Sum(nil)

	sha.Reset()
	sha.Write(hash1)
	hash2 := sha.Sum(nil)

	if bytes.Compare(hash2[0:4], res[len(res) - CHECKSUM_LEN:]) != 0{
		return 0, nil, fmt.Errorf("invalid checksum")
	}

	res = res[: len(res) - CHECKSUM_LEN]
	version = res[0]
	res = res[1:]

	return version, res, nil
}

func newKeyPair() (ecdsa.PrivateKey) {
	//椭圆曲线算法生成私钥
	curve := elliptic.P256()
	privateKey, err := ecdsa.GenerateKey(curve, rand.Reader)

	if err != nil {
		log.Panic(err)
	}
	return *privateKey
}

func bytesToPrivateKey(pri_key_bytes []byte) (priv_key ecdsa.PrivateKey, err error) {
	if len(pri_key_bytes) != PRIVATE_KEY_KEN {
		return priv_key, fmt.Errorf("invalid key length")
	}
	priv_key.D = new(big.Int).SetBytes(pri_key_bytes)
	return priv_key, nil
}

func privateKeyDerive(priv_key ecdsa.PrivateKey) (ecdsa.PrivateKey){
	curve := elliptic.P256()
	priv_key.PublicKey.Curve = curve
	priv_key.PublicKey.X, priv_key.PublicKey.Y  = curve.ScalarBaseMult(priv_key.D.Bytes())
	return priv_key
}

func (wal *Wallet) ToAddress() (address string) {

	pub_bytes := wal.publickeyToBytes()

	// Perform SHA-256 hashing on the public key
	s := sha256.New()
	s.Reset()
	s.Write(pub_bytes)
	hash1 := s.Sum(nil)
	
	//  Perform RIPEMD-160 hashing 
	r := ripemd160.New()
	r.Reset()
	r.Write(hash1)
	hash2 := r.Sum(nil)
	address = base58CheckEncode(WALLET_ADDRESS_FLAG, hash2)
	return address
}

// convert public key to address
// https://en.bitcoin.it/wiki/Technical_background_of_Bitcoin_addresses
func (wal *Wallet) ToAddressCompressed() (address string) {

	pub_bytes := wal.publickeyToBytesCompressed()

	// Perform SHA-256 hashing on the public key
	s := sha256.New()
	s.Reset()
	s.Write(pub_bytes)
	hash1 := s.Sum(nil)
	
	//  Perform RIPEMD-160 hashing 
	r := ripemd160.New()
	r.Reset()
	r.Write(hash1)
	hash2 := r.Sum(nil)
	address = base58CheckEncode(WALLET_ADDRESS_FLAG, hash2)
	return address
}

//convert private key to wallet import format string
func (wal *Wallet) ToWIF() (wif string){
	pri_bytes := wal.privatekeyToBytes()
	wif = base58CheckEncode(WIF_VERSION, pri_bytes)
	return wif
}

func FromWIF(wif string) (*Wallet, error) {
	check_res, priv_key_bytes, err := CheckWIF(wif)
	if check_res && err == nil{
		priv_key, err2 := bytesToPrivateKey(priv_key_bytes)
		if err2 == nil{
			derive_key := privateKeyDerive(priv_key)
			publickey := derive_key.PublicKey
			return &Wallet{derive_key, publickey}, nil

		}else{
			return nil, err2
		}
	}else{
		return nil, err
	}
}

//convert private key to wallet import format string with public key compressed flag
func (wal *Wallet) ToWIFCompressed() (wif string){
	pri_bytes := wal.privatekeyToBytes()
	// to tell wallet use compressed public keys
	pri_bytes = append(pri_bytes, []byte{WIF_COMPRESSED_FLAG}...)
	wif = base58CheckEncode(WIF_VERSION, pri_bytes)
	return wif
}

func (wal *Wallet) ToPublicKey() (pub_key_str string) {
	pub_key := wal.publickeyToBytes()
	pub_key_str = byteToString(pub_key)
	return pub_key_str
}

func(wal *Wallet) ToPublicKeyCompressed()(pub_key_str string){
	pub_key := wal.publickeyToBytesCompressed()
	pub_key_str = byteToString(pub_key)
	return pub_key_str
}

func(wal *Wallet) ToPrivateKey()(priv_key_str string){
	priv_key := wal.privatekeyToBytes()
	priv_key_str = byteToString(priv_key)
	return priv_key_str
}

func CheckWIF(wif string) (valid bool, priv_key_bytes [] byte,  err error){
	version, priv_bytes, err := base58CheckDecode(wif)
	if err != nil{
		return false, nil, err
	}

	if version != WIF_VERSION{
		return false, nil,  fmt.Errorf("invalid version: %02x", version)
	}

	if(len(priv_bytes) != 32 && len(priv_bytes) != 33){
		return false, nil, fmt.Errorf("invalid private key length")
	}

	if len(priv_bytes) == 33{
		if priv_bytes[len(priv_bytes)-1] != WIF_COMPRESSED_FLAG{
			return false, nil, fmt.Errorf("invalid private key, unknow tail byte: %02x", priv_bytes[len(priv_bytes)-1])
		}
	}

	return true, priv_bytes, nil
}


func (wal *Wallet) ToBip38Encrypt(passphrase string) string{
	bip38 := new(BIP38Key)
	priv_bytes := wal.privatekeyToBytes()
	pub_bytes := wal.publickeyToBytes()
	ah := doubleHash256(pub_bytes)[:4]
	dh, _ := scrypt.Key([]byte(passphrase), ah, 16384, 8, 8, 64)

	bip38.Flag = byte(0xC0)
	copy(bip38.Hash[:], ah)
	copy(bip38.Data[:], encrypt(priv_bytes, dh[:32], dh[32:]))
	return bip38.String()
}

func Bip38Decrypt(b38 string, passphrase string) (string) {
	b, err := b58decode(b38)
	if err != nil {
		// return nil, err
	}
	bip38 := new(BIP38Key)
	bip38.Flag = b[2]
	copy(bip38.Hash[:], b[3:7])
	copy(bip38.Data[:], b[7:])

	dh, _ := scrypt.Key([]byte(passphrase), bip38.Hash[:], 16384, 8, 8, 64)
	p := decrypt(bip38.Data[:], dh[:32], dh[32:])
	priv_key_str := byteToString(p)
	return priv_key_str

}

func (bip BIP38Key) String() string {
	return b58encode(bip.Bytes())
}
func (bip BIP38Key) Bytes() []byte {
	dst := make([]byte, 39)

	dst[0] = byte(0x01)
	dst[1] = byte(0x42)
	dst[2] = bip.Flag

	copy(dst[3:], bip.Hash[:])
	copy(dst[7:], bip.Data[:])

	return dst
}
func encrypt(pk, dh1, dh2 []byte) (dst []byte) {
	c, _ := aes.NewCipher(dh2)

	for i, _ := range dh1 {
		dh1[i] ^= pk[i]
	}

	dst = make([]byte, 48)
	c.Encrypt(dst, dh1[:16])
	c.Encrypt(dst[16:], dh1[16:])
	dst = dst[:32]

	return
}
func decrypt(src, dh1, dh2 []byte) (dst []byte) {
	c, _ := aes.NewCipher(dh2)

	dst = make([]byte, 48)
	c.Decrypt(dst, src[:16])
	c.Decrypt(dst[16:], src[16:])
	dst = dst[:32]

	for i := range dst {
		dst[i] ^= dh1[i]
	}

	return
}
func doubleHash256(in []byte) []byte {
	s1 := sha256.New()
	s2 := sha256.New()

	s1.Write(in)
	s2.Write(s1.Sum(nil))

	return s2.Sum(nil)
}