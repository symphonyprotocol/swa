## HD(分层确定)钱包
**本代码基于BIP0032开发分层确定性钱包。**
**确定性钱包被开发成更容易从单个“种子”中生成许多密钥。**

### 安装

```
go get github.com/symphonyprotocol/swa
```

### 编译

```
go build -o swa *.go
```

### 使用


  #### 生成助记词
 

```
➜  swa git:(dev) ✗ ./swa newmnemonic
Mnemonic is: orphan sentence network gun purpose toe wolf bulk another slide involve mercy
```

#### 从助记词生成主公钥和主私钥

**-m**： 指定助记词
**-p**:     助记词的脑密码

```
➜  swa git:(dev) ✗ ./swa getkey -m "orphan sentence network gun purpose toe wolf bulk another slide involve mercy" -p "User@123"
master public key compressed           :0262B1764E5CBF6CAFCB3B72DFEBAE85348827F8772E4EB4A19BC7D3A5295BE194
master public key un compressed        :0462B1764E5CBF6CAFCB3B72DFEBAE85348827F8772E4EB4A19BC7D3A5295BE19442419221C40C2002CB008F60B999837AC3FB01333DF05738C440FCC70BC76A7A
master public key address              :12Xyeo1m2bmqANFAV6NWRj6oz5R1c5d7ZB
master public key address compressed   :1T3r9yFFM6St9wGSp7zMYP24G6pUYnL7y
master private key wif                 :5KjEcrVAEwtWEeKn46ySebFd6AxwuN9YwBf2kj3o26eSZtNigd6
master private key wif compressed      :L5fR7FRHnZGL3DjsrhN8CvBYHpywL8LjxA2rjzbL7qvFqjgbNVQ5
master private key str                 :FBEC50438CFD849DEE6EBEDDA98217EA75ACD06E27569571CB0D54446A392EFB
```

####  推导秘钥

**-m**： 指定助记词
**-pwd**:     助记词的脑密码
**-path**: 推导路径


**例如**，推导主秘钥的第一层子秘钥

```
➜  swa git:(dev) ✗ ./swa derivekey -m "orphan sentence network gun purpose toe wolf bulk another slide involve mercy" -pwd "User@123" -path "m/0"
derive public key compressed           :02879C2CE29F14FF2115229AC1834A471F8DAB6B1863449FE52968B81BD7D3B9DD
derive public key un compressed        :04879C2CE29F14FF2115229AC1834A471F8DAB6B1863449FE52968B81BD7D3B9DDC96CE28B46F90D1DE18F9ADF5485E9E87B84C4E7FAB4C3D368ACEAE16EDCAA64
derive public key address              :1CNJWMArmbrerkGN9JBnfdEQzHQY6SwMGN
derive public key address compressed   :14S5x7J74bm273WPc1CHu2NBwaZJfxVSDT
derive private key wif                 :5J1s8thMpkzgUyKATYNTo71d4xRSHoKGYSXcCnBLySMRi4uFpvU
derive private key wif compressed      :Kx6pHqB8uoBbGTZAk9TjGVXkCTcrd9Rdbmg6NzQfA6uA4FHb11Rk
derive private key str                 :1A4A5DC3FB04031D91A468869184DFFAFFB4FD15282D050948197DF93913D959
```
