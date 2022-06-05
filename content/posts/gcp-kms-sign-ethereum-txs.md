---
title: "Use GCP KMS to sign Ethereum trasactions"
date: 2022-06-05T10:20:53+08:00
author: LY Cheng
authorTwitter: lyforever
tags: [ "Web3", "GCP", "KMS", "Golang", "Ethereum" ]
keywords: [ "web3", "gcp", "kms", "go", "secp256k1", "ethereum" ]
draft: false
---

## What is Google Cloud Key Management Service
It's a cloud key management service provided by GCP (Google Cloud Platform). It supports HSM (hardware security modules) and multiple algorithms to encrypt. You can read more from [here](https://cloud.google.com/security-key-management). we will only focus on asymmetric signing and secp256k1 algorithm.

## Generate a private key
First, we need to generate a private key on GCP KMS. Here are commands we can use to generate. you need to install `gcloud` first. Check [this link](https://cloud.google.com/sdk/docs/install-sdk) to install.

* Generate keyrings named `dev-test`

`$ gcloud kms keyrings create dev-test --location asia-southeast1`

* Generate a private key named `private-test` under keyrings `dev-test`

`$ gcloud kms keys create private-test --keyring dev-test --location asia-southeast1 --purpose "asymmetric-signing" --protection-level "hsm" --default-algorithm ec-sign-secp256k1-sha256`

We choose `asymmetric-signing` to be our purpose and protection level is hsm. The most important thing is the algorithm is `ec-sign-secp256k1-sha256`. Why can we use `ec-sign-secp256k1-sha256` to generate a signature in Ethereum? In ethereum, people usually use `keccak256` as the hash algorithm but not `sha256`. From [this comment](https://github.com/celo-org/optics-monorepo/discussions/598) we found in the github issues, we can still use `keccak256` into the `sha256` field. Even its name is `sha256` but actually it won't know what's the algorithm you use.

## Verify the signature
Now we can write some code to verify the signature signed from GCP KMS. Before you test it, don't forget to generate a key file from GCP. Check [here](https://cloud.google.com/docs/authentication/production) to pass credentials to environment variable.

When we retrieve the public key from GCP KMS, we need to use the DER-encoded ASN.1 to parse it. Especially see those asn1 related types, it's the most important part before we dig into the ethereum compatible signature.

```go
import (
    "encoding/asn1"
    "encoding/pem"

    kms "cloud.google.com/go/kms/apiv1"
    kmspb "google.golang.org/genproto/googleapis/cloud/kms/v1"
)

type asn1EcPublicKey struct {
    EcPublicKeyInfo asn1EcPublicKeyInfo
    PublicKey       asn1.BitString
}

type asn1EcPublicKeyInfo struct {
    Algorithm  asn1.ObjectIdentifier
    Parameters asn1.ObjectIdentifier
}

// ctx := context.Background()
// client, err := kms.NewKeyManagementClient(ctx)
// name := "projects/my-project/locations/asia-southeast1/keyRings/dev-test/cryptoKeys/private-test/cryptoKeyVersions/1"
req := &kmspb.GetPublicKeyRequest{
    Name: name,
}

response, err := client.GetPublicKey(ctx, req)
if err != nil {
    log.Fatal(err)
}

block, _ := pem.Decode([]byte(response.Pem))
var asn1pubk asn1EcPublicKey
_, err = asn1.Unmarshal(block.Bytes, &asn1pubk)
if err != nil {
    log.Fatal(err)
}

publicKeyByte := asn1pubk.PublicKey.Bytes
```

For the signature, we can directly use hash of keccak256 in the Sha256 field. Then use ASN.1 to get R and S Value.  

```go
type asn1EcSig struct {
    R asn1.RawValue
    S asn1.RawValue
}
// txHashBytes := signer.Hash(tx).Bytes()
// you can use crypto.Keccak256Hash([]byte("plain text"))
req := &kmspb.AsymmetricSignRequest{
    Name: name,
    Digest: &kmspb.Digest{
        Digest: &kmspb.Digest_Sha256{
            Sha256: txHashBytes,
        },
    },
}

result, err := client.AsymmetricSign(ctx, req)
if err != nil {
    log.Fatal(err)
}

var sigAsn1 asn1EcSig
_, err = asn1.Unmarshal(result.Signature, &sigAsn1)
if err != nil {
    log.Fatal(err)
}

rBytes := sigAsn1.R.Bytes
sBytes := sigAsn1.S.Bytes
```

The S Value from GCP KMS maybe over the half N of secp256k, we need to adjust it to match the Ethereum standard. Then adjust the length of R and S bytes to fit 32 bytes each. The final step is to calculate to V value by recovering the public key. The V value is zero if the recovered public key matches the public key from GCP KMS otherwise V value should be one. If you think about different chain for the V value, it will be adjusted by `WithSignature` when you given a different chain id into the `Signer`.

```go
var secp256k1N = crypto.S256().Params().N
var secp256k1HalfN = new(big.Int).Div(secp256k1N, big.NewInt(2))
func adjustSignatureLength(buffer []byte) []byte {
    buffer = bytes.TrimLeft(buffer, "\x00")
    for len(buffer) < 32 {
        zeroBuf := []byte{0}
        buffer = append(zeroBuf, buffer...)
    }
    return buffer
}

// Adjust S value from signature according to Ethereum standard
sBigInt := new(big.Int).SetBytes(sBytes)
if sBigInt.Cmp(secp256k1HalfN) > 0 {
    sBytes = new(big.Int).Sub(secp256k1N, sBigInt).Bytes()
}

rsSignature := append(adjustSignatureLength(r), adjustSignatureLength(s)...)
signature := append(rsSignature, []byte{0}...)

recoveredPublicKeyBytes, err := crypto.Ecrecover(txHashBytes, signature)
if err != nil {
    log.Fatal(err)
}

if hex.EncodeToString(recoveredPublicKeyBytes) != hex.EncodeToString(expectedPublicKeyBytes) {
    signature = append(rsSignature, []byte{1}...)
    recoveredPublicKeyBytes, err = crypto.Ecrecover(txHashBytes, signature)
    if err != nil {
        log.Fatal(err)
    }

    if hex.EncodeToString(recoveredPublicKeyBytes) != hex.EncodeToString(expectedPublicKeyBytes) {
        log.Fatal(errors.New("can not reconstruct public key from sig"))
    }
}
```

## Generate a raw transaction with signature
Here is the full example to generate a ethereum transaction.

```go
func publicKeyBytesToAddress(publicKey []byte) common.Address {
    hash := crypto.Keccak256Hash(publicKey[1:])
    address := hash[12:]

    return common.HexToAddress(hex.EncodeToString(address))
}

fromAddress := publicKeyBytesToAddress(publicKeyBytes)
client, err := ethclient.Dial("[ethereum node url]")
if err != nil {
    log.Fatal(err)
}

value := big.NewInt(1000000000000000000) // in wei (1 eth)
gasLimit := uint64(21000)                // in units
gasPrice, err := client.SuggestGasPrice(context.Background())
if err != nil {
    log.Fatal(err)
}

toAddress := common.HexToAddress("0x4592d8f8d7b001e72cb26a73e4fa1806a51ac79d")
nonce, err := client.PendingNonceAt(context.Background(), fromAddress)
if err != nil {
    log.Fatal(err)
}
tx := types.NewTransaction(nonce, toAddress, value, gasLimit, gasPrice, nil)
// chainID := big.NewInt(1) // for mainnet
signer := types.LatestSignerForChainID(chainID)
signedTx := tx.WithSignature(signer, signature)
ts := types.Transactions{signedTx}
rawTxBytes, _ := rlp.EncodeToBytes(ts[0])
rawTxHex := hex.EncodeToString(rawTxBytes)
fmt.Printf("0x%s\n", rawTxHex)
```

## Reference

Really appreciate [welthee/go-ethereum-aws-kms-tx-signer](https://github.com/welthee/go-ethereum-aws-kms-tx-signer). lots of implements are borrowed from their code base.

* https://aws.amazon.com/blogs/database/how-to-sign-ethereum-eip-1559-transactions-using-aws-kms/
* https://goethereumbook.org/signature-verify/
* https://goethereumbook.org/transaction-raw-create/