# Changelog

## 1.0

### 1.0.0
 First public release
 
## 2.0

### 2.0.0
 * JWS Support
 * Bugfixes and streamlining all over the place
 * Proper BIT STRING
 * BitSet (100% Kotlin BitSet implementation)
 * Recursively parsing (and encapsulating) ASN.1 structures in OCTET Strings
 * Initial pretty-printing of ASN.1 Strucutres
 * Massive ASN.1 builder DSL streamlining
 * More convenient explicit tagging


### 2.1.0
* Kotlin 1.9.20
* COSE Support
* Full RSA and HMAC Support
* New interface `Asn1OctetString` to unify both ASN.1 OCTET STREAM classes
* Fix broken `content` property of `Asn1EncapsulatingOctetString`
* Refactor `.derEncoded` property of `Asn1Encodable` interface to function `.encodeToDer()`
* Consistent exception handling behaviour
  * Throw new type `Asn1Exception` for ASN.1-related errors
  * Throw `IllegalArgumentException` for input-related errors
  * Add `xxxOrNull()` functions for all encoding/decoding/parsing functions
  * Add `xxxSafe()` functions to encapsulate encoding/decoding in `KmmResult`
  * Return `KmmResult` for conversions between different key representations ( i.e. `CryptoPublicKey`, `CoseKey` and `JsonWebKey`) 

### 2.2.0
* Dependency Updates
  * KmmResult 1.5.4
* Refactor `MultiBaseHelper` to only handle conversion
* Change `JwsHeader.publicKey` from JsonWebKey to CryptoPublicKey
* Remove `SignatureValueLength` parameters from JWS & COSE Algorithm Enum class
* Remove deprecated functions
* Rename `Jws` classes
  * New `CryptoAlgorithm` class
  * New `CryptoSignature` class for easy Asn1 - RawByteArray conversion
* Rename function in file `JcaExtensions.kt` from `.toPublicKey` to `.toJcaPublicKey` to reflect connection to JVM
* Remove VcLib-specific constants

#### 2.2.1
* Update conventions
  * Rename CBOR annotations
  * Target Java 17

### 2.3.0
* Change `CryptoPublicKey.toJsonWebKey()` return type from `KmmResult<JsonWebKey>` to `JsonWebKey`
* Add `CryptoSignature.parseFromJca` function
* Refactor `CryptoPublicKey.keyID` to `CryptoPublicKey.didEncoded` to better reflect what it actually is
* Rename `CryptoPublicKey.fromKeyId` to `CryptoPublicKey.fromDid`

### 2.4.0
* Add Support for EC Point compression
* Add Support for full Cose-Key Spec
* Correct Multibase Encoding
* Change `DID:KEY` encoding to Base58_BTC to comply with draft
* Add Multibase Encoder/Decoder
* Add UVarInt datatype (63 bit max)
* Remove MultibaseHelper
* Finally make `CoseKey`'s EC Point compression play nicely with kotlinx.serialization
* Rename `CoseKey.fromKeyId` to `CoseKey.fromDid`
* Rename `JsonWebKey.fromKeyId` to `JsonWebKey.fromDid`

### 2.5.0
* Parse more certificates from `x5c` in JWS headers
* Kotlin 1.9.23 thanks to updated conventions
* Generate `KnownOIDs` using [KotlinPoet](https://square.github.io/kotlinpoet/)
* Work around KT-65315 thanks to updated conventions
* BigNum as API dependency and iOS export (seems nonsensical,
  but is somehow required when using this inside a compose multiplatform app)
* Rename `BERTags.NULL` to `BERTags.ASN1_NULL` to fix broken ObjC export 
