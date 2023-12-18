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
  * Add `xxxSafe()` functions to encapsulate endocing/decoding in `KmmResult`
  * Return `KmmResult` for conversions between different key representations ( i.e. `CryptoPublicKey`, `CoseKey` and `JsonWebKey`) 

### 2.2.0
* Dependency Updates
  * KmmResult 1.5.4
* Refactor `MultiBaseHelper` to only handle conversion
* Change `JwsHeader.publicKey` from JsonWebKey to CryptoPublicKey
* Remove `SignatureValueLength` parameters from JWS & COSE Algorithm Enum class
* Remove deprecated functions
* New `CryptoAlgorithm` class
* New `CryptoSignature` class for easy Asn1 - RawByteArray conversion
* Rename `Jws` classes
  * New `CryptoAlgorithm` class
  * New `CryptoSignature` class for easy Asn1 - RawByteArray conversion
* Rename function in file `JcaExtensions.kt` from `.toPublicKey` to `.toJcaPublicKey` to reflect connection to JVMname function in file `JcaExtensions.kt` from `.toPublicKey` to `.toJcaPublicKey` to reflect connection to JVM
* Remove VcLib-specific constants