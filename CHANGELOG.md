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

### 2.6.0
 * Pull in `JsonWebKeySet` from `vclib`
 * Implement JWK Set Url (`jku`) in JWS headers
 * Implement Attestation JWT (`jwt`) in JWS headers
 * Implement Confirmation keys (`cnf`) in JWT
 * Implement `CborWebToken` (RFC 8392)
 * Boolean ASN.1 decoding helper function
 * Certificate to/from JCA certificate conversion functions

## 3.0

### 3.0.0

**Fixes**
 * Restructure and fix `RelativeDistinguishedName`. **THIS IS A BREAKING CHANGE**
 * Fix `Asn1Time` not truncating to seconds
 * Fix parsing of CryptoSignature when decoding Certificates
 * Remove bogus `serialize()` function from `CryptoSignature`  **THIS IS A BREAKING CHANGE**


**Features**
 * Wrap exceptions during deserialization in `KmmResult`, i.e. changing all `deserialize()` methods in companion objects  **THIS IS A BREAKING CHANGE**
 * Move class `JweDecrypted` from package `at.asitplus.wallet.lib.jws` to `at.asitplus.crypto.datatypes.jws`  **THIS IS A BREAKING CHANGE**
 * Support more JWE algorithms, e.g. AES
 * Add `header` to constructor parameters of `JweEncrypted`
 * Extend properties of `JsonWebKey`
 * Introduce `CertificateChain` typealias with `.leaf` and `.root` convenience properties
 * Use `CertificateChain` inside `JwsHeader` instead of `Array<ByteArray>'
 * Use `CertificateChain` inside `JsonWebKey` instead of `Array<ByteArray>'

 * SubjectAltNames and IssuerAltNames:
    * Perform some structural validations on SAN and IAN
    * Expose `TbsCertificate.issuerAltNames` and `TbsCertificte.subjectAltnames`, which contain (somewhat) parsed
      `AlternativeNames` structures for easy access to `dnsName`. `iPAddress`, etc.

### 3.1.0

**Fixes**
 * Standardize class names: `Ec` -> `EC` everywhere
 * Fix an edge case where very small `r`/`s` in `CryptoSignature.EC` would be corrupted
 * Remove bogus ASN.1 encoding from JWS Algorithms
   * `CryptoSignature.EC` now requires specification of a curve or size when reading raw bytes

**Features**
 * Support ASN.1 encoding/decoding for `BigInteger`
 * Expose `generator`, `order` and `cofactor` of `ECCurve`
 * Extend list of values in `JweAlgorithm` and `JweEncryption`
 * Extend properties in `JweHeader`
 * Extend properties in `JwsHeader`
 * **BREAKING CHANGE:** Completely revamp the ASN.1 builder DSL
   * explicitly require `+` to add some ASN.1 element to a builder
   * Make convenience functions like `Bool(<boolean value>)`work stand-alone
 * Introduce common interface `JsonWebAlgorithm` for Jw{s,e}Algorithm
 * JsonWebKey Changes:
   * do not generate kid when there is none and allow removing it
   * reference `JsonWebAlgorithm` instead of `JwsAlgorithm`
   * add `.didEncoded`, which may return null, if encoding fails
 * add `.curve` to EC CryptoAlgorithms
 * Change JweAlgorithm to sealed class to support unknown algorithms
 * Add generic `ECPoint` class
 * Implement elliptic-curve arithmetic


### 3.2.0

* Kotlin 2.0
* Gradle 8.8
* Bouncy Castle 1.78.1
* Kotest 5.9.1 
* Coroutines 1.8.1
* Serialization 1.7.1-SNAPSHOT
* KmmResult 1.6.2

**Fixes**
 * Move `curve` from `CryptoAlgorithm` to `JwsAlgorithm`
 * Don't assume curve information for the X.509 signature when, in fact, none exists
   * `CryptoSignature`s in X.509 are now indefinite length

**Changes**
* Always DID-encode keys in compressed form (but keep decoding support)
* Rename `CryptoAlgorithm` to `X509SignatureAlgorithm` to better describe what it is
  * Rename `toCryptoAlgorithm` to `toX509SignatureAlgorithm` accordingly
* Rework CryptoSignature to two-dimensional interface:
  * CryptoSignature <- {EC <- {IndefiniteLength, DefiniteLength}, RsaOrHmac}
  * CryptoSignature <- {RawByteEncodable <- {EC.DefiniteLength, RsaOrHmac}, NotRawByteEncodable <- EC.IndefiniteLength}

### NEXT

* KmmResult 1.7.0

**Changes**
* Add `provider` module that actually implements cryptography!
* Add `COSE_Key` header to `CoseHeader`, defined in OpenID for Verifiable Credential Issuance draft 13
* Fix serialization of COSE signature structures
* Refactor `JsonWebKey`:
  * Remove `identifier`, please use `keyId` or `jwkThumbprint` directly
  * Add `equalsCryptographically()` to compare two keys by their cryptographic properties only
