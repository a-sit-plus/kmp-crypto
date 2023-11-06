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


### NEXT
* COSE Support
* Full RSA and HMAC Support
* new interface `Asn1OctetString` to unify both ASN.1 OCTET STREAM classes
* fix broken `content` property of `Asn1EncapsulatingOctetString`
* refactor `.derEncoded` property of `Asn1Encodable` interface to function `.encodeToDer()`
* consistent exception handling behaviour
  * throw new type `Asn1Exception` for ASN.1-related errors
  * add `xxxOrNull()` functions for all encoding/decoding/parsing functions

