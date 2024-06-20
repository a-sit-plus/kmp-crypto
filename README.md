# 🔥🔥🔥KMP Crypto🔥🔥🔥

[![GitHub license](https://img.shields.io/badge/license-Apache%20License%202.0-brightgreen.svg?style=flat)](http://www.apache.org/licenses/LICENSE-2.0)
[![Kotlin](https://img.shields.io/badge/kotlin-multiplatform-orange.svg?logo=kotlin)](http://kotlinlang.org)
[![Kotlin](https://img.shields.io/badge/kotlin-2.0.0-blue.svg?logo=kotlin)](http://kotlinlang.org)
[![Java](https://img.shields.io/badge/java-17+-blue.svg?logo=OPENJDK)](https://www.oracle.com/java/technologies/downloads/#java11)
[![Maven Central](https://img.shields.io/maven-central/v/at.asitplus.crypto/datatypes)](https://mvnrepository.com/artifact/at.asitplus.crypto/datatypes/)

## Kotlin Multiplatform Crypto/PKI Library and ASN1 Parser + Encoder

_(We are not doing the Prince thing; the emojis are not part of the project name)_

This [Kotlin Multiplatform](https://kotlinlang.org/docs/multiplatform.html) library provides platform-independent data
types and functionality related to crypto and PKI applications:

* **Multiplatform ECDSA and RSA verification**
* Public Keys (RSA and EC)
* Algorithm Identifiers (Signatures, Hashing)
* X509 Certificate Class (create, encode, decode)
* Certification Request (CSR)
* ObjectIdentifier Class with human-readable notation (e.g. 1.2.9.6245.3.72.13.4.7.6)
* Generic ASN.1 abstractions to operate on and create arbitrary ASN.1 Data
* JWS-related data structures (JSON Web Keys, JWT, etc…)
* COSE-related data structures (COSE Keys, CWT, etc…)
* Serializability of all ASN.1 classes for debugging **AND ONLY FOR DEBUGGING!!!** *Seriously, do not try to deserialize ASN.1 classes through kotlinx.serialization! Use `decodeFromDer()` and its companions!*
* 100% pure Kotlin BitSet
* **ASN.1 Parser and Encoder including a DSL to generate ASN.1 structures**

This last bit means that
**you can work with X509 Certificates, public keys, CSRs and arbitrary ASN.1 structures on iOS.**  
The last bit means that you can verify signatures on the JVM, Android and on iOS.

**Do check out the full API docs [here](https://a-sit-plus.github.io/kmp-crypto/)**!

## Usage

This library was built for [Kotlin Multiplatform](https://kotlinlang.org/docs/multiplatform.html). Currently, it targets
the JVM, Android and iOS.

This library consists of four modules, each of which is published on maven central:

| Name | Info                                                                                                                         | Maven Coordinates                   |
|------|------------------------------------------------------------------------------------------------------------------------------|-------------------------------------|
|   `provider`    | KMP module implementing the actual cryptographic operations.                                                                 | `at.asitplus.crypto:provider`       |
|   `datatypes`   | Base module containing the cryptographic data strucures, algorithm identifiers, the ASN.1 parser, OIDs, X.509 certificate, … | `at.asitplus.crypto:datatypes`      |
|   `datatypes-jws`   | JWS/JWE/JWT add-on module containing JWS/E/T-specific data structures and extensions to convert from/to types contained in the base module. Includes all required kotlinx-serialization magic to allow for spec-compliant de-/serialization.                                                                                                                              | `at.asitplus.crypto:datatypes-jws`  |
|`datatypes-cose` |     COSE add-on module containing all COSE/CWT-specific data structures and extensions to convert from/to types contained in the base module. Includes all required kotlinx-serialization magic to allow for spec-compliant de-/serialization.                                                                                                                         | `at.asitplus.crypto:datatypes-cose` |

This separation keeps dependencies to a minimum, i.e. it enables including only JWT-related functionality, if COSE is irrelevant.

### Using it in your Projects

Simply declare the desired dependency to get going:

```kotlin 
implementation("at.asitplus.crypto:datatypes:$version")
```

```kotlin 
implementation("at.asitplus.crypto:provider:$version")
```

```kotlin 
implementation("at.asitplus.crypto:datatypes-jws:$version")
```

```kotlin 
implementation("at.asitplus.crypto:datatypes-cose:$version")
```

In addition, (while we're waiting for upstream to release new stable versions of `BigNum` and `kotlinx.serialization`),
add the following repositories to your project:

```kotlin
repositories {
  maven(uri("https://raw.githubusercontent.com/a-sit-plus/kotlinx.serialization/mvn/repo"))
  maven {
    url = uri("https://oss.sonatype.org/content/repositories/snapshots")
    name = "bigNum"
  }
}
```

<br>

_Relevant classes like `CryptoPublicKey`, `X509Certificate`, `Pkcs10CertificationRequest`, etc. all
implement `Asn1Encodable` and their respective companions implement `Asn1Decodable`.
Which means that you can do things like parsing and examining certificates, creating CSRs, or transferring key
material._

<br>

### Signature Verification

To verify a signature, obtain a `Verifier` instance using `SignatureAlgorithm.verifierFor(k: PublicKey)`.
`SignatureAlgorithm`s can be obtained from an `algorithm` member on a variety of specialized algorithms.
A variety of constants, resembling the well-known JCA names, are also available in `SignatureAlgorithm`'s companion.

As an example, here's how to verify a basic signature using a public key:
```kotlin
val publicKey: CryptoPublicKey.EC = TODO("You have this and trust it.")
val plaintext = "You want to trust this.".encodeToByteArray()
val signature = TODO("This was sent alongside the plaintext.")
val verifier = SignatureAlgorithm.ECDSAwithSHA256.verifierFor(publicKey).getOrThrow()
val isValid = verifier.verify(plaintext, signature).isSuccess
println("Looks good? $isValid")
```

Or here's how to validate a X.509 certificate:
```kotlin
val rootCert: X509Certificate = TODO("You have this and trust it.")
val untrustedCert: X509Certificate = TODO("You want to verify that this is trustworthy.")

val verifier = untrustedCert.signatureAlgorithm.verifierFor(rootCert.publicKey).getOrThrow()
val plaintext = untrustedCert.tbsCertificate.encodeToDer()
val signature = untrustedCert.signature
val isValid = verifier.verify(plaintext, signature).isSuccess
println("Certificate looks trustworthy: $isValid")
```

#### Platform Verifiers

Not every platform supports every algorithm parameter. For example, iOS does not support raw ECDSA verification (of pre-hashed data).
If you use `.verifierFor`, and this happens, the library will transparently substitute a pure-Kotlin implementation.

If this is not desired, you can specifically enforce a platform verifier by using `.platformVerifierFor`.
That way, the library will only ever act as a proxy to platform APIs (JCA, CryptoKit, etc.), and will not use its own implementations.

You can also further configure the verifier, for example to specify the `provider` to use on the JVM.
To do this, pass a DSL configuration lambda to `verifierFor`/`platformVerifierFor`.

```kotlin
val publicKey: CryptoPublicKey.EC = TODO("You have this.")
val plaintext: ByteArray = TODO("This is the message.")
val signature: CryptoSignature.EC = TODO("And this is the signature.")
    
val verifier = SignatureAlgorithm.ECDSAwithSHA512
    .platformVerifierFor(publicKey) { provider = "BC"} /* specify BouncyCastle */
    .getOrThrow()
val isValid = verifier.verify(plaintext, signature).isSuccess
println("Is it trustworthy? $isValid")
```

### Certificate Parsing

```kotlin
val cert = X509Certificate.decodeFromDer(certBytes)

when (val pk = cert.publicKey) {
    is CryptoPublicKey.EC -> println(
        "Certificate with serial no. ${
            cert.tbsCertificate.serialNumber
        } contains an EC public key using curve ${pk.curve}"
    )

    is CryptoPublicKey.Rsa -> println(
        "Certificate with serial no. ${
            cert.tbsCertificate.serialNumber
        } contains a ${pk.bits.number} bit RSA public key"
    )
}

println("The full certificate is:\n${Json { prettyPrint = true }.encodeToString(cert)}")

println("Re-encoding it produces the same bytes? ${cert.encodeToDer() contentEquals certBytes}")
```

Which produces the following output:
> Certificate with serial no. 19821EDCA68C59CF contains an EC public key using curve SECP_256_R_1
>
> The full certificate is:

<details>
    <summary>{ "tbsCertificate": {…</summary>

```json
{
  "tbsCertificate": {
    "serialNumber": "GYIe3KaMWc8=",
    "signatureAlgorithm": "ES384",
    "issuerName": [
      {
        "type": "C",
        "value": "13024154"
      },
      {
        "type": "O",
        "value": "133352657075626C696B204F65737465727265696368202876657274726574656E20647572636820424B4120756E6420424D445729"
      },
      {
        "type": "OU",
        "value": "130A542D556D676562756E67"
      },
      {
        "type": "CN",
        "value": "132B542D52657075626C696B2D4F657374657272656963682D41757468656E746966697A696572756E672D3031"
      }
    ],
    "validFrom": "170D3233303932303132343135305A",
    "validUntil": "170D3233303932333132353134395A",
    "subjectName": [
      {
        "type": "C",
        "value": "13024154"
      },
      {
        "type": "O",
        "value": "133352657075626C696B204F65737465727265696368202876657274726574656E20647572636820424B4120756E6420424D445729"
      },
      {
        "type": "OU",
        "value": "130A542D556D676562756E67"
      },
      {
        "type": "CN",
        "value": "1340542D42696E64756E67732D5A6572746966696B61742D4157502D3165306436383063656464613439636539313337386462613934326533663432346663663164"
      }
    ],
    "publicKey": {
      "type": "EC",
      "curve": "P-256",
      "x": "/wlkNNLhIKmO7tQY1824tD6FSf1/evXzQui1quzsSpw=",
      "y": "SggoS/B464PKcHXT9phYxBPOnMEwL/ZC+Q9vZXoxY/g="
    },
    "extensions": [
      {
        "id": "1.3.6.1.5.5.7.1.1",
        "value": "MDEwLwYIKwYBBQUHMAGGI2h0dHA6Ly9vY3NwMy5vZXN0ZXJyZWljaC5ndi5hdC9vY3Nw"
      },
      {
        "id": "2.5.29.14",
        "value": "BBRQQnap5sOMkNX+lCHhWGstLkEe6Q=="
      },
      {
        "id": "2.5.29.35",
        "value": "MBaAFAgwoHa6fUvtsBT+jMHkTBAnomXU"
      },
      {
        "id": "2.5.29.31",
        "value": "MDQwMqAwoC6GLGh0dHA6Ly9jcmwzLm9lc3RlcnJlaWNoLmd2LmF0L2NybC9vZWd2LzFhY2Ex"
      },
      {
        "id": "2.5.29.15",
        "critical": true,
        "value": "AwIHgA=="
      },
      {
        "id": "2.5.29.37",
        "critical": true,
        "value": "MAoGCCsGAQUFBwMC"
      },
      {
        "id": "1.2.40.0.10.2.6.1.1",
        "value": "MA2gAwIBAIEGcmVhZGVy"
      }
    ]
  },
  "signatureAlgorithm": "ES384",
  "signature": "MGQCMEAqUL8qRpPwDi7u1qeEXfJp7Pk4GE4diI9GTSTE/yzFEHJD/o6SRy+lCbJgo58+AwIwCTsMgGdWLIMkN9n1KsuLt6jD/FFF1qzHuj5cTH4JeY0bNwLPxvAUVk3V43pCfMgD"
}
```

</details> 

> Re-encoding it produces the same bytes? true

### Creating a CSR

```kotlin
val ecPublicKey: ECPublicKey = TODO("From platform-specific code")
val cryptoPublicKey = CryptoPublicKey.EC.fromJcaPublicKey(ecPublicKey).getOrThrow()

val commonName = "DefaultCryptoService"
val signatureAlgorithm = X509SignatureAlgorithm.ES256


val tbsCsr = TbsCertificationRequest(
    version = 0,
    subjectName = listOf(RelativeDistinguishedName(AttributeTypeAndValue.CommonName(Asn1String.UTF8(commonName)))),
    publicKey = cryptoPublicKey
)
val signed: ByteArray = TODO("pass tbsCsr.encodeToDer() to platform code")
val csr = Pkcs10CertificationRequest(tbsCsr, signatureAlgorithm, signed)

println(csr.encodeToDer())
```

Which results in the following output:

> [3081D9308181020100301F311D301B06035504030C1444656661756C74437279
> 70746F536572766963653059301306072A8648CE3D020106082A8648CE3D0301
> 07034200043797E977E359AAABFC9177E7C95FD5B4BE4AC24C4FF13F3233F774
> E8B65FE5FBA5057513BD076CFFB2E17567AC9BD43737FB6BDF496CC6DCB47194
> BBE7512F0BA000300A06082A8648CE3D0403020347003044022079D188C09E20
> C70AFF096B9484DDDE70484485FD551676273A517E818B94644E02206B222905
> D343C1D6FC9319A364CECA7E67956E4B99D63537E17A9F5D4093D7AE](https://lapo.it/asn1js/#MIHZMIGBAgEAMB8xHTAbBgNVBAMMFERlZmF1bHRDcnlwdG9TZXJ2aWNlMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEN5fpd-NZqqv8kXfnyV_VtL5KwkxP8T8yM_d06LZf5fulBXUTvQds_7LhdWesm9Q3N_tr30lsxty0cZS751EvC6AAMAoGCCqGSM49BAMCA0cAMEQCIHnRiMCeIMcK_wlrlITd3nBIRIX9VRZ2JzpRfoGLlGROAiBrIikF00PB1vyTGaNkzsp-Z5VuS5nWNTfhep9dQJPXrg)

### Working with Generic ASN.1 Structures

The magic shown above is based on a from-scratch 100% KMP implementation of an ASN.1 encoder and parser.
To parse any DER-encoded ASN.1 structure, call `Asn1Element.parse(derBytes)`, which will result in exactly a single
`Asn1Element`.
It can be re-encoded (and yes, it is a true re-encoding, since the original bytes are discarded after decoding) by
accessing the lazily evaluated `.derEncoded` property.

**Note that decoding operations will throw exceptions if invalid data is provided!**

A parsed `Asn1Element` can either be a primitive (whose tag and value can be read) or a structure (like a set or
sequence) whose child
nodes can be processed as desired. Subclasses of `Asn1Element` reflect this:

* `Asn1Primitive`
* `Asn1Structure`
    * `Asn1Set`
    * `Asn1Sequence`

Any complex data structure (such as CSR, public key, certificate, …) implements `Asn1Encodable`, which means you can:

* encapsulate it into an ASN.1 Tree by calling `.encodeToTlv()`
* directly get a DER-encoded byte array through the `.encodetoDer()` function

To also suport going the other way, the companion objects of these complex classes implement `Asn1Decodable`, which
allows for

* directly parsing DER-encoded byte arrays by calling `.decodeFromDer(bytes)`
* processing an `Asn1Element` by calling `.fromTlv(src)`

#### Decoding Values

Various helper functions exist to facilitate decoging the values contained in `Asn1Primitives`, such as `decodeInt()`,
for example.
However, anything can be decoded and tagged at will. Therefore, a generic decoding function exists, which has the
following signature:

```kotlin
inline fun <reified T> Asn1Primitive.decode(tag: UByte, decode: (content: ByteArray) -> T) 
```

Check out [Asn1Reader.kt](datatypes/src/commonMain/kotlin/at/asitplus/crypto/datatypes/asn1/Asn1Reader.kt) for a full
list
of helper functions.

#### ASN1 DSL for Creating ASN.1 Structures

While it is perfectly possible to manually construct a hierarchy of `Asn1Element` objects, we provide a more convenient
DSL, which returns an `Asn1Structure`:

```kotlin
Asn1.Sequence {
    +Tagged(1u) {
        +Asn1Primitive(BERTags.BOOLEAN, byteArrayOf(0x00))
    }
    +Asn1.Set {
        +Asn1.Sequence {
            +Asn1.SetOf {
                +PrintableString("World")
                +PrintableString("Hello")
            }
            +Asn1.Set {
                +PrintableString("World")
                +PrintableString("Hello")
                +Utf8String("!!!")
            }

        }
    }
    +Asn1.Null()

    +ObjectIdentifier("1.2.603.624.97")

    +Utf8String("Foo")
    +PrintableString("Bar")

    +Asn1.Set {
        +Asn1.Int(3)
        +Asn1.Long(-65789876543L)
        +Asn1.Bool(false)
        +Asn1.Bool(true)
    }
    +Asn1.Sequence {
        +Asn1.Null()
        +Asn1String.Numeric("12345")
        +UtcTime(Clock.System.now())
    }
}
```

In accordance with DER-Encoding, this produces the following ASN.1 structure:

```
SEQUENCE (8 elem)
  [1] (1 elem)
    BOOLEAN false
  SET (1 elem)
    SEQUENCE (2 elem)
      SET (2 elem)
        PrintableString Hello
        PrintableString World
      SET (3 elem)
        UTF8String !!!
        PrintableString World
        PrintableString Hello
  NULL
  OBJECT IDENTIFIER 1.2.603.624.97
  UTF8String Foo
  PrintableString Bar
  SET (4 elem)
    BOOLEAN false
    BOOLEAN true
    INTEGER 3
    INTEGER (36 bit) -65789876543
  SEQUENCE (3 elem)
    NULL
    NumericString 12345
    UTCTime 2023-10-21 21:14:49 UTC
```

## Limitations
* While the ASN.1 parser will happily parse any valid **DER-encoded** ASN.1 structure you throw at it and the encoder will
  write it back correctly too. (No, we don't care for BER, since we want to transport cryptographic material!)
* Higher-level abstractions (such as `X509Certificate`) are too lenient in some aspects and
  too strict in others.
  For example: DSA-signed certificates will not parse to an instance of `X509Certificate`.
  At the same time, certificates containing the same extension multiple times will work fine, even though they violate
  the spec.
  This is irrelevant in practice, since platform-specific code will perform the actual cryptographic operations on these
  data structures and complain anyway, if something is off.
* No OCSP and CRL Checks (though it is perfectly possible to parse this data from a certificate and implement the checks)
* We do need more comprehensive tests, but we're getting there, mostly thanks to [@iaik-jheher](https://github.com/iaik-jheher)
  and [@n0900](https://github.com/n0900).
* We don't yet know how compliant everything really is, but this code has been successfully handling cryptographic material
  for a couple of months now and we're improving whenever we hit an issue.
* Number of supported Algorithms is limited to the usual suspects (sorry, no Bernstein curves )-:)
