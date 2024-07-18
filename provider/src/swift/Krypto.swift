//
//  Krypto.swift
//  SwiftCrypto
//

import CryptoKit
import Foundation

@objc public class SignerProxy: NSObject {
    let publicKey: SecKey
    let privateKey: SecKey
    init(_ pubKey: SecKey, _ privKey: SecKey) {
        publicKey = pubKey
        privateKey = privKey
    }

    @objc public func getPublicKey() throws -> Data
    {
        var error: Unmanaged<CFError>?
        guard let result = SecKeyCopyExternalRepresentation(publicKey, &error)
            else { throw error!.takeRetainedValue() as Error }
        return result as Data
    }

    @objc public func sign(_ digest: String, _ data: Data) throws -> Data
    {
        let algorithm: SecKeyAlgorithm = switch digest {
            case "SHA256": .ecdsaSignatureMessageX962SHA256
            case "SHA384": .ecdsaSignatureMessageX962SHA384
            case "SHA512": .ecdsaSignatureMessageX962SHA512
            default: throw RuntimeError("Unsupported digest \(digest)")
        }
        guard SecKeyIsAlgorithmSupported(privateKey, .sign, algorithm)
            else { throw RuntimeError("ECDSA with \(digest) is unsupported by this key") }

        var error: Unmanaged<CFError>?
        guard let signature = SecKeyCreateSignature(privateKey, algorithm, data as CFData, &error) as Data?
            else { throw error!.takeRetainedValue() as Error }
        return signature
    }
}

@objc public class Krypto: NSObject {

    // =========== SIGNING

    @objc public static func createAttestedP256Key(_ alias: String) throws -> SignerProxy
    {
        guard let bundleId = Bundle.main.bundleIdentifier
            else { throw RuntimeError("Failed to retrieve main bundle identifier") }
        let tag = "kmp-crypto-\(bundleId)"
    fputs("zero\n", stderr)
        //var error: Unmanaged<CFError>?
        /*guard let access = SecAccessControlCreateWithFlags(
            kCFAllocatorDefault,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            .privateKeyUsage,
            &error)
            else { throw error!.takeRetainedValue() as Error }*/

        let privateKeyParams = [
            kSecAttrLabel: "privkey-\(alias)",
            kSecAttrIsPermanent: true,
            kSecAttrApplicationTag: tag
        ] as CFDictionary
        let publicKeyParams = [
            kSecAttrLabel: "pubkey-\(alias)",
            kSecAttrIsPermanent: false,
            kSecAttrApplicationTag: tag
        ] as CFDictionary

        let parameters = [
            kSecAttrKeyType: kSecAttrKeyTypeEC,
            kSecAttrKeySizeInBits: 256,
            kSecAttrTokenID: kSecAttrTokenIDSecureEnclave,
            kSecPublicKeyAttrs: publicKeyParams,
            kSecPrivateKeyAttrs: privateKeyParams,
        ] as CFDictionary

    fputs("one\n", stderr)
        var pubKey, privKey: SecKey?
        let status = SecKeyGeneratePair(parameters, &pubKey, &privKey)
        if (status != errSecSuccess) {
            let e = SecCopyErrorMessageString(status, nil) as String? ?? "Unspecified security error"
            throw RuntimeError("Failed to generate key: \(e)")
        }
    fputs("three\n", stderr)
        return SignerProxy(pubKey!, privKey!)
    }

    // =========== VERIFICATION

    fileprivate static func verifyECDSA_P256(_ pubkeyDER: Data, _ sigDER: Data, _ data: any Digest) throws -> Bool {
        let pubKey = try P256.Signing.PublicKey(derRepresentation: pubkeyDER)
        let sig = try P256.Signing.ECDSASignature(derRepresentation: sigDER)
        return pubKey.isValidSignature(sig, for: data)
    }

    fileprivate static func verifyECDSA_P384(_ pubkeyDER: Data, _ sigDER: Data, _ data: any Digest) throws -> Bool {
        let pubKey = try P384.Signing.PublicKey(derRepresentation: pubkeyDER)
        let sig = try P384.Signing.ECDSASignature(derRepresentation: sigDER)
        return pubKey.isValidSignature(sig, for: data)
    }

    fileprivate static func verifyECDSA_P521(_ pubkeyDER: Data, _ sigDER: Data, _ data: any Digest) throws -> Bool {
        let pubKey = try P521.Signing.PublicKey(derRepresentation: pubkeyDER)
        let sig = try P521.Signing.ECDSASignature(derRepresentation: sigDER)
        return pubKey.isValidSignature(sig, for: data)
    }

    @objc public class func verifyECDSA(_ curve: String, _ digest: String, _ pubkeyDER: Data,
            _ sigDER: Data, _ data: Data) throws -> String
    {
        let hash: any Digest = switch digest {
            case "SHA256": SHA256.hash(data: data)
            case "SHA384": SHA384.hash(data: data)
            case "SHA512": SHA512.hash(data: data)
            default: throw RuntimeError("Unsupported digest \(digest)")
        }
        switch curve {
            case "P256": return try String(verifyECDSA_P256(pubkeyDER, sigDER, hash))
            case "P384": return try String(verifyECDSA_P384(pubkeyDER, sigDER, hash))
            case "P521": return try String(verifyECDSA_P521(pubkeyDER, sigDER, hash))
            default: throw RuntimeError("Unsupported curve \(curve)")
        }
    }

    fileprivate static func getRSAAlgorithm(_ padding: String, _ digest: String)
        throws -> SecKeyAlgorithm
    {
        switch padding {
            case "PKCS1": switch digest {
                case "SHA1": return .rsaSignatureMessagePKCS1v15SHA1
                case "SHA256": return .rsaSignatureMessagePKCS1v15SHA256
                case "SHA384": return .rsaSignatureMessagePKCS1v15SHA384
                case "SHA512": return .rsaSignatureMessagePKCS1v15SHA512
                default: throw RuntimeError("Unsupported digest \(digest) for padding \(padding)")
            }
            case "PSS": switch digest {
                case "SHA1": return .rsaSignatureMessagePSSSHA1
                case "SHA256": return .rsaSignatureMessagePSSSHA256
                case "SHA384": return .rsaSignatureMessagePSSSHA384
                case "SHA512": return .rsaSignatureMessagePSSSHA512
                default: throw RuntimeError("Unsupported digest \(digest) for padding \(padding)")
            }
            default: throw RuntimeError("Unsupported padding \(padding)")
        }
    }

    @objc public static func verifyRSA(_ padding: String, _ digest: String, _ pubkeyPKCS1: Data,
        _ sigDER: Data, _ data: Data) throws -> String
    {
        let algorithm = try getRSAAlgorithm(padding, digest)
        let options: [String: Any] = [kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
                                      kSecAttrKeyClass as String: kSecAttrKeyClassPublic]
        var error: Unmanaged<CFError>?
        guard let pubkey = SecKeyCreateWithData(pubkeyPKCS1 as CFData, options as CFDictionary, &error)
                            else { throw error!.takeRetainedValue() as Error }

        guard SecKeyVerifySignature(pubkey, algorithm, data as CFData, sigDER as CFData, &error)
            else { throw error!.takeRetainedValue() as Error }
        return "true"
    }
}

struct RuntimeError: LocalizedError {
    let description: String

    init(_ description: String) {
        self.description = description
    }

    var errorDescription: String? {
        description
    }
}
