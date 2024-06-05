//
//  Krypto.swift
//  SwiftCrypto
//
//  Created by Bernd Prünster on 30.01.24.
//

// Generate RSA: https://developer.apple.com/documentation/security/certificate_key_and_trust_services/keys/generating_new_cryptographic_keys

import CryptoKit
import DeviceCheck
import Foundation
import LocalAuthentication


@objc public class Krypto: NSObject {

    private static let SUFFIX_PUBKEY = "pubKey"

    private class func prepareRetrievalQuery(_ alias: String, _ props: [String: Any]? = nil, _ authCtx: LAContext?) -> CFDictionary {
        var query = [kSecClass: kSecClassGenericPassword,
 kSecUseDataProtectionKeychain: true,
                 kSecAttrLabel: alias,
                kSecReturnData: true] as [String: Any]
        if let id = Bundle.main.bundleIdentifier {
            query[kSecAttrService as String] = id+"-"+alias
        }

        if  authCtx != nil {
            query[kSecUseAuthenticationContext as String] = authCtx
        }

        if props != nil {
            query.merge(props!) { _, second in second }
        }

        return query as CFDictionary
    }

    private class func signES256(_ query: CFDictionary, _ data:Data) throws -> Data {
        var item: CFTypeRef?
        let status: OSStatus = SecItemCopyMatching(query, &item)
        switch status {
        case errSecSuccess:
            do {
                guard let keyData = item as? Data,
                      let privateKey = try? SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: keyData)
                else {
                    throw RuntimeError("Could not get private key for data \(data)")
                }

                return  try privateKey.signature(for: data).derRepresentation
            }catch {
                throw RuntimeError("Error creating signature: \(error)")
            }
        default:
            throw RuntimeError("could not load private key due to status \(status)")
        }
    }

    @objc public class func getCertificate(_ alias: String) async throws -> Data {
        return try getItem(alias)
    }

    @objc public class func getPublicKey(_ alias: String) async throws -> Data {
        return try getItem("\(alias)-\(SUFFIX_PUBKEY)")
    }

     private  class func getItem(_ alias: String)  throws -> Data {
        var item: CFTypeRef?
        let status: OSStatus = SecItemCopyMatching(prepareRetrievalQuery(alias, nil, nil), &item)
        switch status {
        case errSecSuccess:
               return item as! Data
        default:
            throw RuntimeError("could not load public key due to status \(status)")
        }
    }

    private class func signES384(_ query: CFDictionary, _ data:Data) throws -> Data {
        var item: CFTypeRef?
        let status: OSStatus = SecItemCopyMatching(query, &item)
        switch status {
        case errSecSuccess:
            do {
                guard let keyData = item as? Data,
                      let privateKey = try? P384.Signing.PrivateKey(derRepresentation: keyData)
                else {
                    throw RuntimeError("Could not get private key for data \(data)")
                }

                return  try privateKey.signature(for: data).derRepresentation
            }catch {
                throw RuntimeError("Error creating signature: \(error)")
            }
        default:
            throw RuntimeError("could not load private key due to status \(status)")
        }
    }


    private class func signES512(_ query: CFDictionary, _ data:Data) throws -> Data {
        var item: CFTypeRef?
        let status: OSStatus = SecItemCopyMatching(query, &item)
        switch status {
        case errSecSuccess:
            do {
                guard let keyData = item as? Data,
                      let privateKey = try? P521.Signing.PrivateKey(derRepresentation: keyData)
                else {
                    throw RuntimeError("Could not get private key for data \(data)")
                }

                return  try privateKey.signature(for: data).derRepresentation
            }catch {
                throw RuntimeError("Error creating signature: \(error)")
            }
        default:
            throw RuntimeError("could not load private key due to status \(status)")
        }
    }

    @objc public class func sign(_ input: Data, _ alias: String, _ alg: String, _ props: [String: Any]? = nil, _ authCtx: LAContext? = nil) async throws -> Data {
        do {
            print("loading private key...")
            let query = prepareRetrievalQuery(alias, props, authCtx)
            return if alg == "ES256" {
                try signES256(query, input)
            }else if alg == "ES384" {
                try signES384(query, input)
            }else if alg == "ES512" {
                try signES512(query, input)
            } else {throw RuntimeError("Algorithm \(alg) not supported")}
        } catch {
            throw RuntimeError("Signature creation failed due to \(error)")
        }
    }

    @objc public class func createAttestedKey(_ alias: String, _ challenge: Data, _ props: [String: Any]?, _ accessibilityValue: CFTypeRef, _ flags: SecAccessControlCreateFlags, _ authCtx: LAContext? = nil) async throws -> KeyPairAttestation {
        if !DCAppAttestService.shared.isSupported {
            throw RuntimeError("Attestation not supported!")
        }
        guard let publicKey = try? await createSigningKey(alias, "ES256", props, accessibilityValue, flags, authCtx) else {
            throw RuntimeError("Can't generate key for attestation")
        }
        guard let attestationKeyId = try? await DCAppAttestService.shared.generateKey() else {
            throw RuntimeError("Can't generate key for attestation")
        }

        guard let attestationStatement = await attestKey(with: challenge, also: publicKey, key: attestationKeyId) else {
            throw RuntimeError("Error: Can't create attestation statement")
        }
        return KeyPairAttestation(publicKey: publicKey, attestationStatement: attestationStatement)
    }

    @objc public class func keyExists(_ alias: String, _ authCtx: LAContext? = nil) -> Bool{
        let findQuery = prepareRetrievalQuery(alias, nil, authCtx)
        var item: CFTypeRef?

        return SecItemCopyMatching(findQuery, &item) == errSecSuccess

    }

    @objc public class func createSigningKey(_ alias: String, _ alg: String, _ props: [String: Any]?, _ accessibilityValue: CFTypeRef, _ flags: SecAccessControlCreateFlags, _ authCtx: LAContext? = nil) async throws -> Data {

        if(keyExists(alias, authCtx)) {
            throw RuntimeError("Key with alias \(alias) already exists")
        }
        var error2: Unmanaged<CFError>?
        let flags2 = SecAccessControlCreateFlags.privateKeyUsage
        /*
         //we could also do
         var flags2 = flags
         flags2.insert(SecAccessControlCreateFlags.privateKeyUsage)*/
        //however: then we would have kSecAccessControl on the keyChain and in the secure enclave. this would lead to the user having to authenticate twice for signing:
        //once due to the outer flags and once due to the access control flags in the secure enclave
        guard let access2 = SecAccessControlCreateWithFlags(kCFAllocatorDefault, accessibilityValue, flags2, &error2) else {
            throw RuntimeError("Can't create access flags: \(error2)")
        }
        let (priv, pub) = if alg == "ES256" {
            await createSecureEnclaveP256Key(access2, nil) //for the same reason as above, we won't be using an auth context here
        } else if alg == "ES384" {
            await createP384Key()
        } else if alg == "ES512" {
            await createP521Key()
        } else if alg == "RSA2048" {
           try  generateRSAKeyPair(keySize: 2048, alias: alias)
          } else {
              throw RuntimeError("Illegal Algorithm: \(alg)")
          }

        if pub == nil { throw RuntimeError("Can't create private key") }

    //    if alg.starts(with: "ES") {
        print("Storing key with \(alias) in KeyChain")
            // SecureEnclave keys from CryptoKit shall be stored as "passwords"
            // (their data representation is an encrypted blob)
            var query = [kSecClass: kSecClassGenericPassword,
     kSecUseDataProtectionKeychain: true,
                     kSecAttrLabel: alias,
                     kSecValueData: priv!] as [String: Any]

            if flags.isEmpty == false {
                var error: Unmanaged<CFError>?
                guard let access = SecAccessControlCreateWithFlags(kCFAllocatorDefault, accessibilityValue, flags, &error) else {
                    throw RuntimeError("Can't create access flags: \(error)")
                }
                query[kSecAttrAccessControl as String] = access
            }

            if( authCtx != nil) {
             query[kSecUseAuthenticationContext as String] = authCtx
            }

            let pubAlias = "\(alias)-\(SUFFIX_PUBKEY)"

             var pubQuery = [kSecClass: kSecClassGenericPassword,
                 kSecUseDataProtectionKeychain: true,
                                 kSecAttrLabel: pubAlias,
                                 kSecValueData: pub!] as [String: Any]

            //I can't even…
            if let id = Bundle.main.bundleIdentifier {
                query[kSecAttrService as String] = id+"-"+alias
                pubQuery[kSecAttrService as String] = id+"-"+pubAlias
            }

            if props != nil {
                query.merge(props!) { _, second in second }
            }

            let status = SecItemAdd(query as CFDictionary, nil)
            guard status == errSecSuccess else {
                throw RuntimeError("Can't store private key \(alias):  \(status), \(SecCopyErrorMessageString(status, nil))")
            }

            let pubStatus = SecItemAdd(pubQuery as CFDictionary, nil)
            guard pubStatus == errSecSuccess else {
                throw RuntimeError("Can't store public key \(pubAlias):  \(pubStatus), \(SecCopyErrorMessageString(pubStatus, nil))")
            }
    //    }
        return pub!
    }

    private class func generateRSAKeyPair(keySize: Int = 2048, alias: String) throws -> (privateKey: Data?, publicKey: Data?) {
        guard let tag = Bundle.main.bundleIdentifier else{
            throw RuntimeError("Can't store private key \(alias)")
        }

        guard let tagData = (tag+"-"+alias).data(using: .utf8) else {
            throw RuntimeError("Can't store private key \(alias)")
        }
        guard let pubTagData = (tag+"-"+alias+"-"+SUFFIX_PUBKEY).data(using: .utf8) else {
            throw RuntimeError("Can't store private key \(alias)")
        }

        let isPermanent = false
        let attributes: [CFString: Any] = [
            kSecAttrKeyType: kSecAttrKeyTypeRSA,
            kSecAttrKeySizeInBits: keySize,
            kSecPrivateKeyAttrs: [
                kSecAttrIsPermanent: isPermanent,
                kSecAttrApplicationTag: tagData,
                kSecAttrKeyType: kSecAttrKeyTypeRSA // Add this line
            ],
            kSecPublicKeyAttrs: [
                kSecAttrIsPermanent: isPermanent,
                kSecAttrApplicationTag: pubTagData,
                kSecAttrKeyType: kSecAttrKeyTypeRSA // Add this line
            ]
        ]

        var error: Unmanaged<CFError>?
        guard let privKey = SecKeyCreateRandomKey(attributes as CFDictionary, &error),
              let pubKey = SecKeyCopyPublicKey(privKey) else {
            throw  RuntimeError("RSA Key generation failed \(alias):  \(error) ")
        }

        guard let pubD = SecKeyCopyExternalRepresentation(pubKey, &error) else {
            throw  RuntimeError("RSA Key generation failed \(alias):  \(error) ")

        }
        guard let privD = SecKeyCopyExternalRepresentation(privKey, &error) else {
            throw  RuntimeError("RSA Key generation failed \(alias):  \(error) ")

        }


        return (privD as Data, pubD as Data)
    }


    private class func createSecureEnclaveP256Key(_ access: SecAccessControl, _ authCtx:LAContext?) async -> (Data?, Data?) {
        guard let privateKey: SecureEnclave.P256.Signing.PrivateKey = try? SecureEnclave.P256.Signing.PrivateKey(compactRepresentable: true, accessControl: access, authenticationContext: authCtx) else {
            return (nil, nil)
        }
        return (privateKey.dataRepresentation, privateKey.publicKey.derRepresentation)
    }

    private class func createP384Key() async -> (Data?, Data?) {
        let privateKey: P384.Signing.PrivateKey =  P384.Signing.PrivateKey(compactRepresentable: true)
        return (privateKey.derRepresentation, privateKey.publicKey.derRepresentation)
    }

    private class func createP521Key() async -> (Data?, Data?) {
        let privateKey: P521.Signing.PrivateKey = P521.Signing.PrivateKey(compactRepresentable: true)
        return (privateKey.derRepresentation, privateKey.publicKey.derRepresentation)
    }

    private class func attestKey(with challenge: Data, also clientData: Data, key: String) async -> [Data]? {
        if DCAppAttestService.shared.isSupported {
            do {
                let attestation = try await DCAppAttestService.shared.attestKey(key, clientDataHash: Data(SHA256.hash(data: challenge)))
                let assertion = try await DCAppAttestService.shared.generateAssertion(key, clientDataHash: Data(SHA256.hash(data: clientData)))
                return [attestation, assertion]
            } catch {
                print("attestKey failed")
                print(error)
            }
        }
        print("attestKey not supported")
        return nil
    }

    fileprivate static func verifyP256(_ derEncodedPubKey: Data, _ derEncodedDetachedSignature: Data, _ inputData: Data) throws -> Bool {
        let pubKey = try P256.Signing.PublicKey(derRepresentation: derEncodedPubKey)
        let sig = try P256.Signing.ECDSASignature(derRepresentation: derEncodedDetachedSignature)
        return pubKey.isValidSignature(sig, for: inputData)
    }
    fileprivate static func verifyP384(_ derEncodedPubKey: Data, _ derEncodedDetachedSignature: Data, _ inputData: Data) throws -> Bool {
        let pubKey = try P384.Signing.PublicKey(derRepresentation: derEncodedPubKey)
        let sig = try P384.Signing.ECDSASignature(derRepresentation: derEncodedDetachedSignature)
        return pubKey.isValidSignature(sig, for: inputData)
    }
    fileprivate static func verifyP521(_ derEncodedPubKey: Data, _ derEncodedDetachedSignature: Data, _ inputData: Data) throws -> Bool {
        let pubKey = try P521.Signing.PublicKey(derRepresentation: derEncodedPubKey)
        let sig = try P521.Signing.ECDSASignature(derRepresentation: derEncodedDetachedSignature)
        return pubKey.isValidSignature(sig, for: inputData)
    }

    @objc public class func verify(_ alg:String, _ derEncodedPubKey: Data, _ derEncodedDetachedSignature: Data, _ inputData: Data) async throws -> String {

        let verified = if alg == "ES256" {
            try verifyP256(derEncodedPubKey, derEncodedDetachedSignature, inputData)
        } else if alg  == "ES384" {
            try verifyP384(derEncodedPubKey, derEncodedDetachedSignature, inputData)
        } else if alg == "ES512" {
            try verifyP521(derEncodedPubKey, derEncodedDetachedSignature, inputData)
        }else {
            throw RuntimeError("Unsupported algorithm: \(alg)")
        }

        return "\(verified)"
    }

    @objc public class func clear(_ alias: String, _ authCtx: LAContext? = nil) {
        clearGenericPassword(for: alias, /*authCtx*/nil)
        let pubAlias = "\(alias)-\(SUFFIX_PUBKEY)"
        clearGenericPassword(for: pubAlias, nil) //pub Key is never protected → never need authCtx
    }

    @objc public class func storeCertificateChain(_ alias: String, _  asn1Sequence: Data) async throws -> String {
         var query = [kSecClass: kSecClassGenericPassword,
             kSecUseDataProtectionKeychain: true,
                             kSecAttrLabel: alias,
                             kSecValueData: asn1Sequence] as [String: Any]

        //I can't even…
        if let id = Bundle.main.bundleIdentifier {
            query[kSecAttrService as String] = id+"-"+alias
        }


        let crtStatus = SecItemAdd(query as CFDictionary, nil)
        guard crtStatus == errSecSuccess else {
            throw RuntimeError("Can't store certificate \(alias):  \(crtStatus), \(SecCopyErrorMessageString(crtStatus, nil))")
        }
        return "OK"
    }



    private class func clearGenericPassword(for alias: String, _ authCtx: LAContext?) {
        var deleteQuery: [String: Any] = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrLabel: alias,
        ] as [String: Any]

        if let auth = authCtx {
            deleteQuery[kSecUseAuthenticationContext as String] = auth
        }

        if let id = Bundle.main.bundleIdentifier {
            deleteQuery[kSecAttrService as String] = id+"-"+alias
        }
        let status = SecItemDelete(deleteQuery as CFDictionary)
        if status != errSecSuccess  {
                        print("Can't clear key for \(alias) with authCtx \(authCtx):  \(status), \(SecCopyErrorMessageString(status, nil))")
                    }
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

@objc public class KeyPairAttestation: NSObject {
    @objc public private(set) var publicKey: Data
    @objc public private(set) var attestationStatement: [Data]

    init(publicKey: Data, attestationStatement: [Data]) {
        self.publicKey = publicKey
        self.attestationStatement = attestationStatement
    }
}
