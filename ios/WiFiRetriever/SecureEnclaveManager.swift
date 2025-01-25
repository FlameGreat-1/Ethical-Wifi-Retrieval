
import Foundation
import Security
import LocalAuthentication

class SecureEnclaveManager {
    enum SecureEnclaveError: Error {
        case keyGenerationFailed
        case encryptionFailed
        case decryptionFailed
    }

    private let tag = "com.wifiretriever.secureenclave"

    func generateKey() throws -> SecKey {
        let access = SecAccessControlCreateWithFlags(nil,
                                                     kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
                                                     [.privateKeyUsage, .userPresence],
                                                     nil)
        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
            kSecPrivateKeyAttrs as String: [
                kSecAttrIsPermanent as String: true,
                kSecAttrApplicationTag as String: tag,
                kSecAttrAccessControl as String: access as Any
            ]
        ]

        var error: Unmanaged<CFError>?
        guard let privateKey = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
            throw SecureEnclaveError.keyGenerationFailed
        }

        return privateKey
    }

    func encrypt(_ data: Data, with publicKey: SecKey) throws -> Data {
        var error: Unmanaged<CFError>?
        guard let encryptedData = SecKeyCreateEncryptedData(publicKey,
                                                            .eciesEncryptionStandardX963SHA256AESGCM,
                                                            data as CFData,
                                                            &error) as Data? else {
            throw SecureEnclaveError.encryptionFailed
        }
        return encryptedData
    }

    func decrypt(_ encryptedData: Data, with privateKey: SecKey) throws -> Data {
        var error: Unmanaged<CFError>?
        guard let decryptedData = SecKeyCreateDecryptedData(privateKey,
                                                            .eciesEncryptionStandardX963SHA256AESGCM,
                                                            encryptedData as CFData,
                                                            &error) as Data? else {
            throw SecureEnclaveError.decryptionFailed
        }
        return decryptedData
    }

    func getExistingKey() throws -> SecKey {
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: tag,
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecReturnRef as String: true
        ]

        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        guard status == errSecSuccess else {
            throw SecureEnclaveError.keyGenerationFailed
        }

        guard let key = item as? SecKey else {
            throw SecureEnclaveError.keyGenerationFailed
        }

        return key
    }
}
