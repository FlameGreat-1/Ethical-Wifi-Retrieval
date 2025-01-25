import Foundation
import Security
import LocalAuthentication

class iOSKeychainManager {
    private let secureEnclaveManager = SecureEnclaveManager()
    
    enum KeychainError: Error {
        case itemNotFound
        case duplicateItem
        case invalidItemFormat
        case unexpectedStatus(OSStatus)
        case encryptionFailed
        case decryptionFailed
    }

    func storeWifiPassword(_ password: String, forSSID ssid: String) throws {
        let privateKey = try secureEnclaveManager.generateKey()
        let publicKey = SecKeyCopyPublicKey(privateKey)!

        guard let encryptedPassword = try? secureEnclaveManager.encrypt(password.data(using: .utf8)!, with: publicKey) else {
            throw KeychainError.encryptionFailed
        }

        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: ssid,
            kSecValueData as String: encryptedPassword,
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            kSecUseAuthenticationContext as String: LAContext()
        ]

        let status = SecItemAdd(query as CFDictionary, nil)

        guard status != errSecDuplicateItem else { throw KeychainError.duplicateItem }
        guard status == errSecSuccess else { throw KeychainError.unexpectedStatus(status) }
    }

    func retrieveWifiPassword(forSSID ssid: String) throws -> String {
        let context = LAContext()
        var error: NSError?
        
        guard context.canEvaluatePolicy(.deviceOwnerAuthentication, error: &error) else {
            throw KeychainError.unexpectedStatus(error?.code ?? 0)
        }
        
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: ssid,
            kSecMatchLimit as String: kSecMatchLimitOne,
            kSecReturnData as String: true,
            kSecUseAuthenticationContext as String: context
        ]

        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)

        guard status != errSecItemNotFound else { throw KeychainError.itemNotFound }
        guard status == errSecSuccess else { throw KeychainError.unexpectedStatus(status) }

        guard let encryptedPassword = item as? Data else {
            throw KeychainError.invalidItemFormat
        }

        let privateKey = try getPrivateKey()
        guard let decryptedData = try? secureEnclaveManager.decrypt(encryptedPassword, with: privateKey) else {
            throw KeychainError.decryptionFailed
        }

        guard let password = String(data: decryptedData, encoding: .utf8) else {
            throw KeychainError.invalidItemFormat
        }

        return password
    }

    func deleteWifiPassword(forSSID ssid: String) throws {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: ssid
        ]

        let status = SecItemDelete(query as CFDictionary)

        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw KeychainError.unexpectedStatus(status)
        }
    }

    private func getPrivateKey() throws -> SecKey {
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: "com.wifiretriever.secureenclave",
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecReturnRef as String: true
        ]

        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        guard status == errSecSuccess else {
            throw KeychainError.unexpectedStatus(status)
        }

        guard let privateKey = item as? SecKey else {
            throw KeychainError.invalidItemFormat
        }

        return privateKey
    }
}

