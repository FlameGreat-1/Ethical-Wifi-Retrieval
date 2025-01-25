import Foundation
import Security
import LocalAuthentication
import MachO

class iOSKeychainExplorer {
    enum KeychainExplorerError: Error {
        case deviceNotTrusted
        case decryptionFailed
        case encryptionFailed
    }

    private let udid: String
    private let encryptionKey: Data

    init(udid: String) throws {
        self.udid = udid
        self.encryptionKey = try deriveEncryptionKey(from: udid)
        try verifyDeviceTrust()
    }

    private func verifyDeviceTrust() throws {
        if isJailbroken() {
            throw KeychainExplorerError.deviceNotTrusted
        }

        let context = LAContext()
        var error: NSError?
        
        guard context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error) else {
            throw KeychainExplorerError.deviceNotTrusted
        }
        
        var result = false
        let semaphore = DispatchSemaphore(value: 0)
        
        context.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, localizedReason: "Verify device trust") { success, error in
            result = success
            semaphore.signal()
        }
        
        semaphore.wait()
        
        if !result {
            throw KeychainExplorerError.deviceNotTrusted
        }
    }

    private func isJailbroken() -> Bool {
        #if targetEnvironment(simulator)
        return false
        #else
        let paths = [
            "/Applications/Cydia.app",
            "/Library/MobileSubstrate/MobileSubstrate.dylib",
            "/bin/bash",
            "/usr/sbin/sshd",
            "/etc/apt",
            "/private/var/lib/apt/"
        ]

        for path in paths {
            if FileManager.default.fileExists(atPath: path) {
                return true
            }
        }

        let dyldWhiteList = [
            "libSystem.B.dylib",
            "libSystem.dylib",
            "libobjc.A.dylib",
            "libc++.1.dylib",
            "libicucore.A.dylib",
            "libz.1.dylib",
            "libcache.dylib",
            "libsqlite3.dylib",
            "libxml2.2.dylib",
            "libnetwork.dylib",
            "libc++abi.dylib"
        ]

        for i in 0..<_dyld_image_count() {
            if let imageName = _dyld_get_image_name(i) {
                let name = String(cString: imageName)
                if !dyldWhiteList.contains(where: { name.hasSuffix($0) }) {
                    return true
                }
            }
        }

        return false
        #endif
    }

    func getWifiPasswords() throws -> [String: String] {
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: "WiFiNetwork",
            kSecReturnAttributes as String: true,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitAll
        ]

        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)

        guard status == errSecSuccess else {
            throw KeychainExplorerError.deviceNotTrusted
        }

        guard let items = result as? [[String: Any]] else {
            return [:]
        }

        var passwords: [String: String] = [:]
        for item in items {
            if let ssid = item[kSecAttrAccount as String] as? String,
               let passwordData = item[kSecValueData as String] as? Data,
               let encryptedPassword = String(data: passwordData, encoding: .utf8) {
                passwords[ssid] = try decryptPassword(encryptedPassword)
            }
        }

        return passwords
    }

    private func decryptPassword(_ encryptedPassword: String) throws -> String {
        guard let data = Data(base64Encoded: encryptedPassword) else {
            throw KeychainExplorerError.decryptionFailed
        }

        let decrypted = try AES256.decrypt(data, withKey: encryptionKey)
        
        guard let decryptedString = String(data: decrypted, encoding: .utf8) else {
            throw KeychainExplorerError.decryptionFailed
        }

        return decryptedString
    }

    private func deriveEncryptionKey(from udid: String) throws -> Data {
        let salt = "iOSKeychainExplorer".data(using: .utf8)!
        let keyLength = 32 // AES-256
        let iterations = 10000

        var derivedKey = Data(repeating: 0, count: keyLength)
        let result = derivedKey.withUnsafeMutableBytes { derivedKeyPtr in
            udid.data(using: .utf8)!.withUnsafeBytes { udidPtr in
                salt.withUnsafeBytes { saltPtr in
                    CCKeyDerivationPBKDF(
                        CCPBKDFAlgorithm(kCCPBKDF2),
                        udidPtr.baseAddress, udidPtr.count,
                        saltPtr.baseAddress, saltPtr.count,
                        CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256),
                        UInt32(iterations),
                        derivedKeyPtr.baseAddress, derivedKeyPtr.count
                    )
                }
            }
        }

        guard result == kCCSuccess else {
            throw KeychainExplorerError.encryptionFailed
        }

        return derivedKey
    }
}

// AES256 encryption/decryption helper
struct AES256 {
    private static let algorithm = SecKeyAlgorithm.rsaEncryptionOAEPSHA256AESGCM
    
    static func encrypt(_ data: Data, withKey key: Data) throws -> Data {
        var error: Unmanaged<CFError>?
        guard let encryptedData = SecKeyCreateEncryptedData(key as CFData as! SecKey, algorithm, data as CFData, &error) as Data? else {
            throw error!.takeRetainedValue() as Error
        }
        return encryptedData
    }
    
    static func decrypt(_ data: Data, withKey key: Data) throws -> Data {
        var error: Unmanaged<CFError>?
        guard let decryptedData = SecKeyCreateDecryptedData(key as CFData as! SecKey, algorithm, data as CFData, &error) as Data? else {
            throw error!.takeRetainedValue() as Error
        }
        return decryptedData
    }
}
