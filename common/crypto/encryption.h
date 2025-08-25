#pragma once

#include <string>
#include <vector>
#include <memory>
#include <chrono>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

namespace botnet {
namespace crypto {

/**
 * @brief AES-256-GCM encryption handler
 * 
 * Cross-platform implementation using OpenSSL for maximum compatibility.
 * No platform-specific code - works identically on Windows, Linux, macOS.
 */
class AESEncryption {
public:
    static constexpr size_t KEY_SIZE = 32;      // 256 bits
    static constexpr size_t IV_SIZE = 12;       // 96 bits for GCM
    static constexpr size_t TAG_SIZE = 16;      // 128 bits

    struct EncryptedData {
        std::vector<uint8_t> ciphertext;
        std::vector<uint8_t> iv;
        std::vector<uint8_t> tag;
        std::string key_id;
        std::chrono::system_clock::time_point timestamp;
        
        // Serialization for network transmission
        std::vector<uint8_t> Serialize() const;
        static EncryptedData Deserialize(const std::vector<uint8_t>& data);
    };

public:
    explicit AESEncryption(const std::vector<uint8_t>& key);
    ~AESEncryption();

    // Core encryption/decryption
    EncryptedData Encrypt(const std::string& plaintext, 
                         const std::string& additional_data = "") const;
    EncryptedData Encrypt(const std::vector<uint8_t>& plaintext, 
                         const std::string& additional_data = "") const;
    
    std::string DecryptToString(const EncryptedData& encrypted_data, 
                               const std::string& additional_data = "") const;
    std::vector<uint8_t> DecryptToBytes(const EncryptedData& encrypted_data, 
                                       const std::string& additional_data = "") const;

    // Key management
    static std::vector<uint8_t> GenerateKey();
    static std::vector<uint8_t> DeriveKey(const std::string& password, 
                                         const std::vector<uint8_t>& salt, 
                                         uint32_t iterations = 100000);
    
    void SetKeyId(const std::string& key_id);
    std::string GetKeyId() const;

    // Research mode utilities
    void EnableResearchLogging(bool enabled);
    std::vector<std::string> GetEncryptionLog() const;

private:
    std::vector<uint8_t> key_;
    std::string key_id_;
    mutable std::vector<std::string> research_log_;
    bool research_logging_enabled_;

    void LogResearchActivity(const std::string& activity) const;
};

/**
 * @brief RSA encryption and digital signatures
 * 
 * Cross-platform RSA implementation for authentication and key exchange.
 */
class RSAKeyPair {
public:
    static constexpr int KEY_SIZE = 4096;

public:
    RSAKeyPair();
    explicit RSAKeyPair(const std::string& private_key_pem, 
                       const std::string& public_key_pem);
    ~RSAKeyPair();

    // Key generation and loading
    static std::unique_ptr<RSAKeyPair> Generate();
    static std::unique_ptr<RSAKeyPair> LoadFromPEM(const std::string& private_key_pem);
    static std::unique_ptr<RSAKeyPair> LoadPublicFromPEM(const std::string& public_key_pem);

    // Key export
    std::string GetPrivateKeyPEM() const;
    std::string GetPublicKeyPEM() const;
    std::string GetPublicKeyFingerprint() const;

    // Encryption/Decryption (for small data like session keys)
    std::vector<uint8_t> Encrypt(const std::vector<uint8_t>& plaintext) const;
    std::vector<uint8_t> Decrypt(const std::vector<uint8_t>& ciphertext) const;

    // Digital signatures
    std::vector<uint8_t> Sign(const std::vector<uint8_t>& data) const;
    std::vector<uint8_t> Sign(const std::string& data) const;
    bool Verify(const std::vector<uint8_t>& data, 
               const std::vector<uint8_t>& signature) const;
    bool Verify(const std::string& data, 
               const std::vector<uint8_t>& signature) const;

    // Key properties
    bool HasPrivateKey() const;
    size_t GetKeySize() const;

private:
    EVP_PKEY* key_pair_;
    EVP_PKEY_CTX* sign_ctx_;
    EVP_PKEY_CTX* verify_ctx_;

    void InitializeContexts();
    void CleanupContexts();
};

/**
 * @brief Certificate handling for PKI authentication
 */
class X509Certificate {
public:
    X509Certificate(const std::string& cert_pem);
    ~X509Certificate();

    // Certificate properties
    std::string GetSubject() const;
    std::string GetIssuer() const;
    std::string GetSerialNumber() const;
    std::chrono::system_clock::time_point GetNotBefore() const;
    std::chrono::system_clock::time_point GetNotAfter() const;
    std::string GetFingerprint() const;

    // Validation
    bool IsValid() const;
    bool IsValidAt(const std::chrono::system_clock::time_point& time) const;
    bool VerifySignature(const RSAKeyPair& ca_key) const;

    // Export
    std::string ToPEM() const;
    std::vector<uint8_t> ToDER() const;

    // Public key extraction
    std::unique_ptr<RSAKeyPair> GetPublicKey() const;

private:
    X509* cert_;
};

/**
 * @brief Hash utilities
 */
class HashUtils {
public:
    // SHA-256 hashing
    static std::vector<uint8_t> SHA256(const std::vector<uint8_t>& data);
    static std::vector<uint8_t> SHA256(const std::string& data);
    static std::string SHA256Hex(const std::string& data);

    // HMAC
    static std::vector<uint8_t> HMAC_SHA256(const std::vector<uint8_t>& key, 
                                           const std::vector<uint8_t>& data);
    static std::vector<uint8_t> HMAC_SHA256(const std::string& key, 
                                           const std::string& data);

    // Password hashing (for configuration files)
    static std::string HashPassword(const std::string& password, 
                                   const std::string& salt);
    static bool VerifyPassword(const std::string& password, 
                              const std::string& hash, 
                              const std::string& salt);
};

/**
 * @brief Secure random number generation
 */
class SecureRandom {
public:
    // Cross-platform secure random using OpenSSL
    static std::vector<uint8_t> GenerateBytes(size_t count);
    static uint32_t GenerateUint32();
    static uint64_t GenerateUint64();
    static std::string GenerateHex(size_t byte_count);
    static std::string GenerateBase64(size_t byte_count);

    // Specific random data types
    static std::vector<uint8_t> GenerateAESKey();
    static std::vector<uint8_t> GenerateIV();
    static std::string GenerateSessionId();
    static std::string GenerateNonce();

private:
    static void EnsureInitialized();
    static bool initialized_;
};

/**
 * @brief Key management and rotation
 */
class KeyManager {
public:
    struct KeyInfo {
        std::string key_id;
        std::vector<uint8_t> key_data;
        std::chrono::system_clock::time_point created_at;
        std::chrono::system_clock::time_point expires_at;
        bool is_active;
    };

public:
    KeyManager();
    ~KeyManager();

    // Key lifecycle
    std::string GenerateNewKey(std::chrono::hours validity_period = std::chrono::hours(24));
    bool RotateKeys();
    bool RevokeKey(const std::string& key_id);
    
    // Key access
    std::vector<uint8_t> GetKey(const std::string& key_id) const;
    std::vector<uint8_t> GetCurrentKey() const;
    std::string GetCurrentKeyId() const;
    
    // Key validation
    bool IsKeyValid(const std::string& key_id) const;
    bool IsKeyExpired(const std::string& key_id) const;
    
    // Key storage (encrypted on disk)
    bool SaveKeysToFile(const std::string& file_path, const std::string& password);
    bool LoadKeysFromFile(const std::string& file_path, const std::string& password);
    
    // Research mode
    void EnableResearchMode();
    std::vector<KeyInfo> GetKeyHistory() const;

private:
    std::map<std::string, KeyInfo> keys_;
    std::string current_key_id_;
    bool research_mode_;
    
    void CleanupExpiredKeys();
    std::string GenerateKeyId() const;
};

/**
 * @brief Utility functions for encoding/decoding
 */
class EncodingUtils {
public:
    // Base64 encoding/decoding
    static std::string Base64Encode(const std::vector<uint8_t>& data);
    static std::string Base64Encode(const std::string& data);
    static std::vector<uint8_t> Base64Decode(const std::string& encoded);
    
    // Hex encoding/decoding
    static std::string HexEncode(const std::vector<uint8_t>& data);
    static std::vector<uint8_t> HexDecode(const std::string& hex);
    
    // URL encoding for HTTP requests
    static std::string URLEncode(const std::string& data);
    static std::string URLDecode(const std::string& encoded);
};

/**
 * @brief Memory security utilities
 */
class SecureMemory {
public:
    // Secure memory allocation and deallocation
    template<typename T>
    class SecureAllocator {
    public:
        using value_type = T;
        
        T* allocate(size_t n);
        void deallocate(T* ptr, size_t n);
        
        template<typename U>
        bool operator==(const SecureAllocator<U>& other) const noexcept {
            return true;
        }
    };
    
    // Secure string that zeros memory on destruction
    using SecureString = std::basic_string<char, std::char_traits<char>, 
                                          SecureAllocator<char>>;
    
    // Secure vector that zeros memory on destruction
    template<typename T>
    using SecureVector = std::vector<T, SecureAllocator<T>>;
    
    // Memory wiping
    static void SecureZero(void* ptr, size_t size);
    static void SecureZero(std::string& str);
    static void SecureZero(std::vector<uint8_t>& vec);
};

} // namespace crypto
} // namespace botnet
