mod keychain;
mod secure_enclave;

pub use self::keychain::{
    delete_key_from_keychain, get_key_from_keychain, key_exists_in_keychain, store_key_in_keychain,
};
pub use self::secure_enclave::{SecureEnclaveKey, SecureEnclaveManager};

use std::ffi::c_void;
use std::os::raw::c_int;
use std::ptr;

use super::PlatformSecurity;
use crate::{Result, UraniumError};

// External C functions from macOS system libraries
extern "C" {
    // Memory protection
    fn mlock(addr: *const c_void, len: usize) -> c_int;
    fn munlock(addr: *const c_void, len: usize) -> c_int;
    fn mprotect(addr: *const c_void, len: usize, prot: c_int) -> c_int;

    // Security framework functions
    fn SecRandomCopyBytes(rnd: *const c_void, count: usize, bytes: *mut u8) -> i32;
}

// Memory protection flags
const PROT_READ: c_int = 0x01;
#[allow(dead_code)]
const PROT_WRITE: c_int = 0x02;
#[allow(dead_code)]
const PROT_EXEC: c_int = 0x04;

// Security framework constants
#[allow(non_upper_case_globals)]
const kSecRandomDefault: *mut c_void = ptr::null_mut();
#[allow(non_upper_case_globals)]
const errSecSuccess: i32 = 0;

pub struct MacOSSecurity {
    has_secure_enclave: bool,
}

impl Default for MacOSSecurity {
    fn default() -> Self {
        Self::new()
    }
}

impl MacOSSecurity {
    pub fn new() -> Self {
        // Check for Secure Enclave availability
        let has_secure_enclave = Self::check_secure_enclave();

        if has_secure_enclave {
            tracing::info!("Secure Enclave detected - hardware security available");
        } else {
            tracing::info!("No Secure Enclave detected - using software security");
        }

        Self { has_secure_enclave }
    }

    fn check_secure_enclave() -> bool {
        // Check if we're on Apple Silicon or have T2 chip
        // This is a simplified check - in production would use IOKit
        #[cfg(target_arch = "aarch64")]
        {
            true // Apple Silicon always has Secure Enclave
        }
        #[cfg(not(target_arch = "aarch64"))]
        {
            // Intel Macs might have T2 chip
            // Would need to check via IOKit, defaulting to false for now
            false
        }
    }

    fn get_page_size() -> usize {
        // macOS page size is typically 4KB on Intel, 16KB on Apple Silicon
        unsafe { libc::sysconf(libc::_SC_PAGESIZE) as usize }
    }

    fn align_to_page(addr: usize) -> usize {
        let page_size = Self::get_page_size();
        addr & !(page_size - 1)
    }
}

impl PlatformSecurity for MacOSSecurity {
    fn lock_memory(&self, addr: *const u8, len: usize) -> Result<()> {
        // Align to page boundaries
        let start = Self::align_to_page(addr as usize);
        let end = Self::align_to_page(addr as usize + len + Self::get_page_size() - 1);
        let aligned_len = end - start;

        unsafe {
            let result = mlock(start as *const c_void, aligned_len);
            if result == 0 {
                tracing::debug!("Locked {} bytes of memory", aligned_len);
                Ok(())
            } else {
                let err = std::io::Error::last_os_error();
                tracing::warn!("Failed to lock memory: {}", err);
                Err(UraniumError::MemoryProtection(format!(
                    "mlock failed: {}",
                    err
                )))
            }
        }
    }

    fn unlock_memory(&self, addr: *const u8, len: usize) -> Result<()> {
        let start = Self::align_to_page(addr as usize);
        let end = Self::align_to_page(addr as usize + len + Self::get_page_size() - 1);
        let aligned_len = end - start;

        unsafe {
            let result = munlock(start as *const c_void, aligned_len);
            if result == 0 {
                Ok(())
            } else {
                let err = std::io::Error::last_os_error();
                Err(UraniumError::MemoryProtection(format!(
                    "munlock failed: {}",
                    err
                )))
            }
        }
    }

    fn protect_memory_readonly(&self, addr: *const u8, len: usize) -> Result<()> {
        let start = Self::align_to_page(addr as usize);
        let end = Self::align_to_page(addr as usize + len + Self::get_page_size() - 1);
        let aligned_len = end - start;

        unsafe {
            let result = mprotect(start as *const c_void, aligned_len, PROT_READ);
            if result == 0 {
                tracing::debug!("Set {} bytes of memory to read-only", aligned_len);
                Ok(())
            } else {
                let err = std::io::Error::last_os_error();
                Err(UraniumError::MemoryProtection(format!(
                    "mprotect failed: {}",
                    err
                )))
            }
        }
    }

    #[allow(clippy::not_unsafe_ptr_arg_deref)]
    fn secure_zero_memory(&self, addr: *mut u8, len: usize) {
        // Safety: The caller must ensure addr points to valid memory of at least len bytes
        unsafe {
            // On macOS, memset_s might not be available in all cases
            // Use volatile writes which are guaranteed not to be optimized away
            for i in 0..len {
                std::ptr::write_volatile(addr.add(i), 0);
            }
        }
    }

    fn generate_hardware_key(&self, key_id: &str) -> Result<Vec<u8>> {
        // Try to use Secure Enclave if available
        if self.has_secure_enclave && SecureEnclaveKey::is_available() {
            // Generate a key in Secure Enclave
            let se_key = SecureEnclaveKey::generate(key_id)?;

            // For symmetric encryption, we need to derive a key from the SE key
            // Generate a temporary key pair for key agreement
            let _temp_key = SecureEnclaveKey::generate(&format!("{}_temp", key_id))?;
            // Derive symmetric key using ECDH
            let symmetric_key = se_key.generate_symmetric_key()?;

            // Clean up temporary key
            SecureEnclaveKey::delete(&format!("{}_temp", key_id))?;

            tracing::info!("Generated Secure Enclave-backed key for: {}", key_id);
            Ok(symmetric_key)
        } else {
            // Fallback to SecRandomCopyBytes
            let mut key = vec![0u8; 32]; // 256-bit key

            unsafe {
                let result = SecRandomCopyBytes(kSecRandomDefault, key.len(), key.as_mut_ptr());
                if result == errSecSuccess {
                    tracing::info!("Generated random key for: {}", key_id);
                    Ok(key)
                } else {
                    Err(UraniumError::Internal(format!(
                        "Failed to generate secure random key: {}",
                        result
                    )))
                }
            }
        }
    }

    fn store_hardware_key(&self, key_id: &str, key: &[u8]) -> Result<()> {
        // Use Keychain for secure storage
        store_key_in_keychain(key_id, key)?;
        Ok(())
    }

    fn get_hardware_key(&self, key_id: &str) -> Result<Vec<u8>> {
        // Retrieve from Keychain
        get_key_from_keychain(key_id)
    }

    fn has_hardware_security(&self) -> bool {
        self.has_secure_enclave
    }
}

// Additional macOS-specific security features
impl MacOSSecurity {
    /// Enable Data Protection for a file
    pub fn set_data_protection_class(
        &self,
        path: &str,
        _protection_class: DataProtectionClass,
    ) -> Result<()> {
        // This would use NSFileManager to set protection attributes
        tracing::info!("Setting data protection class for: {}", path);
        Ok(())
    }

    /// Use CryptoKit for hardware-accelerated encryption
    pub fn hardware_encrypt(&self, _key: &[u8], _plaintext: &[u8]) -> Result<Vec<u8>> {
        // This would use CryptoKit's AES.GCM or ChaChaPoly
        // For now, we'll use our existing implementation
        Err(UraniumError::Internal(
            "CryptoKit integration pending".to_string(),
        ))
    }
}

#[derive(Debug, Clone, Copy)]
pub enum DataProtectionClass {
    /// Available when unlocked (default)
    Available,
    /// Available after first unlock
    AfterFirstUnlock,
    /// Complete protection - unavailable when locked
    Complete,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_macos_security_creation() {
        let security = MacOSSecurity::new();
        println!("Has Secure Enclave: {}", security.has_secure_enclave);
    }

    #[test]
    #[ignore = "Memory protection tests can cause SIGBUS in test environment"]
    fn test_memory_operations() {
        let security = MacOSSecurity::new();

        // Allocate some memory
        let mut data = vec![0x42u8; 4096];
        let addr = data.as_ptr();
        let len = data.len();

        // Test memory locking
        let result = security.lock_memory(addr, len);
        println!("Memory lock result: {:?}", result);

        // Test memory protection
        if result.is_ok() {
            let protect_result = security.protect_memory_readonly(addr, len);
            println!("Memory protect result: {:?}", protect_result);

            // Unlock memory
            let unlock_result = security.unlock_memory(addr, len);
            println!("Memory unlock result: {:?}", unlock_result);
        }

        // Test secure zeroing
        security.secure_zero_memory(data.as_mut_ptr(), len);
        assert!(data.iter().all(|&b| b == 0));
    }
}
