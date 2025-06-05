#[cfg(target_os = "macos")]
pub mod macos;

#[cfg(target_os = "linux")]
pub mod linux;

#[cfg(target_os = "windows")]
pub mod windows;

// Re-export macOS Secure Enclave functionality
#[cfg(target_os = "macos")]
pub use macos::{SecureEnclaveKey, SecureEnclaveManager};

use crate::Result;

/// Platform-specific security features
pub trait PlatformSecurity: Send + Sync {
    /// Lock memory pages to prevent swapping to disk
    fn lock_memory(&self, addr: *const u8, len: usize) -> Result<()>;

    /// Unlock memory pages
    fn unlock_memory(&self, addr: *const u8, len: usize) -> Result<()>;

    /// Make memory read-only
    fn protect_memory_readonly(&self, addr: *const u8, len: usize) -> Result<()>;

    /// Securely clear memory
    ///
    /// # Safety
    /// The caller must ensure that `addr` points to valid memory of at least `len` bytes
    #[allow(clippy::not_unsafe_ptr_arg_deref)]
    fn secure_zero_memory(&self, addr: *mut u8, len: usize);

    /// Generate hardware-backed encryption key
    fn generate_hardware_key(&self, key_id: &str) -> Result<Vec<u8>>;

    /// Store key in hardware-backed storage
    fn store_hardware_key(&self, key_id: &str, key: &[u8]) -> Result<()>;

    /// Retrieve key from hardware-backed storage
    fn get_hardware_key(&self, key_id: &str) -> Result<Vec<u8>>;

    /// Check if hardware security is available
    fn has_hardware_security(&self) -> bool;
}

/// Get platform-specific security implementation
pub fn get_platform_security() -> Box<dyn PlatformSecurity> {
    #[cfg(target_os = "macos")]
    {
        Box::new(macos::MacOSSecurity::new())
    }

    #[cfg(target_os = "linux")]
    {
        Box::new(linux::LinuxSecurity::new())
    }

    #[cfg(target_os = "windows")]
    {
        Box::new(windows::WindowsSecurity::new())
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        Box::new(GenericSecurity::new())
    }
}

/// Generic implementation for unsupported platforms
#[allow(dead_code)]
struct GenericSecurity;

impl GenericSecurity {
    #[allow(dead_code)]
    fn new() -> Self {
        Self
    }
}

impl PlatformSecurity for GenericSecurity {
    fn lock_memory(&self, _addr: *const u8, _len: usize) -> Result<()> {
        // No-op on unsupported platforms
        Ok(())
    }

    fn unlock_memory(&self, _addr: *const u8, _len: usize) -> Result<()> {
        Ok(())
    }

    fn protect_memory_readonly(&self, _addr: *const u8, _len: usize) -> Result<()> {
        Ok(())
    }

    #[allow(clippy::not_unsafe_ptr_arg_deref)]
    fn secure_zero_memory(&self, addr: *mut u8, len: usize) {
        unsafe {
            std::ptr::write_bytes(addr, 0, len);
        }
    }

    fn generate_hardware_key(&self, _key_id: &str) -> Result<Vec<u8>> {
        Err(crate::UraniumError::Internal(
            "Hardware security not available".to_string(),
        ))
    }

    fn store_hardware_key(&self, _key_id: &str, _key: &[u8]) -> Result<()> {
        Err(crate::UraniumError::Internal(
            "Hardware security not available".to_string(),
        ))
    }

    fn get_hardware_key(&self, _key_id: &str) -> Result<Vec<u8>> {
        Err(crate::UraniumError::Internal(
            "Hardware security not available".to_string(),
        ))
    }

    fn has_hardware_security(&self) -> bool {
        false
    }
}
