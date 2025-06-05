use super::PlatformSecurity;
use crate::{Result, UraniumError};

pub struct WindowsSecurity;

impl WindowsSecurity {
    pub fn new() -> Self {
        Self
    }
}

impl PlatformSecurity for WindowsSecurity {
    fn lock_memory(&self, _addr: *const u8, _len: usize) -> Result<()> {
        // Windows uses VirtualLock
        // For now, we'll stub this out
        Ok(())
    }

    fn unlock_memory(&self, _addr: *const u8, _len: usize) -> Result<()> {
        // Windows uses VirtualUnlock
        Ok(())
    }

    fn protect_memory_readonly(&self, _addr: *const u8, _len: usize) -> Result<()> {
        // Windows uses VirtualProtect
        Ok(())
    }

    #[allow(clippy::not_unsafe_ptr_arg_deref)]
    fn secure_zero_memory(&self, addr: *mut u8, len: usize) {
        unsafe {
            // Windows has SecureZeroMemory, but we'll use volatile writes for portability
            for i in 0..len {
                std::ptr::write_volatile(addr.add(i), 0);
            }
        }
    }

    fn generate_hardware_key(&self, _key_id: &str) -> Result<Vec<u8>> {
        // Use CryptGenRandom or BCryptGenRandom on Windows
        // For now, use rand crate
        use rand::RngCore;
        let mut key = vec![0u8; 32];
        rand::thread_rng().fill_bytes(&mut key);
        Ok(key)
    }

    fn store_hardware_key(&self, _key_id: &str, _key: &[u8]) -> Result<()> {
        // Windows has Credential Manager / DPAPI
        // For now, return error
        Err(UraniumError::Internal(
            "Hardware key storage not implemented on Windows".to_string(),
        ))
    }

    fn get_hardware_key(&self, _key_id: &str) -> Result<Vec<u8>> {
        Err(UraniumError::Internal(
            "Hardware key storage not implemented on Windows".to_string(),
        ))
    }

    fn has_hardware_security(&self) -> bool {
        false
    }
}
