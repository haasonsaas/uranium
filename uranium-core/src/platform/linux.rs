use super::PlatformSecurity;
use crate::{Result, UraniumError};

pub struct LinuxSecurity;

impl LinuxSecurity {
    pub fn new() -> Self {
        Self
    }
}

impl PlatformSecurity for LinuxSecurity {
    fn lock_memory(&self, addr: *const u8, len: usize) -> Result<()> {
        #[cfg(target_os = "linux")]
        unsafe {
            use libc::{madvise, mlock, MADV_DONTDUMP};

            // Lock memory
            if mlock(addr as *const libc::c_void, len) != 0 {
                return Err(UraniumError::MemoryProtection("mlock failed".to_string()));
            }

            // Prevent memory from being included in core dumps
            madvise(addr as *mut libc::c_void, len, MADV_DONTDUMP);
        }

        Ok(())
    }

    fn unlock_memory(&self, addr: *const u8, len: usize) -> Result<()> {
        #[cfg(target_os = "linux")]
        unsafe {
            use libc::munlock;
            if munlock(addr as *const libc::c_void, len) != 0 {
                return Err(UraniumError::MemoryProtection("munlock failed".to_string()));
            }
        }
        Ok(())
    }

    fn protect_memory_readonly(&self, addr: *const u8, len: usize) -> Result<()> {
        #[cfg(target_os = "linux")]
        unsafe {
            use libc::{mprotect, PROT_READ};
            if mprotect(addr as *mut libc::c_void, len, PROT_READ) != 0 {
                return Err(UraniumError::MemoryProtection(
                    "mprotect failed".to_string(),
                ));
            }
        }
        Ok(())
    }

    #[allow(clippy::not_unsafe_ptr_arg_deref)]
    fn secure_zero_memory(&self, addr: *mut u8, len: usize) {
        unsafe {
            // Use volatile writes to prevent optimization
            for i in 0..len {
                std::ptr::write_volatile(addr.add(i), 0);
            }
        }
    }

    fn generate_hardware_key(&self, _key_id: &str) -> Result<Vec<u8>> {
        // Linux doesn't have hardware key generation like macOS
        // Use /dev/urandom for secure random
        use std::fs::File;
        use std::io::Read;

        let mut key = vec![0u8; 32];
        let mut file = File::open("/dev/urandom")
            .map_err(|e| UraniumError::Internal(format!("Failed to open /dev/urandom: {}", e)))?;
        file.read_exact(&mut key)
            .map_err(|e| UraniumError::Internal(format!("Failed to read random: {}", e)))?;

        Ok(key)
    }

    fn store_hardware_key(&self, _key_id: &str, _key: &[u8]) -> Result<()> {
        // Linux doesn't have a built-in keychain like macOS
        // In production, you'd use the Linux kernel keyring or libsecret
        Err(UraniumError::Internal(
            "Hardware key storage not implemented on Linux".to_string(),
        ))
    }

    fn get_hardware_key(&self, _key_id: &str) -> Result<Vec<u8>> {
        Err(UraniumError::Internal(
            "Hardware key storage not implemented on Linux".to_string(),
        ))
    }

    fn has_hardware_security(&self) -> bool {
        false
    }
}
