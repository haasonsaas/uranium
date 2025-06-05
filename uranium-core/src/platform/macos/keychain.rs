use crate::{Result, UraniumError};
use security_framework::passwords::{
    delete_generic_password, get_generic_password, set_generic_password,
};

const SERVICE_NAME: &str = "com.uranium.vault";
const ACCOUNT_PREFIX: &str = "uranium_key_";

/// Store a key in the macOS Keychain
pub fn store_key_in_keychain(key_id: &str, key_data: &[u8]) -> Result<()> {
    let account = format!("{}{}", ACCOUNT_PREFIX, key_id);

    // Delete any existing key first
    let _ = delete_generic_password(SERVICE_NAME, &account);

    // Store the new key
    set_generic_password(SERVICE_NAME, &account, key_data)
        .map_err(|e| UraniumError::Internal(format!("Failed to store key in Keychain: {}", e)))?;

    tracing::info!("Stored key '{}' in macOS Keychain", key_id);
    Ok(())
}

/// Retrieve a key from the macOS Keychain
pub fn get_key_from_keychain(key_id: &str) -> Result<Vec<u8>> {
    let account = format!("{}{}", ACCOUNT_PREFIX, key_id);

    let password = get_generic_password(SERVICE_NAME, &account).map_err(|e| {
        UraniumError::Internal(format!("Failed to retrieve key from Keychain: {}", e))
    })?;

    Ok(password)
}

/// Delete a key from the macOS Keychain
pub fn delete_key_from_keychain(key_id: &str) -> Result<()> {
    let account = format!("{}{}", ACCOUNT_PREFIX, key_id);

    delete_generic_password(SERVICE_NAME, &account).map_err(|e| {
        UraniumError::Internal(format!("Failed to delete key from Keychain: {}", e))
    })?;

    tracing::info!("Deleted key '{}' from macOS Keychain", key_id);
    Ok(())
}

/// Check if a key exists in the Keychain
pub fn key_exists_in_keychain(key_id: &str) -> bool {
    let account = format!("{}{}", ACCOUNT_PREFIX, key_id);
    get_generic_password(SERVICE_NAME, &account).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keychain_operations() {
        let test_key_id = "test_key_123";
        let test_data = b"secret_key_data";

        // Clean up any existing key
        let _ = delete_key_from_keychain(test_key_id);

        // Test storing
        assert!(store_key_in_keychain(test_key_id, test_data).is_ok());

        // Test retrieval
        let retrieved = get_key_from_keychain(test_key_id).unwrap();
        assert_eq!(retrieved, test_data);

        // Test existence check
        assert!(key_exists_in_keychain(test_key_id));

        // Test deletion
        assert!(delete_key_from_keychain(test_key_id).is_ok());
        assert!(!key_exists_in_keychain(test_key_id));
    }
}
