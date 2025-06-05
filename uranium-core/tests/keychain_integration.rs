#[cfg(target_os = "macos")]
mod keychain_tests {
    use std::sync::Arc;
    use uranium_core::platform::get_platform_security;

    #[test]
    #[cfg_attr(
        any(target_os = "macos", target_os = "ios"),
        ignore = "Keychain tests hang in CI"
    )]
    fn test_keychain_round_trip() {
        let platform = Arc::new(get_platform_security());
        let test_key_id = "test_integration_key";
        let test_data = b"test_secret_data_32_bytes_long!!";

        // Clean up any existing key
        let _ = platform.get_hardware_key(test_key_id);

        // Store key
        platform
            .store_hardware_key(test_key_id, test_data)
            .expect("Failed to store key in Keychain");

        // Retrieve key
        let retrieved = platform
            .get_hardware_key(test_key_id)
            .expect("Failed to retrieve key from Keychain");

        assert_eq!(retrieved, test_data, "Retrieved key doesn't match");

        // Test persistence with new platform instance
        drop(platform);
        let new_platform = Arc::new(get_platform_security());
        let persistent = new_platform
            .get_hardware_key(test_key_id)
            .expect("Failed to retrieve persistent key");

        assert_eq!(persistent, test_data, "Key not persistent");
    }

    #[test]
    #[cfg_attr(
        any(target_os = "macos", target_os = "ios"),
        ignore = "Keychain tests hang in CI"
    )]
    fn test_keychain_overwrite() {
        let platform = Arc::new(get_platform_security());
        let test_key_id = "test_overwrite_key";
        let original_data = b"original_secret_data_32_bytes!!!";
        let new_data = b"new_secret_data_value_32_bytes!!";

        // Store original
        platform
            .store_hardware_key(test_key_id, original_data)
            .expect("Failed to store original key");

        // Overwrite with new data
        platform
            .store_hardware_key(test_key_id, new_data)
            .expect("Failed to overwrite key");

        // Verify new data
        let retrieved = platform
            .get_hardware_key(test_key_id)
            .expect("Failed to retrieve key");

        assert_eq!(retrieved, new_data, "Key not properly overwritten");
    }

    #[test]
    #[cfg_attr(
        any(target_os = "macos", target_os = "ios"),
        ignore = "Keychain tests hang in CI"
    )]
    fn test_keychain_error_handling() {
        let platform = Arc::new(get_platform_security());
        let non_existent_key = "key_that_does_not_exist";

        // Should return error for non-existent key
        let result = platform.get_hardware_key(non_existent_key);
        assert!(result.is_err(), "Expected error for non-existent key");
    }
}
