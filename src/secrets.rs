//! Secure storage of secrets (name/value pairs) using the operating
//! system's native credential store.
//!
//! This module selects a platform-specific backend at compile time:
//!
//! - **Windows** — [Windows Credential Manager](https://learn.microsoft.com/en-us/windows/win32/secauthn/credentials-management)
//!   via the `windows` submodule.
//! - **macOS** — [Keychain](https://developer.apple.com/documentation/security/keychain-services)
//!   via the `macos` submodule.
//! - **Linux** — [Secret Service](https://specifications.freedesktop.org/secret-service/latest/)
//!   via the `linux` submodule.
//!
//! Only the backend matching the target OS is compiled in; its public
//! items are re-exported directly from this module, so callers can use
//! e.g. `armoire::secrets::store` (or whatever the backend exposes)
//! without needing to know which platform module it came from.
//!
//! The [`Secret`] type itself is a plain, platform-independent
//! name/value pair used as the common data structure passed to and
//! returned from the backend.
//!
//! # Unsupported platforms
//!
//! No backend is compiled in for targets other than Windows, macOS, and
//! Linux; only [`Secret`] itself is available on those platforms.
//!
//! # Security
//!
//! [`Secret`] derives [`Debug`], which will print `value` in plaintext.
//! Avoid logging `Secret` values directly (e.g. via `{:?}`) in contexts
//! where logs may be persisted or exposed.

use crate::passwords;
use serde::{Deserialize, Serialize};

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "windows")]
mod windows;

#[cfg(target_os = "linux")]
pub use linux::*;
#[cfg(target_os = "macos")]
pub use macos::*;
#[cfg(target_os = "windows")]
pub use windows::*;

/// A named secret value, e.g. an API key or token, to be stored in or
/// retrieved from the platform's native credential store.
///
/// `Secret` is a plain data holder; reading from and writing to the
/// actual OS credential store is handled by the platform-specific
/// backend re-exported at the top of this module (see the module-level
/// docs).
///
/// # Security
///
/// This type derives [`Debug`], which will print `value` in plaintext.
/// Avoid printing, logging, or otherwise persisting `Secret` values
/// outside of their intended use.
///
/// # Examples
///
/// ```
/// use armoire::secrets::Secret;
///
/// let secret = Secret::new("api_key".to_string(), "sk-abc123".to_string());
/// assert_eq!(secret.name(), "api_key");
/// assert_eq!(secret.value(), "sk-abc123");
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Secret {
    name: String,
    value: String,
}

/// Errors that can occur when interacting with the platform secret store.
///
/// This covers failures from adding, retrieving, updating, or removing
/// secrets via the OS-level credential/keychain backend.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecretError {
    /// No secret was found for the given name.
    ///
    /// Returned by operations that require an existing secret, such as
    /// [`get`], [`remove`], or [`update`], when no matching entry
    /// exists in the store.
    NotFound,
    /// A secret with the given name already exists.
    ///
    /// Returned by [`add`] (or similar creation operations) when attempting
    /// to insert a secret under a name that is already in use. Use
    /// [`update`] instead if you intend to overwrite it.
    AlreadyExists,
    /// The secret value is empty.
    ///
    /// Returned by [`add`] or [`update`] when attempting to add/modify
    /// a secret with an empty value.
    EmptyValue,
    /// The underlying platform backend returned an error.
    ///
    /// This wraps a human-readable message describing a failure that
    /// originated from the OS credential store or platform API (e.g.
    /// permission denied, backend unavailable, or an unsupported platform).
    PlatformError(String),
}

impl Secret {
    /// Creates a new `Secret` with the given `name` and `value`.
    ///
    /// This constructs the in-memory representation only; it does not
    /// write to the OS credential store. See the platform-specific
    /// backend functions re-exported from this module for persisting a
    /// `Secret`.
    ///
    /// # Examples
    ///
    /// ```
    /// use armoire::secrets::Secret;
    ///
    /// let secret = Secret::new("api_key".to_string(), "sk-abc123".to_string());
    /// ```
    pub fn new(name: String, value: String) -> Self {
        Secret { name, value }
    }

    /// Returns the secret's name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the secret's value.
    ///
    /// # Security
    ///
    /// The returned string is the plaintext secret value. Callers should
    /// avoid printing, logging, or otherwise persisting the returned
    /// value outside of its intended use.
    pub fn value(&self) -> &str {
        &self.value
    }
}

/// Generates a random 64-character password and stores it in the secure
/// credential store under the given `name`.
///
/// # Errors
/// Returns the same errors as [`add`], most notably
/// [`SecretError::AlreadyExists`] if a secret with this name already exists.
pub fn create_random(name: &str) -> Result<Secret, SecretError> {
    let generator = passwords::Generator::default();
    let secret = Secret::new(name.to_string(), generator.generate(64));
    match add(&secret) {
        Ok(_) => Ok(secret),
        Err(e) => Err(e),
    }
}

/// Updates the secret if it already exists in the secure credential store,
/// or creates it if it doesn't.
///
/// Attempts [`update`] first; if that fails with [`SecretError::NotFound`],
/// falls back to [`add`]. Any other error from `update` is returned as-is.
///
/// # Errors
/// Returns any error from [`update`] or [`add`] other than
/// `SecretError::NotFound` (which triggers the fallback to `add`).
pub fn upsert(secret: &Secret) -> Result<(), SecretError> {
    match update(secret) {
        Ok(_) => Ok(()),
        Err(SecretError::NotFound) => add(secret),
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Cleanup {
        name: String,
    }

    impl Cleanup {
        fn new(name: &str) -> Self {
            let _ = remove(name);
            Cleanup {
                name: name.to_string(),
            }
        }
    }

    impl Drop for Cleanup {
        fn drop(&mut self) {
            let _ = remove(&self.name);
        }
    }

    #[test]
    fn new_object() {
        let _cleanup = Cleanup::new("my_secret");
        let secret = Secret::new("my_secret".to_string(), "my_value".to_string());
        assert_eq!(secret.name(), "my_secret");
        assert_eq!(secret.value(), "my_value");
    }

    #[test]
    fn add_secret() {
        let _cleanup = Cleanup::new("test_secret");
        let secret = Secret::new("test_secret".to_string(), "test_value".to_string());
        let result = add(&secret);
        assert!(result.is_ok());
        let retrieved = get("test_secret").unwrap();
        assert_eq!(retrieved, secret);
    }

    #[test]
    fn add_random_secret() {
        let _cleanup = Cleanup::new("random_secret");
        let secret = create_random("random_secret").unwrap();
        assert_eq!(secret.name(), "random_secret");
        let retrieved = get("random_secret").unwrap();
        assert_eq!(retrieved, secret);
        assert!(retrieved.value().len() == 64);
    }

    #[test]
    fn update_secret() {
        let _cleanup = Cleanup::new("update_secret");
        let secret = Secret::new("update_secret".to_string(), "initial_value".to_string());
        let result = add(&secret);
        assert!(result.is_ok());
        let updated_secret = Secret::new("update_secret".to_string(), "updated_value".to_string());
        let update_result = update(&updated_secret);
        assert!(update_result.is_ok());
        let retrieved = get("update_secret").unwrap();
        assert_eq!(retrieved, updated_secret);
    }

    #[test]
    fn duplicate_secret() {
        let _cleanup = Cleanup::new("duplicate_secret");
        let secret = Secret::new("duplicate_secret".to_string(), "value1".to_string());
        let result1 = add(&secret);
        assert!(result1.is_ok());
        let duplicate_secret = Secret::new("duplicate_secret".to_string(), "value2".to_string());
        let result2 = add(&duplicate_secret);
        assert!(matches!(result2, Err(SecretError::AlreadyExists)));
        let retrieved = get("duplicate_secret").unwrap();
        assert_eq!(retrieved, secret);
    }

    #[test]
    fn remove_nonexistent_secret() {
        let result = remove("nonexistent_secret");
        assert!(matches!(result, Err(SecretError::NotFound)));
    }
}
