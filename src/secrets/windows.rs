use crate::secrets::{Secret, SecretError};

/// Adds a new secret to the system's secure credential store.
///
/// # Errors
/// - [`SecretError::EmptyValue`] if `secret.value()` is an empty string.
/// - [`SecretError::AlreadyExists`] if a secret with the same name already exists.
/// - [`SecretError::PlatformError`] if the underlying platform API call fails.
pub fn add(secret: &Secret) -> Result<(), SecretError> {
    Err(SecretError::PlatformError(
        "Not implemented for Windows".to_string(),
    ))
}

/// Generates a random 64-character password and stores it in the secure
/// credential store under the given `name`.
///
/// # Errors
/// Returns the same errors as [`add`], most notably
/// [`SecretError::AlreadyExists`] if a secret with this name already exists.
pub fn create_random(name: &str) -> Result<Secret, SecretError> {
    Err(SecretError::PlatformError(
        "Not implemented for Windows".to_string(),
    ))
}

/// Retrieves a secret's value from the secure credential store by its name.
///
/// # Errors
/// - [`SecretError::NotFound`] if no matching secret exists.
/// - [`SecretError::PlatformError`] if the underlying platform API call fails
///   or the stored value is not valid UTF-8.
pub fn get(name: &str) -> Result<Secret, SecretError> {
    Err(SecretError::PlatformError(
        "Not implemented for Windows".to_string(),
    ))
}

/// Deletes a secret from the secure credential store by its name.
///
/// # Errors
/// - [`SecretError::NotFound`] if no matching secret exists.
/// - [`SecretError::PlatformError`] if the underlying platform API call fails.
pub fn remove(name: &str) -> Result<(), SecretError> {
    Err(SecretError::PlatformError(
        "Not implemented for Windows".to_string(),
    ))
}

/// Updates the value of an existing secret in the secure credential store.
///
/// This does *not* create a new secret if one doesn't already exist — use
/// [`upsert`] for that behavior.
///
/// # Errors
/// - [`SecretError::EmptyValue`] if `secret.value()` is an empty string.
/// - [`SecretError::NotFound`] if no secret with this name exists.
/// - [`SecretError::PlatformError`] if the underlying platform API call fails.
pub fn update(secret: &Secret) -> Result<(), SecretError> {
    Err(SecretError::PlatformError(
        "Not implemented for Windows".to_string(),
    ))
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
    Err(SecretError::PlatformError(
        "Not implemented for Windows".to_string(),
    ))
}