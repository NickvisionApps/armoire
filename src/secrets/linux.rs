use crate::secrets::{Secret, SecretError};
use libsecret::*;
use std::collections::HashMap;

fn get_schema() -> Schema {
    Schema::new(
        "armoire",
        SchemaFlags::DONT_MATCH_NAME,
        HashMap::from([("application", SchemaAttributeType::String)]),
    )
}

/// Adds a new secret to the system's secure credential store.
///
/// # Errors
/// - [`SecretError::EmptyValue`] if `secret.value()` is an empty string.
/// - [`SecretError::AlreadyExists`] if a secret with the same name already exists.
/// - [`SecretError::PlatformError`] if the underlying platform API call fails.
pub fn add(secret: &Secret) -> Result<(), SecretError> {
    if secret.value().is_empty() {
        return Err(SecretError::EmptyValue);
    }
    password_store_sync(
        Some(&get_schema()),
        HashMap::from([("application", secret.name())]),
        Some(&COLLECTION_DEFAULT),
        secret.name(),
        secret.value(),
        gio::Cancellable::NONE,
    )
    .map_err(|e| SecretError::PlatformError(format!("Failed to add secret: {}", e)))?;
    Ok(())
}

/// Retrieves a secret's value from the secure credential store by its name.
///
/// # Errors
/// - [`SecretError::NotFound`] if no matching secret exists.
/// - [`SecretError::PlatformError`] if the underlying platform API call fails
///   or the stored value is not valid UTF-8.
pub fn get(name: &str) -> Result<Secret, SecretError> {
    Err(SecretError::PlatformError(
        "Not implemented for Linux".to_string(),
    ))
}

/// Deletes a secret from the secure credential store by its name.
///
/// # Errors
/// - [`SecretError::NotFound`] if no matching secret exists.
/// - [`SecretError::PlatformError`] if the underlying platform API call fails.
pub fn remove(name: &str) -> Result<(), SecretError> {
    Err(SecretError::PlatformError(
        "Not implemented for Linux".to_string(),
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
        "Not implemented for Linux".to_string(),
    ))
}
