//! Linux backend for [`crate::secrets`], implemented with Secret Service via
//! `libsecret`.
//!
//! This module provides the platform-specific implementations of
//! [`add`], [`get`], [`remove`], and [`update`].
//!
use crate::secrets::{Secret, SecretError};
use libsecret::*;
use std::{collections::HashMap, sync::OnceLock};

struct SchemaHandle(Schema);
unsafe impl Sync for SchemaHandle {}
unsafe impl Send for SchemaHandle {}

fn get_schema() -> &'static Schema {
    static SCHEMA: OnceLock<SchemaHandle> = OnceLock::new();
    &SCHEMA
        .get_or_init(|| {
            SchemaHandle(Schema::new(
                "armoire",
                SchemaFlags::DONT_MATCH_NAME,
                HashMap::from([
                    ("application", SchemaAttributeType::String),
                    ("NULL", SchemaAttributeType::String),
                ]),
            ))
        })
        .0
}

/// Stores a new secret in the system credential store.
///
/// # Errors
/// - [`SecretError::EmptyValue`] if `secret.value()` is an empty string.
/// - [`SecretError::AlreadyExists`] if a secret with the same name already exists.
/// - [`SecretError::PlatformError`] if the underlying platform API call fails.
pub fn add(secret: &Secret) -> Result<(), SecretError> {
    if secret.value().is_empty() {
        return Err(SecretError::EmptyValue);
    }
    if get(secret.name()).is_ok() {
        return Err(SecretError::AlreadyExists);
    }
    password_store_sync(
        Some(get_schema()),
        HashMap::from([("application", secret.name())]),
        Some(&COLLECTION_DEFAULT),
        secret.name(),
        secret.value(),
        gio::Cancellable::NONE,
    )
    .map_err(|e| SecretError::PlatformError(format!("Failed to add secret: {}", e)))?;
    Ok(())
}

/// Retrieves a secret from the system credential store by name.
///
/// # Errors
/// - [`SecretError::NotFound`] if no matching secret exists.
/// - [`SecretError::PlatformError`] if the underlying platform API call fails
///   or the stored value is not valid UTF-8.
pub fn get(name: &str) -> Result<Secret, SecretError> {
    let password = password_lookup_sync(
        Some(get_schema()),
        HashMap::from([("application", name)]),
        gio::Cancellable::NONE,
    )
    .map_err(|e| SecretError::PlatformError(format!("Failed to get secret: {}", e)))?;
    if password.is_none() {
        return Err(SecretError::NotFound);
    }
    Ok(Secret::new(name.to_string(), password.unwrap().to_string()))
}

/// Removes a secret from the system credential store by name.
///
/// # Errors
/// - [`SecretError::NotFound`] if no matching secret exists.
/// - [`SecretError::PlatformError`] if the underlying platform API call fails.
pub fn remove(name: &str) -> Result<(), SecretError> {
    get(name)?;
    password_clear_sync(
        Some(get_schema()),
        HashMap::from([("application", name)]),
        gio::Cancellable::NONE,
    )
    .map_err(|e| SecretError::PlatformError(format!("Failed to remove secret: {}", e)))?;
    Ok(())
}

/// Updates an existing secret in the system credential store.
///
/// This does *not* create a new secret if one doesn't already exist — use
/// [`crate::secrets::upsert`] for that behavior.
///
/// # Errors
/// - [`SecretError::EmptyValue`] if `secret.value()` is an empty string.
/// - [`SecretError::NotFound`] if no secret with this name exists.
/// - [`SecretError::PlatformError`] if the underlying platform API call fails.
pub fn update(secret: &Secret) -> Result<(), SecretError> {
    if secret.value().is_empty() {
        return Err(SecretError::EmptyValue);
    }
    get(secret.name())?;
    password_store_sync(
        Some(get_schema()),
        HashMap::from([("application", secret.name())]),
        Some(&COLLECTION_DEFAULT),
        secret.name(),
        secret.value(),
        gio::Cancellable::NONE,
    )
    .map_err(|e| SecretError::PlatformError(format!("Failed to update secret: {}", e)))?;
    Ok(())
}
