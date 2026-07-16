//! Linux backend for [`crate::secrets`], implemented with Secret Service via
//! `libsecret`.
//!
//! This module provides the Linux implementation of the `SecretStoreBackend`
//! trait.
//!
use crate::secrets::{Secret, SecretError, SecretStoreBackend};
use libsecret::*;
use std::{collections::HashMap, sync::OnceLock};

pub(crate) struct Backend;
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

impl SecretStoreBackend for Backend {
    fn add(secret: &Secret) -> Result<(), SecretError> {
        if secret.value().is_empty() {
            return Err(SecretError::EmptyValue);
        }
        if Self::get(secret.name()).is_ok() {
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

    fn get(name: &str) -> Result<Secret, SecretError> {
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

    fn remove(name: &str) -> Result<(), SecretError> {
        Self::get(name)?;
        password_clear_sync(
            Some(get_schema()),
            HashMap::from([("application", name)]),
            gio::Cancellable::NONE,
        )
        .map_err(|e| SecretError::PlatformError(format!("Failed to remove secret: {}", e)))?;
        Ok(())
    }

    fn update(secret: &Secret) -> Result<(), SecretError> {
        if secret.value().is_empty() {
            return Err(SecretError::EmptyValue);
        }
        Self::get(secret.name())?;
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
}
