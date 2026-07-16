//! Windows backend for [`crate::secrets`], implemented with Credential Vault
//! APIs.
//!
//! This module provides the Windows implementation of the
//! `SecretStoreBackend` trait.
//!
use crate::secrets::{Secret, SecretError, SecretStoreBackend};
use windows::{Security::Credentials::*, core::HSTRING};

pub(crate) struct Backend;

impl SecretStoreBackend for Backend {
    fn add(secret: &Secret) -> Result<(), SecretError> {
        if secret.value().is_empty() {
            return Err(SecretError::EmptyValue);
        }
        if Self::get(secret.name()).is_ok() {
            return Err(SecretError::AlreadyExists);
        }
        let cred = PasswordCredential::CreatePasswordCredential(
            &HSTRING::from(secret.name()),
            &HSTRING::from("default"),
            &HSTRING::from(secret.value()),
        )
        .map_err(|e| SecretError::PlatformError(format!("Failed to create credential: {}", e)))?;
        let vault = PasswordVault::new()
            .map_err(|e| SecretError::PlatformError(format!("Failed to create vault: {}", e)))?;
        vault
            .Add(&cred)
            .map_err(|e| SecretError::PlatformError(format!("Failed to add secret: {}", e)))?;
        Ok(())
    }

    fn get(name: &str) -> Result<Secret, SecretError> {
        let vault = PasswordVault::new()
            .map_err(|e| SecretError::PlatformError(format!("Failed to create vault: {}", e)))?;
        let cred = vault
            .Retrieve(&HSTRING::from(name), &HSTRING::from("default"))
            .map_err(|_| SecretError::NotFound)?;
        Ok(Secret::new(
            name.to_string(),
            cred.Password()
                .map_err(|e| {
                    SecretError::PlatformError(format!("Failed to retrieve password: {}", e))
                })?
                .to_string(),
        ))
    }

    fn remove(name: &str) -> Result<(), SecretError> {
        let vault = PasswordVault::new()
            .map_err(|e| SecretError::PlatformError(format!("Failed to create vault: {}", e)))?;
        let cred = vault
            .Retrieve(&HSTRING::from(name), &HSTRING::from("default"))
            .map_err(|_| SecretError::NotFound)?;
        vault
            .Remove(&cred)
            .map_err(|e| SecretError::PlatformError(format!("Failed to remove secret: {}", e)))?;
        Ok(())
    }

    fn update(secret: &Secret) -> Result<(), SecretError> {
        if secret.value().is_empty() {
            return Err(SecretError::EmptyValue);
        }
        let vault = PasswordVault::new()
            .map_err(|e| SecretError::PlatformError(format!("Failed to create vault: {}", e)))?;
        let cred = vault
            .Retrieve(&HSTRING::from(secret.name()), &HSTRING::from("default"))
            .map_err(|_| SecretError::NotFound)?;
        vault
            .Remove(&cred)
            .map_err(|e| SecretError::PlatformError(format!("Failed to remove secret: {}", e)))?;
        let new_cred = PasswordCredential::CreatePasswordCredential(
            &HSTRING::from(secret.name()),
            &HSTRING::from("default"),
            &HSTRING::from(secret.value()),
        )
        .map_err(|e| SecretError::PlatformError(format!("Failed to create credential: {}", e)))?;
        vault
            .Add(&new_cred)
            .map_err(|e| SecretError::PlatformError(format!("Failed to add secret: {}", e)))?;
        Ok(())
    }
}
