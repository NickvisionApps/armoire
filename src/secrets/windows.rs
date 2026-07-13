use crate::secrets::{Secret, SecretError};
use windows::{Security::Credentials::*, core::HSTRING};

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
    if get(secret.name()).is_ok() {
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

/// Retrieves a secret's value from the secure credential store by its name.
///
/// # Errors
/// - [`SecretError::NotFound`] if no matching secret exists.
/// - [`SecretError::PlatformError`] if the underlying platform API call fails
///   or the stored value is not valid UTF-8.
pub fn get(name: &str) -> Result<Secret, SecretError> {
    let vault = PasswordVault::new()
        .map_err(|e| SecretError::PlatformError(format!("Failed to create vault: {}", e)))?;
    let cred = vault
        .Retrieve(&HSTRING::from(name), &HSTRING::from("default"))
        .map_err(|_| SecretError::NotFound)?;
    Ok(Secret::new(
        name.to_string(),
        cred.Password()
            .map_err(|e| SecretError::PlatformError(format!("Failed to retrieve password: {}", e)))?
            .to_string(),
    ))
}

/// Deletes a secret from the secure credential store by its name.
///
/// # Errors
/// - [`SecretError::NotFound`] if no matching secret exists.
/// - [`SecretError::PlatformError`] if the underlying platform API call fails.
pub fn remove(name: &str) -> Result<(), SecretError> {
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
