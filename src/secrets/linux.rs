use crate::secrets::{Secret, SecretError};

pub fn add(secret: &Secret) -> Result<(), SecretError> {
    Err(SecretError::PlatformError(
        "Not implemented for Linux".to_string(),
    ))
}

pub fn create_random(name: &str) -> Result<Secret, SecretError> {
    Err(SecretError::PlatformError(
        "Not implemented for Linux".to_string(),
    ))
}

pub fn get(name: &str) -> Result<Secret, SecretError> {
    Err(SecretError::PlatformError(
        "Not implemented for Linux".to_string(),
    ))
}

pub fn remove(name: &str) -> Result<(), SecretError> {
    Err(SecretError::PlatformError(
        "Not implemented for Linux".to_string(),
    ))
}

pub fn update(secret: &Secret) -> Result<(), SecretError> {
    Err(SecretError::PlatformError(
        "Not implemented for Linux".to_string(),
    ))
}
