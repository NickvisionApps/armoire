//! Cross-platform utilities for credentials, password generation, and secure
//! secret storage.
//!
//! # Modules
//!
//! - [`Credential`] and [`CredentialBuilder`] for login records.
//! - [`passwords`] for configurable random password generation.
//! - [`secrets`] for OS-backed secret storage APIs.
//!
//! # Example
//!
//! ```rust
//! use armoire::{
//!     passwords::{Characters, Generator},
//!     secrets::Secret,
//!     Credential,
//! };
//!
//! fn main() {
//!     let credential = Credential::builder()
//!         .name("Example Service".to_string())
//!         .username("alice".to_string())
//!         .password("super-secret-password".to_string())
//!         .url("https://example.com/login".to_string())
//!         .build()
//!         .expect("all required credential fields should be present");
//!
//!     let generator = Generator::new(
//!         Characters::LOWERCASE | Characters::UPPERCASE | Characters::NUMERIC,
//!     );
//!     let generated_password = generator.generate(24);
//!
//!     let api_secret = Secret::new("example_api_key".to_string(), "key-123".to_string());
//!
//!     assert_eq!(credential.name(), "Example Service");
//!     assert_eq!(generated_password.len(), 24);
//!     assert_eq!(api_secret.name(), "example_api_key");
//! }
//! ```
//!
#[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
compile_error!("armoire only supports Windows, macOS, and Linux");

mod credential;
pub mod passwords;
pub mod secrets;

pub use credential::{Credential, CredentialBuilder, CredentialBuilderError};
