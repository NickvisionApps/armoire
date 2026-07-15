//! Armoire is a small library for managing credentials, generating
//! passwords, and working with secure OS-backed secrets.
//!
//! It provides:
//! - [`Credential`] for username/password login records
//! - [`passwords`] for configurable password generation
//! - [`secrets`] for secure secret storage abstractions
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
//!     let credential = Credential::new(
//!         "Example Service".to_string(),
//!         "alice".to_string(),
//!         "super-secret-password".to_string(),
//!         Some("https://example.com/login".to_string()),
//!     );
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

pub use credential::Credential;
