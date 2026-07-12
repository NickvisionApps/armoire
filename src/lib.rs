#[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
compile_error!("armoire only supports Windows, macOS, and Linux");

mod credential;
pub mod passwords;
pub mod secrets;

pub use credential::Credential;
