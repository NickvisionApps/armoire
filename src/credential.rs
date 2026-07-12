//! Storage of a single login credential (site/service name, username,
//! password, and optional URL).
//!
//! The core type is [`Credential`], a plain data holder with getters and
//! chainable setters.

use serde::{Deserialize, Serialize};

/// A single stored login credential.
///
/// Holds a human-readable `name` for the credential (e.g. the service it
/// belongs to), a `username`, a `password`, and an optional `url` for the
/// associated login page.
///
/// # Security
///
/// `Credential` derives [`Debug`], which will print `password` in
/// plaintext. Avoid logging `Credential` values directly (e.g. via `{:?}`)
/// in contexts where logs may be persisted or exposed.
///
/// # Examples
///
/// ```
/// use armoire::Credential;
///
/// let credential = Credential::new(
///     "Example Site".to_string(),
///     "alice".to_string(),
///     "hunter2".to_string(),
///     Some("https://example.com".to_string()),
/// );
///
/// assert_eq!(credential.name(), "Example Site");
/// assert_eq!(credential.url(), Some("https://example.com"));
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Credential {
    name: String,
    username: String,
    password: String,
    url: Option<String>,
}

impl Credential {
    /// Creates a new `Credential` with the given `name`, `username`,
    /// `password`, and optional `url`.
    ///
    /// # Examples
    ///
    /// ```
    /// use armoire::Credential;
    ///
    /// let credential = Credential::new(
    ///     "Example Site".to_string(),
    ///     "alice".to_string(),
    ///     "hunter2".to_string(),
    ///     None,
    /// );
    /// ```
    pub fn new(name: String, username: String, password: String, url: Option<String>) -> Self {
        Credential {
            name,
            username,
            password,
            url,
        }
    }

    /// Returns the credential's name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Sets the credential's name.
    ///
    /// Returns `&mut Self` to allow chaining multiple setters:
    ///
    /// ```
    /// use armoire::Credential;
    ///
    /// let mut credential = Credential::new(
    ///     "Old Name".to_string(),
    ///     "alice".to_string(),
    ///     "hunter2".to_string(),
    ///     None,
    /// );
    ///
    /// credential.set_name("New Name".to_string()).set_username("bob".to_string());
    ///
    /// assert_eq!(credential.name(), "New Name");
    /// assert_eq!(credential.username(), "bob");
    /// ```
    pub fn set_name(&mut self, name: String) -> &mut Self {
        self.name = name;
        self
    }

    /// Returns the credential's username.
    pub fn username(&self) -> &str {
        &self.username
    }

    /// Sets the credential's username.
    ///
    /// Returns `&mut Self` to allow chaining multiple setters (see
    /// [`Credential::set_name`] for an example).
    pub fn set_username(&mut self, username: String) -> &mut Self {
        self.username = username;
        self
    }

    /// Returns the credential's password.
    ///
    /// # Security
    ///
    /// The returned string is the plaintext password. Callers should avoid
    /// printing, logging, or otherwise persisting the returned value
    /// outside of its intended use.
    pub fn password(&self) -> &str {
        &self.password
    }

    /// Sets the credential's password.
    ///
    /// Returns `&mut Self` to allow chaining multiple setters (see
    /// [`Credential::set_name`] for an example).
    pub fn set_password(&mut self, password: String) -> &mut Self {
        self.password = password;
        self
    }

    /// Returns the credential's associated URL, if one is set.
    pub fn url(&self) -> Option<&str> {
        self.url.as_deref()
    }

    /// Sets (or clears, via `None`) the credential's associated URL.
    ///
    /// Returns `&mut Self` to allow chaining multiple setters (see
    /// [`Credential::set_name`] for an example).
    pub fn set_url(&mut self, url: Option<String>) -> &mut Self {
        self.url = url;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new() {
        let credential = Credential::new(
            "My Credential".to_string(),
            "username".to_string(),
            "password".to_string(),
            Some("https://example.com".to_string()),
        );
        assert_eq!(credential.name(), "My Credential");
        assert_eq!(credential.username(), "username");
        assert_eq!(credential.password(), "password");
        assert_eq!(credential.url(), Some("https://example.com"));
    }
}
