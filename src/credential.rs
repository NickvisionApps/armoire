//! Storage of a single login credential (site/service name, username,
//! password, and optional URL).
//!
//! The core type is [`Credential`], a plain data holder with getters and
//! chainable setters. For ergonomic construction, use [`Credential::builder`].

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
/// let credential = Credential::builder()
///     .name("Example Site".to_string())
///     .username("alice".to_string())
///     .password("hunter2".to_string())
///     .url("https://example.com".to_string())
///     .build()
///     .expect("all required fields are set");
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

/// Builder for [`Credential`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CredentialBuilder {
    name: Option<String>,
    username: Option<String>,
    password: Option<String>,
    url: Option<String>,
}

/// Errors returned by [`CredentialBuilder::build`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CredentialBuilderError {
    /// `name` was not provided.
    MissingName,
    /// `username` was not provided.
    MissingUsername,
    /// `password` was not provided.
    MissingPassword,
}

impl Credential {
    /// Creates a new `Credential` with the given `name`, `username`,
    /// `password`, and optional `url`.
    ///
    /// Prefer [`Credential::builder`] when constructing credentials at call
    /// sites where named fields read better than positional arguments.
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

    /// Creates a [`CredentialBuilder`] for constructing a `Credential` with
    /// named fields.
    ///
    /// # Examples
    ///
    /// ```
    /// use armoire::Credential;
    ///
    /// let credential = Credential::builder()
    ///     .name("Example Site".to_string())
    ///     .username("alice".to_string())
    ///     .password("hunter2".to_string())
    ///     .build()
    ///     .expect("all required fields are set");
    ///
    /// assert_eq!(credential.name(), "Example Site");
    /// assert_eq!(credential.url(), None);
    /// ```
    pub fn builder() -> CredentialBuilder {
        CredentialBuilder::default()
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

impl CredentialBuilder {
    /// Sets the credential name.
    ///
    /// This field is required.
    pub fn name(mut self, name: String) -> Self {
        self.name = Some(name);
        self
    }

    /// Sets the credential username.
    ///
    /// This field is required.
    pub fn username(mut self, username: String) -> Self {
        self.username = Some(username);
        self
    }

    /// Sets the credential password.
    ///
    /// This field is required.
    pub fn password(mut self, password: String) -> Self {
        self.password = Some(password);
        self
    }

    /// Sets the credential URL.
    ///
    /// This field is optional.
    pub fn url(mut self, url: String) -> Self {
        self.url = Some(url);
        self
    }

    /// Builds a [`Credential`].
    ///
    /// # Errors
    /// Returns [`CredentialBuilderError`] when a required field was omitted.
    pub fn build(self) -> Result<Credential, CredentialBuilderError> {
        let name = self.name.ok_or(CredentialBuilderError::MissingName)?;
        let username = self
            .username
            .ok_or(CredentialBuilderError::MissingUsername)?;
        let password = self
            .password
            .ok_or(CredentialBuilderError::MissingPassword)?;
        Ok(Credential {
            name,
            username,
            password,
            url: self.url,
        })
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

    #[test]
    fn builder_with_optional_url() {
        let credential = Credential::builder()
            .name("My Credential".to_string())
            .username("username".to_string())
            .password("password".to_string())
            .url("https://example.com".to_string())
            .build()
            .unwrap();
        assert_eq!(credential.name(), "My Credential");
        assert_eq!(credential.username(), "username");
        assert_eq!(credential.password(), "password");
        assert_eq!(credential.url(), Some("https://example.com"));
    }

    #[test]
    fn builder_without_optional_url() {
        let credential = Credential::builder()
            .name("My Credential".to_string())
            .username("username".to_string())
            .password("password".to_string())
            .build()
            .unwrap();
        assert_eq!(credential.url(), None);
    }

    #[test]
    fn builder_missing_required_field() {
        let result = Credential::builder()
            .name("My Credential".to_string())
            .password("password".to_string())
            .build();
        assert_eq!(result, Err(CredentialBuilderError::MissingUsername));
    }
}
