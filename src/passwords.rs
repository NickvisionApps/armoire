//! Random password generation with configurable character classes.
//!
//! The core type is [`Generator`], which is configured with a [`Characters`]
//! bitflag set describing which classes of characters (numeric, lowercase,
//! uppercase, special, space) are eligible for inclusion.
//!
//! # Examples
//!
//! ```
//! use armoire::passwords::{Generator, Characters};
//!
//! let generator = Generator::new(Characters::LOWERCASE | Characters::NUMERIC);
//! let password = generator.generate(16);
//! assert_eq!(password.len(), 16);
//! ```

use bitflags::bitflags;
use rand::RngExt;

bitflags! {
    /// Character classes eligible for inclusion when generating a password.
    ///
    /// Flags can be combined with `|` to allow multiple classes:
    ///
    /// ```
    /// use armoire::passwords::Characters;
    /// let flags = Characters::LOWERCASE | Characters::UPPERCASE;
    /// assert!(flags.contains(Characters::LOWERCASE));
    /// ```
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct Characters: u16 {
        /// Digits `0`–`9`.
        const NUMERIC    = 0b0000_0001;
        /// Lowercase ASCII letters `a`–`z`.
        const LOWERCASE  = 0b0000_0010;
        /// Uppercase ASCII letters `A`–`Z`.
        const UPPERCASE  = 0b0000_0100;
        /// Punctuation and symbol characters, e.g. `!@#$%^&*()`.
        const SPECIAL    = 0b0000_1000;
        /// The space character.
        const SPACE      = 0b0001_0000;

    }
}

/// Generates random strings from a configurable set of [`Characters`] classes.
///
/// Each generated character is chosen by first selecting an enabled class
/// uniformly at random, then a character uniformly at random from within
/// that class — so classes are weighted equally regardless of how many
/// characters they contain (e.g. `SPACE`, with one character, is chosen as
/// often as `LOWERCASE`, with twenty-six).
///
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Generator {
    characters: Characters,
}

impl Generator {
    /// Creates a generator configured to draw from `characters`.
    ///
    /// # Examples
    ///
    /// ```
    /// use armoire::passwords::{Generator, Characters};
    /// let generator = Generator::new(Characters::NUMERIC);
    /// ```
    pub fn new(characters: Characters) -> Self {
        Self { characters }
    }

    /// Returns the character classes this generator draws from.
    pub fn characters(&self) -> Characters {
        self.characters
    }

    /// Replaces the character classes this generator draws from.
    pub fn set_characters(&mut self, characters: Characters) {
        self.characters = characters;
    }

    /// Generates a random string of the given `length`.
    ///
    /// Each character is drawn from the classes enabled on this generator,
    /// with each *class* (not each character) equally likely to be chosen.
    ///
    /// Returns an empty string when no character classes are enabled.
    ///
    /// # Examples
    ///
    /// ```
    /// use armoire::passwords::{Generator, Characters};
    /// let generator = Generator::new(Characters::LOWERCASE);
    /// let pw = generator.generate(10);
    /// assert_eq!(pw.len(), 10);
    /// ```
    pub fn generate(&self, length: usize) -> String {
        static NUMERIC: &[u8] = b"0123456789";
        static LOWERCASE: &[u8] = b"abcdefghijklmnopqrstuvwxyz";
        static UPPERCASE: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        static SPECIAL: &[u8] = b"!@#$%^&*()-_=+[]{}|;:',.<>?/`~";
        static SPACE: &[u8] = b" ";
        if self.characters.is_empty() {
            return String::new();
        }
        let mut rng = rand::rng();
        let mut charset = Vec::with_capacity(length);
        for _ in 0..length {
            loop {
                let c = match rng.random_range(0..5) {
                    0 if self.characters.contains(Characters::NUMERIC) => {
                        NUMERIC[rng.random_range(0..NUMERIC.len())] as char
                    }
                    1 if self.characters.contains(Characters::LOWERCASE) => {
                        LOWERCASE[rng.random_range(0..LOWERCASE.len())] as char
                    }
                    2 if self.characters.contains(Characters::UPPERCASE) => {
                        UPPERCASE[rng.random_range(0..UPPERCASE.len())] as char
                    }
                    3 if self.characters.contains(Characters::SPECIAL) => {
                        SPECIAL[rng.random_range(0..SPECIAL.len())] as char
                    }
                    4 if self.characters.contains(Characters::SPACE) => {
                        SPACE[rng.random_range(0..SPACE.len())] as char
                    }
                    _ => continue,
                };
                charset.push(c);
                break;
            }
        }
        charset.into_iter().collect()
    }
}

impl Default for Generator {
    /// Creates a generator configured to draw from all character classes.
    ///
    /// # Examples
    ///
    /// ```
    /// use armoire::passwords::Generator;
    /// let generator = Generator::default();
    /// ```
    fn default() -> Self {
        Self {
            characters: Characters::NUMERIC
                | Characters::LOWERCASE
                | Characters::UPPERCASE
                | Characters::SPECIAL
                | Characters::SPACE,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn length_0() {
        let generator = Generator::new(Characters::NUMERIC | Characters::LOWERCASE);
        assert_eq!(generator.generate(0), "");
    }

    #[test]
    fn length_10() {
        let generator = Generator::new(Characters::NUMERIC | Characters::LOWERCASE);
        let password = generator.generate(10);
        assert_eq!(password.len(), 10);
    }

    #[test]
    fn length_100() {
        let generator = Generator::new(Characters::NUMERIC | Characters::LOWERCASE);
        let password = generator.generate(100);
        assert_eq!(password.len(), 100);
    }

    #[test]
    fn no_characters() {
        let generator = Generator::new(Characters::empty());
        assert_eq!(generator.generate(16), "");
    }

    #[test]
    fn numeric_only() {
        let generator = Generator::new(Characters::NUMERIC);
        let password = generator.generate(16);
        assert_eq!(password.len(), 16);
        assert!(password.chars().all(|c| c.is_ascii_digit()));
    }

    #[test]
    fn lowercase_only() {
        let generator = Generator::new(Characters::LOWERCASE);
        let password = generator.generate(16);
        assert_eq!(password.len(), 16);
        assert!(password.chars().all(|c| c.is_ascii_lowercase()));
    }

    #[test]
    fn uppercase_only() {
        let generator = Generator::new(Characters::UPPERCASE);
        let password = generator.generate(16);
        assert_eq!(password.len(), 16);
        assert!(password.chars().all(|c| c.is_ascii_uppercase()));
    }

    #[test]
    fn special_only() {
        let generator = Generator::new(Characters::SPECIAL);
        let password = generator.generate(16);
        assert_eq!(password.len(), 16);
        assert!(
            password
                .chars()
                .all(|c| "!@#$%^&*()-_=+[]{}|;:',.<>?/`~".contains(c))
        );
    }

    #[test]
    fn space_only() {
        let generator = Generator::new(Characters::SPACE);
        let password = generator.generate(16);
        assert_eq!(password.len(), 16);
        assert!(password.chars().all(|c| c == ' '));
    }

    #[test]
    fn upper_and_lower_only() {
        let generator = Generator::new(Characters::UPPERCASE | Characters::LOWERCASE);
        let password = generator.generate(16);
        assert_eq!(password.len(), 16);
        assert!(password.chars().all(|c| c.is_ascii_alphabetic()));
    }

    #[test]
    fn alphanumeric_only() {
        let generator =
            Generator::new(Characters::NUMERIC | Characters::LOWERCASE | Characters::UPPERCASE);
        let password = generator.generate(16);
        assert_eq!(password.len(), 16);
        assert!(password.chars().all(|c| c.is_ascii_alphanumeric()));
    }

    #[test]
    fn all_characters() {
        let generator = Generator::default();
        let password = generator.generate(16);
        assert_eq!(password.len(), 16);
        assert!(
            password
                .chars()
                .all(|c| c.is_ascii() || "!@#$%^&*()-_=+[]{}|;:',.<>?/`~ ".contains(c))
        );
    }
}
