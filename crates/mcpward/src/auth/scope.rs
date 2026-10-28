use std::fmt;

/// An OAuth scope in its two forms.
///
/// Some providers use a different string in the challenge than in the token. Entra challenges
/// with `api://<client-id>/access_as_user` but puts `access_as_user` in `scp`. Policies use the
/// claim form; mcpward writes the challenge form into `WWW-Authenticate` and metadata.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Scope {
    claim: String,
    challenge: String,
}

impl Scope {
    /// A scope that uses the same string in tokens and challenges.
    pub fn new(claim: impl Into<String>) -> Self {
        let claim = claim.into();
        Scope { challenge: claim.clone(), claim }
    }

    /// Sets the form used in challenges and metadata.
    pub fn with_challenge(mut self, full: impl Into<String>) -> Self {
        self.challenge = full.into();
        self
    }

    /// The form found in the token's scope claim.
    pub fn claim(&self) -> &str {
        &self.claim
    }

    /// The form written to `WWW-Authenticate` and `scopes_supported`.
    pub fn challenge(&self) -> &str {
        &self.challenge
    }
}

impl fmt::Debug for Scope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.claim == self.challenge {
            write!(f, "Scope({})", self.claim)
        } else {
            write!(f, "Scope({} as {})", self.claim, self.challenge)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn forms() {
        let s = Scope::new("access_as_user").with_challenge("api://x/access_as_user");
        assert_eq!(s.claim(), "access_as_user");
        assert_eq!(s.challenge(), "api://x/access_as_user");
        assert_eq!(Scope::new("a").challenge(), "a");
    }
}
