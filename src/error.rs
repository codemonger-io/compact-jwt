//! Error types.

use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Debug, Serialize, Clone, Deserialize, PartialEq)]
/// An error in the JWT library
pub enum JwtError {
    /// Invalid Token - May not be in correct compact form
    InvalidCompactFormat,
    /// Invalid Base64 encodidng of the token content
    InvalidBase64,
    /// Invalid token header
    InvalidHeaderFormat,
    /// Invalid signature over the header and payload
    InvalidSignature,
    /// Invalid JWT content
    InvalidJwt,
    /// Invalid certificate
    InvalidCertificate,
    /// Invalid public/private key
    InvalidKey,
    /// Invalid parameter
    InvalidParameter,
    /// Invalid Critical Extension present
    CriticalExtension,
    /// Incorrect Algorithm for verification
    ValidatorAlgMismatch,
    /// The Token has expired
    OidcTokenExpired,
    /// No embeded JWK is available
    EmbededJwkNotAvailable,
    /// Jwk public key export denied
    JwkPublicKeyDenied,
    /// Private key export denied
    PrivateKeyDenied,
    /// Any signer error
    SignerError,
}

impl fmt::Display for JwtError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl std::error::Error for JwtError {}
