//! JWS Cryptographic Operations

#[cfg(feature = "secure")]
use std::convert::TryFrom;

#[cfg(feature = "secure")]
use ::rsa::{
    pkcs1v15::{
        Signature as RsaSignature, SigningKey as RsaSigningKey, VerifyingKey as RsaVerifyingKey,
    },
    signature::{Keypair, SignatureEncoding},
    traits::PublicKeyParts,
    BigUint, RsaPublicKey,
};
#[cfg(feature = "secure")]
use const_oid::db::rfc5912::{ECDSA_WITH_SHA_256, SHA_256_WITH_RSA_ENCRYPTION};
#[cfg(feature = "secure")]
use hmac::{Hmac, Mac as _};
#[cfg(all(test, feature = "secure"))]
use p256::NonZeroScalar;
#[cfg(feature = "secure")]
use p256::{
    ecdsa::{
        signature::{DigestSigner, DigestVerifier},
        Signature as P256Signature, SigningKey as P256SigningKey, VerifyingKey as P256VerifyingKey,
    },
    pkcs8::{DecodePrivateKey, EncodePrivateKey},
    EncodedPoint,
};
#[cfg(feature = "secure")]
use rand_core::{OsRng, RngCore as _};
use serde::{Deserialize, Serialize};
#[cfg(feature = "secure")]
use sha2::{Digest as _, Sha256};
use std::fmt;
use std::str::FromStr;
use url::Url;
#[cfg(feature = "secure")]
use x509_cert::{
    certificate::Certificate,
    der::{referenced::OwnedToRef as _, Decode as _},
};

use crate::error::JwtError;
use base64urlsafedata::Base64UrlSafeData;

#[cfg(feature = "secure")]
const RSA_MIN_SIZE: usize = 3072;
#[cfg(feature = "secure")]
const RSA_SIG_SIZE: usize = 384;

// https://datatracker.ietf.org/doc/html/rfc7515

#[derive(Debug, Serialize, Clone, Deserialize)]
/// A set of jwk keys
pub struct JwkKeySet {
    /// The set of jwks
    pub keys: Vec<Jwk>,
}

#[derive(Debug, Serialize, Clone, Deserialize, PartialEq)]
#[allow(non_camel_case_types)]
/// Valid Eliptic Curves
pub enum EcCurve {
    #[serde(rename = "P-256")]
    /// Nist P-256
    P256,
}

#[derive(Debug, Serialize, Clone, Deserialize, PartialEq)]
#[allow(non_camel_case_types)]
#[serde(tag = "kty")]
/// A JWK formatted public key that can be used to validate a signature
pub enum Jwk {
    /// An Eliptic Curve Public Key
    EC {
        /// The Eliptic Curve in use
        crv: EcCurve,
        /// The public X component
        x: Base64UrlSafeData,
        /// The public Y component
        y: Base64UrlSafeData,
        // We don't decode d (private key) because that way we error defending from
        // the fact that ... well you leaked your private key.
        // d: Base64UrlSafeData
        /// The algorithm in use for this key
        #[serde(skip_serializing_if = "Option::is_none")]
        alg: Option<JwaAlg>,
        #[serde(rename = "use", skip_serializing_if = "Option::is_none")]
        /// The usage of this key
        use_: Option<JwkUse>,
        #[serde(skip_serializing_if = "Option::is_none")]
        /// The key id
        kid: Option<String>,
    },
    /// Legacy RSA public key
    RSA {
        /// Public n value
        n: Base64UrlSafeData,
        /// Public exponent
        e: Base64UrlSafeData,
        /// The algorithm in use for this key
        #[serde(skip_serializing_if = "Option::is_none")]
        alg: Option<JwaAlg>,
        #[serde(rename = "use", skip_serializing_if = "Option::is_none")]
        /// The usage of this key
        use_: Option<JwkUse>,
        #[serde(skip_serializing_if = "Option::is_none")]
        /// The key id
        kid: Option<String>,
    },
}

#[derive(Debug, Serialize, Clone, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
/// What this key is used for
pub enum JwkUse {
    /// This key is for signing.
    Sig,
    /// This key is for encryption
    Enc,
}

#[derive(Debug, Serialize, Copy, Clone, Deserialize, PartialEq)]
#[allow(non_camel_case_types)]
/// Cryptographic algorithm
pub enum JwaAlg {
    /// ECDSA with P-256 and SHA256
    ES256,
    /// RSASSA-PKCS1-v1_5 with SHA-256
    RS256,
    /// HMAC SHA256
    HS256,
}

/// A private key and associated information that can sign Oidc and Jwt data.
#[derive(Clone)]
#[cfg(feature = "secure")]
pub enum JwsSigner {
    /// Eliptic Curve P-256
    ES256 {
        /// The KID of this signer. This is the sha256 digest of the key.
        kid: String,
        /// Private Key
        skey: P256SigningKey,
    },
    /// RSASSA-PKCS1-v1_5 with SHA-256
    RS256 {
        /// The KID of this signer. This is the sha256 digest of the key.
        kid: String,
        /// Private Key
        skey: RsaSigningKey<Sha256>,
    },
    /// HMAC SHA256
    HS256 {
        /// The KID of this signer. This is the sha256 digest of the key.
        kid: String,
        /// Private Key
        skey: Vec<u8>,
    },
}

#[cfg(feature = "secure")]
impl std::cmp::PartialEq for JwsSigner {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (JwsSigner::ES256 { kid: kid_a, .. }, JwsSigner::ES256 { kid: kid_b, .. }) => {
                kid_a.eq(kid_b)
            }
            (JwsSigner::RS256 { kid: kid_a, .. }, JwsSigner::RS256 { kid: kid_b, .. }) => {
                kid_a.eq(kid_b)
            }
            (JwsSigner::HS256 { kid: kid_a, .. }, JwsSigner::HS256 { kid: kid_b, .. }) => {
                kid_a.eq(kid_b)
            }
            _ => false,
        }
    }
}

#[cfg(feature = "secure")]
impl std::cmp::Eq for JwsSigner {}

#[cfg(feature = "secure")]
impl std::hash::Hash for JwsSigner {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        match self {
            JwsSigner::ES256 { kid, .. }
            | JwsSigner::RS256 { kid, .. }
            | JwsSigner::HS256 { kid, .. } => {
                kid.hash(state);
            }
        }
    }
}

#[cfg(feature = "secure")]
impl fmt::Debug for JwsSigner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            JwsSigner::ES256 { kid, .. } => f
                .debug_struct("JwsSigner::ES256")
                .field("kid", kid)
                .finish(),
            JwsSigner::RS256 { kid, .. } => f
                .debug_struct("JwsSigner::RS256")
                .field("kid", kid)
                .finish(),
            JwsSigner::HS256 { kid, .. } => f
                .debug_struct("JwsSigner::HS256")
                .field("kid", kid)
                .finish(),
        }
    }
}

/// A public key with associated information that can validate the signatures of Oidc and Jwt data.
#[derive(Clone)]
#[cfg(feature = "secure")]
pub enum JwsValidator {
    /// Eliptic Curve P-256
    ES256 {
        /// The KID of this validator
        kid: Option<String>,
        /// Public Key
        pkey: P256VerifyingKey,
    },
    /// RSASSA-PKCS1-v1_5 with SHA-256
    RS256 {
        /// The KID of this validator
        kid: Option<String>,
        /// Public Key
        pkey: RsaVerifyingKey<Sha256>,
    },
    /// HMAC SHA256
    HS256 {
        /// The KID of this validator
        kid: Option<String>,
        /// Private Key (Yes, this is correct)
        skey: Vec<u8>,
    },
}

#[cfg(feature = "secure")]
impl fmt::Debug for JwsValidator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("JwsValidator").finish()
    }
}

#[cfg(feature = "secure")]
impl JwsValidator {
    /// Get the KID of this validator if present
    pub fn get_jwk_kid(&self) -> Option<&str> {
        match self {
            JwsValidator::ES256 { kid, .. } => kid.as_deref(),
            JwsValidator::RS256 { kid, .. } => kid.as_deref(),
            JwsValidator::HS256 { kid, .. } => kid.as_deref(),
        }
    }
}

#[derive(Debug, Serialize, Clone, Deserialize)]
struct ProtectedHeader {
    alg: JwaAlg,
    #[serde(skip_serializing_if = "Option::is_none")]
    jku: Option<Url>,
    // https://datatracker.ietf.org/doc/html/rfc7517
    #[serde(skip_serializing_if = "Option::is_none")]
    jwk: Option<Jwk>,
    #[serde(skip_serializing_if = "Option::is_none")]
    kid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    crit: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    typ: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    cty: Option<String>,

    #[serde(skip_deserializing, skip_serializing_if = "Option::is_none")]
    x5u: Option<()>,
    #[serde(skip_serializing_if = "Option::is_none")]
    x5c: Option<Vec<String>>,
    #[serde(skip_deserializing, skip_serializing_if = "Option::is_none")]
    x5t: Option<()>,
    #[serde(
        skip_deserializing,
        rename = "x5t#S256",
        skip_serializing_if = "Option::is_none"
    )]
    x5t_s256: Option<()>,
    // Don't allow extra header names?
}

#[derive(Clone)]
pub(crate) struct JwsCompact {
    header: ProtectedHeader,
    payload: Vec<u8>,
    signature: Vec<u8>,
    #[cfg(feature = "secure")]
    sign_input: Vec<u8>,
}

impl fmt::Debug for JwsCompact {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("JwsCompact")
            .field("header", &self.header)
            .field("payload", &self.payload.len())
            .finish()
    }
}

#[derive(Debug, Clone)]
struct Header {
    #[allow(dead_code)]
    kid: Option<String>,
    #[allow(dead_code)]
    typ: Option<String>,
    #[allow(dead_code)]
    cty: Option<String>,
}

impl From<&ProtectedHeader> for Header {
    fn from(phdr: &ProtectedHeader) -> Self {
        Header {
            kid: phdr.kid.clone(),
            typ: phdr.typ.clone(),
            cty: phdr.cty.clone(),
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct JwsInner {
    #[allow(dead_code)]
    header: Header,
    #[allow(dead_code)]
    payload: Vec<u8>,
}

#[cfg(feature = "secure")]
impl JwsInner {
    pub fn new(payload: Vec<u8>) -> Self {
        JwsInner {
            header: Header {
                kid: None,
                typ: None,
                cty: None,
            },
            payload,
        }
    }

    pub fn set_kid(mut self, kid: String) -> Self {
        self.header.kid = Some(kid);
        self
    }

    pub fn set_typ(mut self, typ: String) -> Self {
        self.header.typ = Some(typ);
        self
    }

    #[allow(dead_code)]
    pub fn set_cty(mut self, cty: String) -> Self {
        self.header.cty = Some(cty);
        self
    }
}

#[cfg(feature = "secure")]
impl JwsInner {
    #[cfg(test)]
    pub fn sign_embed_public_jwk(&self, signer: &JwsSigner) -> Result<JwsCompact, JwtError> {
        let jwk = signer.public_key_as_jwk()?;
        self.sign_inner(signer, None, Some(jwk))
    }

    #[cfg(test)]
    pub fn sign(&self, signer: &JwsSigner) -> Result<JwsCompact, JwtError> {
        self.sign_inner(signer, None, None)
    }

    pub(crate) fn sign_inner(
        &self,
        signer: &JwsSigner,
        jku: Option<Url>,
        jwk: Option<Jwk>,
    ) -> Result<JwsCompact, JwtError> {
        let alg = match signer {
            JwsSigner::ES256 { .. } => JwaAlg::ES256,
            JwsSigner::RS256 { .. } => JwaAlg::RS256,
            JwsSigner::HS256 { .. } => JwaAlg::HS256,
        };

        let header = ProtectedHeader {
            alg,
            jku,
            jwk,
            kid: self.header.kid.clone(),
            typ: self.header.typ.clone(),
            cty: self.header.cty.clone(),
            crit: None,
            x5u: None,
            x5c: None,
            x5t: None,
            x5t_s256: None,
        };

        let payload = self.payload.clone();

        let hdr_b64 = serde_json::to_vec(&header)
            .map_err(|e| {
                debug!(?e);
                JwtError::InvalidHeaderFormat
            })
            .map(|bytes| base64::encode_config(&bytes, base64::URL_SAFE_NO_PAD))?;
        let payload_b64 = base64::encode_config(&self.payload, base64::URL_SAFE_NO_PAD);

        // trace!("sinput -> {}", format!("{}.{}", hdr_b64, payload_b64));

        let sign_input = format!("{}.{}", hdr_b64, payload_b64).as_bytes().to_vec();

        // trace!("sinput -> {:?}", sign_input);

        // Compute the signature!
        let signature = match signer {
            JwsSigner::ES256 { kid: _, skey } => {
                let mut hashout = Sha256::new();
                hashout.update(&sign_input);

                let ec_sig: P256Signature = skey.try_sign_digest(hashout).map_err(|e| {
                    debug!(?e, "ES256 signing");
                    JwtError::SignerError
                })?;
                ec_sig.to_vec()
            }
            JwsSigner::RS256 { kid: _, skey } => {
                let mut hashout = Sha256::new();
                hashout.update(&sign_input);

                let signature = skey.try_sign_digest(hashout).map_err(|e| {
                    debug!(?e, "RS256 signing");
                    JwtError::SignerError
                })?;
                signature.to_vec()
            }
            JwsSigner::HS256 { kid: _, skey } => {
                let mut hmac = Hmac::<Sha256>::new_from_slice(skey.as_slice()).map_err(|e| {
                    debug!(?e, "HMAC signing");
                    JwtError::InvalidKey
                })?;
                hmac.update(&sign_input);
                hmac.finalize().into_bytes().to_vec()
            }
        };

        Ok(JwsCompact {
            header,
            payload,
            sign_input,
            signature,
        })
    }
}

#[cfg(any(feature = "secure", feature = "unsafe_release_without_verify"))]
impl JwsInner {
    pub(crate) fn payload(&self) -> &[u8] {
        &self.payload
    }
}

#[cfg(feature = "secure")]
impl JwsCompact {
    #[cfg(test)]
    fn check_vectors(&self, chk_input: &[u8], chk_sig: &[u8]) -> bool {
        chk_input == &self.sign_input && chk_sig == &self.signature
    }

    pub fn get_x5c_pubkey(&self) -> Result<Option<Certificate>, JwtError> {
        let fullchain = match &self.header.x5c {
            Some(chain) => chain,
            None => return Ok(None),
        };

        fullchain
            .get(0)
            .map(|value| {
                base64::decode(value)
                    .map_err(|_| JwtError::InvalidBase64)
                    .and_then(|bytes| {
                        Certificate::from_der(&bytes).map_err(|e| {
                            debug!(?e, "x5c public key");
                            JwtError::InvalidCertificate
                        })
                    })
            })
            .transpose()
    }

    /// return [Ok(None)] if the jws object's header's x5c field isn't populated
    pub fn get_x5c_chain(&self) -> Result<Option<Vec<Certificate>>, JwtError> {
        let fullchain = match &self.header.x5c {
            Some(chain) => chain,
            None => return Ok(None),
        };

        let fullchain: Result<Vec<_>, _> = fullchain
            .iter()
            .map(|value| {
                base64::decode(value)
                    .map_err(|_| JwtError::InvalidBase64)
                    .and_then(|bytes| {
                        Certificate::from_der(&bytes).map_err(|e| {
                            debug!(?e, "x5c chain");
                            JwtError::InvalidCertificate
                        })
                    })
            })
            .collect();

        let fullchain = fullchain?;

        Ok(Some(fullchain))
    }

    pub(crate) fn validate(&self, validator: &JwsValidator) -> Result<JwsInner, JwtError> {
        match (validator, &self.header.alg) {
            (JwsValidator::ES256 { kid: _, pkey }, JwaAlg::ES256) => {
                if self.signature.len() != 64 {
                    return Err(JwtError::InvalidSignature);
                }

                let sig = P256Signature::from_slice(&self.signature).map_err(|e| {
                    debug!(?e, "ES256 verifying");
                    JwtError::InvalidSignature
                })?;

                let mut hashout = Sha256::new();
                hashout.update(&self.sign_input);

                match pkey.verify_digest(hashout, &sig) {
                    Ok(()) => Ok(JwsInner {
                        header: (&self.header).into(),
                        payload: self.payload.clone(),
                    }),
                    Err(e) => {
                        debug!(?e, "ES256 verifying");
                        Err(JwtError::InvalidSignature)
                    }
                }
            }
            (JwsValidator::RS256 { kid: _, pkey }, JwaAlg::RS256) => {
                if self.signature.len() < 256 {
                    debug!("invalid signature length");
                    return Err(JwtError::InvalidSignature);
                }

                let sig = RsaSignature::try_from(self.signature.as_ref()).map_err(|e| {
                    debug!(?e, "RS256 verifying");
                    JwtError::InvalidSignature
                })?;

                let mut hashout = Sha256::new();
                hashout.update(&self.sign_input);

                match pkey.verify_digest(hashout, &sig) {
                    Ok(()) => Ok(JwsInner {
                        header: (&self.header).into(),
                        payload: self.payload.clone(),
                    }),
                    Err(e) => {
                        debug!(?e, "RS256 verifying");
                        Err(JwtError::InvalidSignature)
                    }
                }
            }
            (JwsValidator::HS256 { kid: _, skey }, JwaAlg::HS256) => {
                let mut hmac = Hmac::<Sha256>::new_from_slice(skey.as_slice()).map_err(|e| {
                    debug!(?e, "HMAC verifying");
                    JwtError::InvalidKey
                })?;
                hmac.update(&self.sign_input);

                match hmac.verify_slice(&self.signature) {
                    Ok(()) => Ok(JwsInner {
                        header: (&self.header).into(),
                        payload: self.payload.clone(),
                    }),
                    Err(e) => {
                        debug!(?e, "HMAC verifying");
                        Err(JwtError::InvalidSignature)
                    }
                }
            }
            alg_request => {
                debug!(?alg_request, "validator algorithm mismatch");
                Err(JwtError::ValidatorAlgMismatch)
            }
        }
    }
}

impl JwsCompact {
    pub fn get_jwk_kid(&self) -> Option<&str> {
        self.header.kid.as_deref()
    }

    #[allow(dead_code)]
    pub fn get_jwk_pubkey_url(&self) -> Option<&Url> {
        self.header.jku.as_ref()
    }

    #[allow(dead_code)]
    pub fn get_jwk_pubkey(&self) -> Option<&Jwk> {
        self.header.jwk.as_ref()
    }

    #[cfg(feature = "unsafe_release_without_verify")]
    pub(crate) fn release_without_verification(&self) -> Result<JwsInner, JwtError> {
        warn!("UNSAFE RELEASE OF JWT WAS PERFORMED");
        Ok(JwsInner {
            header: (&self.header).into(),
            payload: self.payload.clone(),
        })
    }
}

impl FromStr for JwsCompact {
    type Err = JwtError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // split on the ".".
        let mut siter = s.splitn(3, '.');

        let hdr_str = siter.next().ok_or_else(|| {
            debug!("invalid compact format - protected header not present");
            JwtError::InvalidCompactFormat
        })?;

        let header: ProtectedHeader = base64::decode_config(hdr_str, base64::URL_SAFE_NO_PAD)
            .map_err(|_| JwtError::InvalidBase64)
            .and_then(|bytes| {
                serde_json::from_slice(&bytes).map_err(|e| {
                    debug!(?e, "invalid header format - invalid json");
                    JwtError::InvalidHeaderFormat
                })
            })?;

        // Assert that from the critical field of the header, we have decoded all the needed types.
        // Remember, anything in rfc7515 can NOT be in the crit field.
        if let Some(crit) = &header.crit {
            if !crit.is_empty() {
                error!("critical extension - unable to process critical extensions");
                return Err(JwtError::CriticalExtension);
            }
        }

        // Now we have a header, lets get the rest.
        let payload_str = siter.next().ok_or_else(|| {
            debug!("invalid compact format - payload not present");
            JwtError::InvalidCompactFormat
        })?;

        let sig_str = siter.next().ok_or_else(|| {
            debug!("invalid compact format - signature not present");
            JwtError::InvalidCompactFormat
        })?;

        if siter.next().is_some() {
            // Too much data.
            debug!("invalid compact format - extra fields present");
            return Err(JwtError::InvalidCompactFormat);
        }

        let payload =
            base64::decode_config(payload_str, base64::URL_SAFE_NO_PAD).map_err(|_| {
                debug!("invalid base64");
                JwtError::InvalidBase64
            })?;

        let signature = base64::decode_config(sig_str, base64::URL_SAFE_NO_PAD).map_err(|_| {
            debug!("invalid base64");
            JwtError::InvalidBase64
        })?;

        #[cfg(feature = "secure")]
        let sign_input = {
            let (data_input, _) = s.rsplit_once(".").ok_or_else(|| {
                debug!("invalid compact format - unable to parse sign input");
                JwtError::InvalidCompactFormat
            })?;
            debug_assert!(data_input == &format!("{}.{}", hdr_str, payload_str));
            data_input.as_bytes().to_vec()
        };

        Ok(JwsCompact {
            header,
            payload,
            signature,
            #[cfg(feature = "secure")]
            sign_input,
        })
    }
}

impl fmt::Display for JwsCompact {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let hdr = serde_json::to_vec(&self.header)
            .map_err(|e| {
                debug!(?e, "unable to serialise to json");
                fmt::Error
            })
            .map(|bytes| base64::encode_config(&bytes, base64::URL_SAFE_NO_PAD))?;
        let payload = base64::encode_config(&self.payload, base64::URL_SAFE_NO_PAD);
        let sig = base64::encode_config(&self.signature, base64::URL_SAFE_NO_PAD);
        write!(f, "{}.{}.{}", hdr, payload, sig)
    }
}

#[cfg(feature = "secure")]
impl TryFrom<&Jwk> for JwsValidator {
    type Error = JwtError;

    fn try_from(value: &Jwk) -> Result<Self, Self::Error> {
        match value {
            Jwk::EC {
                crv,
                x,
                y,
                alg: _,
                use_: _,
                kid,
            } => {
                let encoded_point = EncodedPoint::from_affine_coordinates(
                    x.as_ref().into(),
                    y.as_ref().into(),
                    false,
                );
                let pkey = P256VerifyingKey::from_encoded_point(&encoded_point).map_err(|e| {
                    debug!(?e, "ES256 private key from encoded point");
                    JwtError::InvalidKey
                })?;

                let kid = kid.clone();

                Ok(match crv {
                    EcCurve::P256 => JwsValidator::ES256 { kid, pkey },
                })
            }
            Jwk::RSA {
                n,
                e,
                alg: _,
                use_: _,
                kid,
            } => {
                let nbn = BigUint::from_bytes_be(n.as_ref());
                let ebn = BigUint::from_bytes_be(e.as_ref());
                let pkey = RsaPublicKey::new(nbn, ebn).map_err(|e| {
                    debug!(?e, "RS256 private key from components");
                    JwtError::InvalidKey
                })?;
                let pkey = RsaVerifyingKey::<Sha256>::new(pkey);

                let kid = kid.clone();

                Ok(JwsValidator::RS256 { kid, pkey })
            }
        }
    }
}

#[cfg(feature = "secure")]
impl TryFrom<Certificate> for JwsValidator {
    type Error = JwtError;

    fn try_from(value: Certificate) -> Result<Self, Self::Error> {
        let public_key_info = value.tbs_certificate.subject_public_key_info.owned_to_ref();
        let validator = match &value.signature_algorithm.oid {
            &ECDSA_WITH_SHA_256 => {
                let pkey = P256VerifyingKey::try_from(public_key_info).map_err(|e| {
                    debug!(?e, "ES256 public key");
                    JwtError::InvalidKey
                })?;
                JwsValidator::ES256 { kid: None, pkey }
            }
            &SHA_256_WITH_RSA_ENCRYPTION => {
                let pkey = RsaVerifyingKey::<Sha256>::try_from(public_key_info).map_err(|e| {
                    debug!(?e, "RS256 public key");
                    JwtError::InvalidKey
                })?;
                JwsValidator::RS256 { kid: None, pkey }
            }
            _ => {
                debug!(
                    "unsupported signature algorithm: {:?}",
                    value.signature_algorithm.oid,
                );
                return Err(JwtError::InvalidKey);
            }
        };
        Ok(validator)
    }
}

#[cfg(feature = "secure")]
impl JwsSigner {
    #[cfg(test)]
    pub fn from_es256_jwk_components(x: &str, y: &str, d: &str) -> Result<Self, JwtError> {
        let x = base64::decode_config(x, base64::URL_SAFE_NO_PAD).map_err(|e| {
            debug!(?e);
            JwtError::InvalidBase64
        })?;
        let y = base64::decode_config(y, base64::URL_SAFE_NO_PAD).map_err(|e| {
            debug!(?e);
            JwtError::InvalidBase64
        })?;

        let d = base64::decode_config(&d, base64::URL_SAFE_NO_PAD).map_err(|e| {
            debug!(?e);
            JwtError::InvalidBase64
        })?;

        let d = NonZeroScalar::try_from(d.as_slice()).unwrap();
        let skey = P256SigningKey::from(d);

        // verifies the public key
        let pkey = skey.verifying_key();
        let encoded_point = pkey.to_encoded_point(false);
        assert_eq!(encoded_point.x().unwrap().as_slice(), x.as_slice());
        assert_eq!(encoded_point.y().unwrap().as_slice(), y.as_slice());

        let kid = skey
            .to_pkcs8_der()
            .map_err(|e| {
                debug!(?e, "ES256 private key from secret number");
                JwtError::InvalidKey
            })
            .map(|der| {
                let mut hashout = Sha256::new();
                hashout.update(der.as_bytes());
                let hashout = hashout.finalize();
                hex::encode(hashout.as_slice())
            })?;

        Ok(JwsSigner::ES256 { kid, skey })
    }

    #[cfg(test)]
    pub fn from_hs256_raw(buf: &[u8]) -> Result<Self, JwtError> {
        if buf.len() < 32 {
            return Err(JwtError::InvalidParameter);
        }

        let mut hashout = Sha256::new();
        hashout.update(buf);
        let kid = hashout.finalize().to_vec();
        let kid = hex::encode(kid);

        if let Err(e) = Hmac::<Sha256>::new_from_slice(buf) {
            debug!(?e, "HMAC generating");
            return Err(JwtError::InvalidKey);
        }
        let mut skey = Vec::with_capacity(buf.len());
        skey.extend_from_slice(&buf);

        Ok(JwsSigner::HS256 { kid, skey })
    }

    /// Retrieve the Jwa alg that is in use
    pub fn get_jwa_alg(&self) -> JwaAlg {
        match self {
            JwsSigner::ES256 { .. } => JwaAlg::ES256,
            JwsSigner::RS256 { .. } => JwaAlg::RS256,
            JwsSigner::HS256 { .. } => JwaAlg::HS256,
        }
    }

    /// Given this signer, retrieve the matching validator which can be paired with this.
    pub fn get_validator(&self) -> Result<JwsValidator, JwtError> {
        match self {
            JwsSigner::ES256 { kid, skey } => Ok(JwsValidator::ES256 {
                kid: Some(kid.clone()),
                pkey: skey.verifying_key().clone(),
            }),
            JwsSigner::RS256 { kid, skey } => Ok(JwsValidator::RS256 {
                kid: Some(kid.clone()),
                pkey: skey.verifying_key(),
            }),
            JwsSigner::HS256 { kid, skey } => Ok(JwsValidator::HS256 {
                kid: Some(kid.clone()),
                skey: skey.clone(),
            }),
        }
    }

    /// Restore this JwsSigner from a DER private key.
    pub fn from_es256_der(der: &[u8]) -> Result<Self, JwtError> {
        let mut hashout = Sha256::new();
        hashout.update(der);
        let kid = hashout.finalize().to_vec();
        let kid = hex::encode(kid);

        let skey = P256SigningKey::from_pkcs8_der(der).map_err(|e| {
            debug!(?e, "ES256 private key DER decoding");
            JwtError::InvalidKey
        })?;

        Ok(JwsSigner::ES256 { kid, skey })
    }

    /// Restore this JwsSigner from a DER private key.
    pub fn from_rs256_der(der: &[u8]) -> Result<Self, JwtError> {
        let mut hashout = Sha256::new();
        hashout.update(der);
        let kid = hashout.finalize().to_vec();
        let kid = hex::encode(kid);

        let skey = RsaSigningKey::<Sha256>::from_pkcs8_der(der).map_err(|e| {
            debug!(?e, "RS256 private key");
            JwtError::InvalidKey
        })?;

        Ok(JwsSigner::RS256 { kid, skey })
    }

    /*
    pub fn public_key_to_der(&self) -> Result<Vec<u8>, JwtError> {
        unimplemented!();
    }
    */

    /// Access the KID of this signer. This is useful for identifying the key used to create a
    /// signature, so that you can locate the correct signer/validator from a signed JWS/JWT
    pub fn get_kid(&self) -> &str {
        match self {
            JwsSigner::ES256 { kid, .. } => &kid,
            JwsSigner::RS256 { kid, .. } => &kid,
            JwsSigner::HS256 { kid, .. } => &kid,
        }
    }

    /// Export this JwsSigner to a DER private key.
    pub fn private_key_to_der(&self) -> Result<Vec<u8>, JwtError> {
        match self {
            JwsSigner::ES256 { kid: _, skey } => skey
                .to_pkcs8_der()
                .map_err(|e| {
                    debug!(?e, "ES256 private key DER encoding");
                    JwtError::InvalidKey
                })
                .map(|d| {
                    let d = d.as_bytes();
                    let mut der: Vec<u8> = Vec::with_capacity(d.len());
                    der.extend_from_slice(d);
                    der
                }),
            JwsSigner::RS256 { kid: _, skey } => skey
                .to_pkcs8_der()
                .map_err(|e| {
                    debug!(?e, "RS256 private key DER encoding");
                    JwtError::InvalidKey
                })
                .map(|d| {
                    let d = d.as_bytes();
                    let mut der: Vec<u8> = Vec::with_capacity(d.len());
                    der.extend_from_slice(d);
                    der
                }),
            JwsSigner::HS256 { kid: _, skey: _ } => {
                debug!("unable to release hs256 private key");
                Err(JwtError::PrivateKeyDenied)
            }
        }
    }

    /// Create a new secure private key for signing
    pub fn generate_es256() -> Result<Self, JwtError> {
        let skey = P256SigningKey::random(&mut OsRng);

        let kid = skey
            .to_pkcs8_der()
            .map_err(|e| {
                debug!(?e, "ES256 private key generating");
                JwtError::InvalidKey
            })
            .map(|d| {
                let mut hashout = Sha256::new();
                hashout.update(d.as_bytes());
                hex::encode(hashout.finalize().as_slice())
            })?;

        Ok(JwsSigner::ES256 { kid, skey })
    }

    /// Create a new secure private key for signing
    pub fn generate_hs256() -> Result<Self, JwtError> {
        let mut skey = vec![0u8; 32];
        OsRng.fill_bytes(&mut skey);

        // Can it become a pkey?
        if let Err(e) = Hmac::<Sha256>::new_from_slice(&skey) {
            debug!(?e, "HMAC signer generating");
            return Err(JwtError::InvalidKey);
        }

        let mut kid = [0u8; 32];
        OsRng.fill_bytes(&mut kid);
        let mut hashout = Sha256::new();
        hashout.update(&kid);
        let kid = hashout.finalize().to_vec();
        let kid = hex::encode(kid);

        Ok(JwsSigner::HS256 { kid, skey })
    }

    /// Create a new legacy (RSA) private key for signing
    pub fn generate_legacy_rs256() -> Result<Self, JwtError> {
        let skey = RsaSigningKey::<Sha256>::random(&mut OsRng, RSA_MIN_SIZE).map_err(|e| {
            debug!(?e, "RSA private key generating");
            JwtError::InvalidKey
        })?;

        let kid = skey
            .to_pkcs8_der()
            .map_err(|e| {
                debug!(?e, "RSA private key generating");
                JwtError::InvalidKey
            })
            .map(|der| {
                let mut hashout = Sha256::new();
                hashout.update(der.as_bytes());
                let hashout = hashout.finalize().to_vec();
                hex::encode(hashout)
            })?;

        Ok(JwsSigner::RS256 { kid, skey })
    }

    /// Export the public key of this signer as a Jwk
    pub fn public_key_as_jwk(&self) -> Result<Jwk, JwtError> {
        match self {
            JwsSigner::ES256 { kid, skey } => {
                let pkey = skey.verifying_key();
                let encoded_point = pkey.to_encoded_point(false);

                let public_key_x = encoded_point.x().ok_or(JwtError::InvalidKey)?.to_vec();
                let public_key_y = encoded_point.y().ok_or(JwtError::InvalidKey)?.to_vec();

                Ok(Jwk::EC {
                    crv: EcCurve::P256,
                    x: Base64UrlSafeData(public_key_x),
                    y: Base64UrlSafeData(public_key_y),
                    alg: Some(JwaAlg::ES256),
                    use_: Some(JwkUse::Sig),
                    kid: Some(kid.clone()),
                })
            }
            JwsSigner::RS256 { kid, skey } => {
                let pkey = skey.verifying_key();
                let pkey = pkey.as_ref();
                let n = pkey.n().to_bytes_be();
                let e = pkey.e().to_bytes_be();
                let mut padded_n = vec![0u8; RSA_SIG_SIZE];
                let mut padded_e = vec![0u8; 3];
                let (_left_n, right_n) = padded_n.split_at_mut(RSA_SIG_SIZE - n.len());
                let (_left_e, right_e) = padded_e.split_at_mut(3 - e.len());
                right_n.copy_from_slice(&n);
                right_e.copy_from_slice(&e);

                Ok(Jwk::RSA {
                    n: Base64UrlSafeData(padded_n),
                    e: Base64UrlSafeData(padded_e),
                    alg: Some(JwaAlg::RS256),
                    use_: Some(JwkUse::Sig),
                    kid: Some(kid.clone()),
                })
            }
            JwsSigner::HS256 { kid: _, skey: _ } => Err(JwtError::JwkPublicKeyDenied),
        }
    }
}

#[cfg(all(feature = "secure", test))]
mod tests {
    use super::{Certificate, Jwk, JwsCompact, JwsInner, JwsSigner, JwsValidator};
    use std::convert::TryFrom;
    use std::str::FromStr;
    use x509_cert::der::DecodePem;

    #[test]
    fn rfc7515_es256_validation_example() {
        let _ = tracing_subscriber::fmt::try_init();
        let test_jws = "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q";

        let jwsc = JwsCompact::from_str(test_jws).unwrap();

        assert!(jwsc.to_string() == test_jws);

        assert!(jwsc.check_vectors(
            &[
                101, 121, 74, 104, 98, 71, 99, 105, 79, 105, 74, 70, 85, 122, 73, 49, 78, 105, 74,
                57, 46, 101, 121, 74, 112, 99, 51, 77, 105, 79, 105, 74, 113, 98, 50, 85, 105, 76,
                65, 48, 75, 73, 67, 74, 108, 101, 72, 65, 105, 79, 106, 69, 122, 77, 68, 65, 52,
                77, 84, 107, 122, 79, 68, 65, 115, 68, 81, 111, 103, 73, 109, 104, 48, 100, 72, 65,
                54, 76, 121, 57, 108, 101, 71, 70, 116, 99, 71, 120, 108, 76, 109, 78, 118, 98, 83,
                57, 112, 99, 49, 57, 121, 98, 50, 57, 48, 73, 106, 112, 48, 99, 110, 86, 108, 102,
                81
            ],
            &[
                14, 209, 33, 83, 121, 99, 108, 72, 60, 47, 127, 21, 88, 7, 212, 2, 163, 178, 40, 3,
                58, 249, 124, 126, 23, 129, 154, 195, 22, 158, 166, 101, 197, 10, 7, 211, 140, 60,
                112, 229, 216, 241, 45, 175, 8, 74, 84, 128, 166, 101, 144, 197, 242, 147, 80, 154,
                143, 63, 127, 138, 131, 163, 84, 213
            ]
        ));

        assert!(jwsc.get_jwk_pubkey_url().is_none());
        assert!(jwsc.get_jwk_pubkey().is_none());

        let pkey = r#"{"kty":"EC","crv":"P-256","x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU","y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"}"#;

        let pkey: Jwk = serde_json::from_str(pkey).expect("Invalid JWK");
        trace!("jwk -> {:?}", pkey);

        let jws_validator = JwsValidator::try_from(&pkey).expect("Unable to create validator");
        assert!(jwsc.get_jwk_pubkey_url().is_none());

        let released = jwsc
            .validate(&jws_validator)
            .expect("Unable to validate jws");
        trace!("rel -> {:?}", released);
    }

    #[test]
    fn rfc7515_es256_signature_example() {
        let _ = tracing_subscriber::fmt::try_init();
        // https://docs.rs/openssl/0.10.36/openssl/ec/struct.EcKey.html#method.from_private_components
        let jwss = JwsSigner::from_es256_jwk_components(
            "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
            "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
            "jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI",
        )
        .expect("failed to construct signer");

        let jws = JwsInner::new(vec![
            123, 34, 105, 115, 115, 34, 58, 34, 106, 111, 101, 34, 44, 13, 10, 32, 34, 101, 120,
            112, 34, 58, 49, 51, 48, 48, 56, 49, 57, 51, 56, 48, 44, 13, 10, 32, 34, 104, 116, 116,
            112, 58, 47, 47, 101, 120, 97, 109, 112, 108, 101, 46, 99, 111, 109, 47, 105, 115, 95,
            114, 111, 111, 116, 34, 58, 116, 114, 117, 101, 125,
        ]);

        let jwsc = jws.sign(&jwss).expect("Failed to sign");

        assert!(jwsc.get_jwk_pubkey_url().is_none());
        assert!(jwsc.get_jwk_pubkey().is_none());

        let pkey = r#"{"kty":"EC","crv":"P-256","x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU","y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"}"#;

        let pkey: Jwk = serde_json::from_str(pkey).expect("Invalid JWK");
        trace!("jwk -> {:?}", pkey);

        let jws_validator = JwsValidator::try_from(&pkey).expect("Unable to create validator");

        let released = jwsc
            .validate(&jws_validator)
            .expect("Unable to validate jws");
        trace!("rel -> {:?}", released);
    }

    #[test]
    fn es256_key_generate_cycle() {
        let _ = tracing_subscriber::fmt::try_init();
        let jwss = JwsSigner::generate_es256().expect("failed to construct signer.");

        let der = jwss.private_key_to_der().expect("Failed to extract DER");

        let jwss = JwsSigner::from_es256_der(&der).expect("Failed to restore signer");

        // This time we'll add the jwk pubkey and show it being used with the validator.
        let jws = JwsInner::new(vec![0, 1, 2, 3, 4])
            .set_kid("abcd".to_string())
            .set_typ("abcd".to_string())
            .set_cty("abcd".to_string());

        let jwsc = jws.sign_embed_public_jwk(&jwss).expect("Failed to sign");

        assert!(jwsc.get_jwk_pubkey_url().is_none());
        let pub_jwk = jwsc.get_jwk_pubkey().expect("No embeded public jwk!");
        assert!(*pub_jwk == jwss.public_key_as_jwk().unwrap());

        let jws_validator = JwsValidator::try_from(pub_jwk).expect("Unable to create validator");

        let released = jwsc
            .validate(&jws_validator)
            .expect("Unable to validate jws");
        assert!(released.payload() == &[0, 1, 2, 3, 4]);
    }

    // RSA3072
    // https://datatracker.ietf.org/doc/html/rfc7515#appendix-A.2
    #[test]
    fn rfc7515_rs256_validation_example() {
        let _ = tracing_subscriber::fmt::try_init();
        let test_jws = "eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.cC4hiUPoj9Eetdgtv3hF80EGrhuB__dzERat0XF9g2VtQgr9PJbu3XOiZj5RZmh7AAuHIm4Bh-0Qc_lF5YKt_O8W2Fp5jujGbds9uJdbF9CUAr7t1dnZcAcQjbKBYNX4BAynRFdiuB--f_nZLgrnbyTyWzO75vRK5h6xBArLIARNPvkSjtQBMHlb1L07Qe7K0GarZRmB_eSN9383LcOLn6_dO--xi12jzDwusC-eOkHWEsqtFZESc6BfI7noOPqvhJ1phCnvWh6IeYI2w9QOYEUipUTI8np6LbgGY9Fs98rqVt5AXLIhWkWywlVmtVrBp0igcN_IoypGlUPQGe77Rw";

        let jwsc = JwsCompact::from_str(test_jws).unwrap();

        assert!(jwsc.to_string() == test_jws);

        assert!(jwsc.check_vectors(
            &[
                101, 121, 74, 104, 98, 71, 99, 105, 79, 105, 74, 83, 85, 122, 73, 49, 78, 105, 74,
                57, 46, 101, 121, 74, 112, 99, 51, 77, 105, 79, 105, 74, 113, 98, 50, 85, 105, 76,
                65, 48, 75, 73, 67, 74, 108, 101, 72, 65, 105, 79, 106, 69, 122, 77, 68, 65, 52,
                77, 84, 107, 122, 79, 68, 65, 115, 68, 81, 111, 103, 73, 109, 104, 48, 100, 72, 65,
                54, 76, 121, 57, 108, 101, 71, 70, 116, 99, 71, 120, 108, 76, 109, 78, 118, 98, 83,
                57, 112, 99, 49, 57, 121, 98, 50, 57, 48, 73, 106, 112, 48, 99, 110, 86, 108, 102,
                81
            ],
            &[
                112, 46, 33, 137, 67, 232, 143, 209, 30, 181, 216, 45, 191, 120, 69, 243, 65, 6,
                174, 27, 129, 255, 247, 115, 17, 22, 173, 209, 113, 125, 131, 101, 109, 66, 10,
                253, 60, 150, 238, 221, 115, 162, 102, 62, 81, 102, 104, 123, 0, 11, 135, 34, 110,
                1, 135, 237, 16, 115, 249, 69, 229, 130, 173, 252, 239, 22, 216, 90, 121, 142, 232,
                198, 109, 219, 61, 184, 151, 91, 23, 208, 148, 2, 190, 237, 213, 217, 217, 112, 7,
                16, 141, 178, 129, 96, 213, 248, 4, 12, 167, 68, 87, 98, 184, 31, 190, 127, 249,
                217, 46, 10, 231, 111, 36, 242, 91, 51, 187, 230, 244, 74, 230, 30, 177, 4, 10,
                203, 32, 4, 77, 62, 249, 18, 142, 212, 1, 48, 121, 91, 212, 189, 59, 65, 238, 202,
                208, 102, 171, 101, 25, 129, 253, 228, 141, 247, 127, 55, 45, 195, 139, 159, 175,
                221, 59, 239, 177, 139, 93, 163, 204, 60, 46, 176, 47, 158, 58, 65, 214, 18, 202,
                173, 21, 145, 18, 115, 160, 95, 35, 185, 232, 56, 250, 175, 132, 157, 105, 132, 41,
                239, 90, 30, 136, 121, 130, 54, 195, 212, 14, 96, 69, 34, 165, 68, 200, 242, 122,
                122, 45, 184, 6, 99, 209, 108, 247, 202, 234, 86, 222, 64, 92, 178, 33, 90, 69,
                178, 194, 85, 102, 181, 90, 193, 167, 72, 160, 112, 223, 200, 163, 42, 70, 149, 67,
                208, 25, 238, 251, 71
            ]
        ));

        assert!(jwsc.get_jwk_pubkey_url().is_none());
        assert!(jwsc.get_jwk_pubkey().is_none());

        let pkey = r#"{
            "kty":"RSA",
            "n":"ofgWCuLjybRlzo0tZWJjNiuSfb4p4fAkd_wWJcyQoTbji9k0l8W26mPddxHmfHQp-Vaw-4qPCJrcS2mJPMEzP1Pt0Bm4d4QlL-yRT-SFd2lZS-pCgNMsD1W_YpRPEwOWvG6b32690r2jZ47soMZo9wGzjb_7OMg0LOL-bSf63kpaSHSXndS5z5rexMdbBYUsLA9e-KXBdQOS-UTo7WTBEMa2R2CapHg665xsmtdVMTBQY4uDZlxvb3qCo5ZwKh9kG4LT6_I5IhlJH7aGhyxXFvUK-DWNmoudF8NAco9_h9iaGNj8q2ethFkMLs91kzk2PAcDTW9gb54h4FRWyuXpoQ",
            "e":"AQAB"
        }"#;

        let pkey: Jwk = serde_json::from_str(pkey).expect("Invalid JWK");
        trace!("jwk -> {:?}", pkey);

        let jws_validator = JwsValidator::try_from(&pkey).expect("Unable to create validator");
        assert!(jwsc.get_jwk_pubkey_url().is_none());

        let released = jwsc
            .validate(&jws_validator)
            .expect("Unable to validate jws");
        trace!("rel -> {:?}", released);
    }

    #[test]
    fn rs256_key_generate_cycle() {
        let _ = tracing_subscriber::fmt::try_init();
        let jwss = JwsSigner::generate_legacy_rs256().expect("failed to construct signer.");

        let der = jwss.private_key_to_der().expect("Failed to extract DER");

        let jwss = JwsSigner::from_rs256_der(&der).expect("Failed to restore signer");

        // This time we'll add the jwk pubkey and show it being used with the validator.
        let jws = JwsInner::new(vec![0, 1, 2, 3, 4])
            .set_kid("abcd".to_string())
            .set_typ("abcd".to_string())
            .set_cty("abcd".to_string());

        let jwsc = jws.sign_embed_public_jwk(&jwss).expect("Failed to sign");

        assert!(jwsc.get_jwk_pubkey_url().is_none());
        assert!(jwsc.get_jwk_kid() == Some("abcd"));

        let pub_jwk = jwsc.get_jwk_pubkey().expect("No embeded public jwk!");
        assert!(*pub_jwk == jwss.public_key_as_jwk().unwrap());

        let jws_validator = JwsValidator::try_from(pub_jwk).expect("Unable to create validator");

        let released = jwsc
            .validate(&jws_validator)
            .expect("Unable to validate jws");
        assert!(released.payload() == &[0, 1, 2, 3, 4]);
    }

    // A test for the signer to/from der.
    // directly get the validator from the signer.

    #[test]
    fn rfc7519_hs256_validation_example() {
        let _ = tracing_subscriber::fmt::try_init();
        let test_jws = "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

        let jwsc = JwsCompact::from_str(test_jws).unwrap();

        // When we encode this, we change the order of some fields, which means this check will
        // fail, but we still assert the vectors correctly so it's okay :)
        // assert!(jwsc.to_string() == test_jws);

        assert!(jwsc.check_vectors(
            &[
                101, 121, 74, 48, 101, 88, 65, 105, 79, 105, 74, 75, 86, 49, 81, 105, 76, 65, 48,
                75, 73, 67, 74, 104, 98, 71, 99, 105, 79, 105, 74, 73, 85, 122, 73, 49, 78, 105,
                74, 57, 46, 101, 121, 74, 112, 99, 51, 77, 105, 79, 105, 74, 113, 98, 50, 85, 105,
                76, 65, 48, 75, 73, 67, 74, 108, 101, 72, 65, 105, 79, 106, 69, 122, 77, 68, 65,
                52, 77, 84, 107, 122, 79, 68, 65, 115, 68, 81, 111, 103, 73, 109, 104, 48, 100, 72,
                65, 54, 76, 121, 57, 108, 101, 71, 70, 116, 99, 71, 120, 108, 76, 109, 78, 118, 98,
                83, 57, 112, 99, 49, 57, 121, 98, 50, 57, 48, 73, 106, 112, 48, 99, 110, 86, 108,
                102, 81
            ],
            &[
                116, 24, 223, 180, 151, 153, 224, 37, 79, 250, 96, 125, 216, 173, 187, 186, 22,
                212, 37, 77, 105, 214, 191, 240, 91, 88, 5, 88, 83, 132, 141, 121
            ]
        ));

        assert!(jwsc.get_jwk_pubkey_url().is_none());
        assert!(jwsc.get_jwk_pubkey().is_none());

        let skey = base64::decode_config(
        "AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow", base64::URL_SAFE_NO_PAD
        ).expect("Invalid key");

        let jws_signer = JwsSigner::from_hs256_raw(&skey).expect("Unable to create validator");
        let jws_validator = jws_signer
            .get_validator()
            .expect("Unable to create validator");

        let released = jwsc
            .validate(&jws_validator)
            .expect("Unable to validate jws");
        trace!("rel -> {:?}", released);
    }

    #[test]
    fn test_jws_validator_can_be_built_from_certificate_of_prime256v1() {
        // openssl ecparam -out ec_key.pem -name prime256v1 -genkey
        // openssl req -new -key ec_key.pem -x509 -days 365 -out cert.pem
        let cert_pem = r#"-----BEGIN CERTIFICATE-----
MIIB4DCCAYWgAwIBAgIULi9xlsQtHXNQ+FM92tLg7XHQbyAwCgYIKoZIzj0EAwIw
RTELMAkGA1UEBhMCSlAxETAPBgNVBAgMCEthbmFnYXdhMRMwEQYDVQQKDApjb2Rl
bW9uZ2VyMQ4wDAYDVQQDDAVLaWt1bzAeFw0yMzExMTAwNjMwMTFaFw0yNDExMDkw
NjMwMTFaMEUxCzAJBgNVBAYTAkpQMREwDwYDVQQIDAhLYW5hZ2F3YTETMBEGA1UE
CgwKY29kZW1vbmdlcjEOMAwGA1UEAwwFS2lrdW8wWTATBgcqhkjOPQIBBggqhkjO
PQMBBwNCAAQk1nolzbMPGRpcpWl163gg4g0ZzQpNp+RMRSzQQm750way2mWkyBwR
L0fqvOIx+SMsC4NKPFgt4q0YXf1W63uuo1MwUTAdBgNVHQ4EFgQUmvJWV9jWW09+
9otLB7WPD0B4tA0wHwYDVR0jBBgwFoAUmvJWV9jWW09+9otLB7WPD0B4tA0wDwYD
VR0TAQH/BAUwAwEB/zAKBggqhkjOPQQDAgNJADBGAiEA4t7fHNbKado4cBZJc6UN
o1sF+a+l+V3dc9SDu/UOQ7gCIQCxWOv91yQYb9qeTLvhAZQkUpaRvZB4YZK4nEe9
6ACdUg==
-----END CERTIFICATE-----"#;
        let cert = Certificate::from_pem(cert_pem).unwrap();
        let validator = JwsValidator::try_from(cert).unwrap();
        assert!(matches!(validator, JwsValidator::ES256 { .. }));
    }

    #[test]
    fn test_jws_validator_can_be_built_from_certificate_of_rsa_2048() {
        // openssl genrsa -out rsa_key.pem 2048
        // openssl req -new -key rsa_key.pem -x509 -days 365 -out cert.pem
        let cert_pem = r#"-----BEGIN CERTIFICATE-----
MIIDazCCAlOgAwIBAgIUOToRKDpmxdwGEm20x8Z6ydKqZwkwDQYJKoZIhvcNAQEL
BQAwRTELMAkGA1UEBhMCSlAxETAPBgNVBAgMCEthbmFnYXdhMRMwEQYDVQQKDApj
b2RlbW9uZ2VyMQ4wDAYDVQQDDAVLaWt1bzAeFw0yMzExMTAwNjM3MDBaFw0yNDEx
MDkwNjM3MDBaMEUxCzAJBgNVBAYTAkpQMREwDwYDVQQIDAhLYW5hZ2F3YTETMBEG
A1UECgwKY29kZW1vbmdlcjEOMAwGA1UEAwwFS2lrdW8wggEiMA0GCSqGSIb3DQEB
AQUAA4IBDwAwggEKAoIBAQDzWSL5nX5uK08h3tE7addr4XuqcUlWqw6LKyi1N/Ru
6B5dKvdV/cRp8IZMkChrwOraLnBhvdkVieISUwhThApPVwwIBuEdSrG6MZ/q5uay
Zpv8/0PhlFkdeXQqoHCrng4iEWzHVRVxytQNkfDWuoddbL2XLR4g6+R4dW29+aky
i+Ouk1MFh7B5lhSBPtvqeMY0k44sLw+j/nUYuhp1aul+AfDC9feet1nw+6jiwtzh
EFgm2N7gk5I2YB4sib7Qn6rgcTaMuDOyKLj5otih7GAR7aPLec9KzUFdIWAYdUNh
SpYwwRRHlEuE/6lT4vV70Oxr5WLut0znBy6mB8bcxDzvAgMBAAGjUzBRMB0GA1Ud
DgQWBBR8srw+Y/ulAEusOy0UBliH8Q0bVDAfBgNVHSMEGDAWgBR8srw+Y/ulAEus
Oy0UBliH8Q0bVDAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQA+
qRDpzkzGgA0FADAQHJ+l4sLLcPde4nkIVLMraIXF2SgEnH+z8IUaq8QFgGOkzf7i
zJDHiGmD20jHLadKWp7BWi/X7sS5SkGpnkBe6Nn9kOKMozcLwjdAX8a7Ok2F8EmR
qsY00NxRk8nED7BnTC3Ppw+GGvxsIlnm50iLmZRgo8hJU+uKNVN7wTgAEguDuE7z
nsydZ+kCJI+RHpyURQDuI8nZ7vZXES9Buo1TIa/hXgzqBuCkUfLG61fhGNA1c5SR
4mvOLglQcRUYTokJ3PQVNudmKf2VTRiRWGrO5hQGjIa9DVRfUp5c3pnUa7FPhqjX
76JFauJl+rWTzn9OiIW+
-----END CERTIFICATE-----"#;
        let cert = Certificate::from_pem(cert_pem).unwrap();
        let validator = JwsValidator::try_from(cert).unwrap();
        assert!(matches!(validator, JwsValidator::RS256 { .. }));
    }
}
