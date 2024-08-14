use vodozemac::{KeyError, SignatureError};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Curve25519PublicKey(pub(crate) vodozemac::Curve25519PublicKey);

impl Curve25519PublicKey {
    pub fn from_base64(key: &str) -> Result<Box<Curve25519PublicKey>, KeyError> {
        Ok(Curve25519PublicKey(vodozemac::Curve25519PublicKey::from_base64(key)?).into())
    }

    #[allow(clippy::wrong_self_convention)]
    pub fn to_base64(&self) -> String {
        self.0.to_base64()
    }
}

pub fn curve25519_public_key_from_base64(key: &str) -> Box<Curve25519PublicKeyFromBase64Result> {
    Box::new(Curve25519PublicKeyFromBase64Result(Curve25519PublicKey::from_base64(key)))
}

pub fn curve25519_public_key_from_base64_result_value(result: Box<Curve25519PublicKeyFromBase64Result>) -> Box<Curve25519PublicKey> {
    return result.value()
}

pub struct Curve25519PublicKeyFromBase64Result(pub(crate) Result<Box<Curve25519PublicKey>, KeyError>);

impl Curve25519PublicKeyFromBase64Result {
    pub fn has_error(&self) -> bool {
        self.0.is_err()
    }

    pub fn error_code(&self) -> u8 {
        match &self.0 {
            Ok(_) => 0,
            Err(error) => match error {
                KeyError::Base64Error(_) => 1,
                KeyError::Base64PrivateKey(_) => 2,
                KeyError::InvalidKeyLength { .. } => 3,
                KeyError::Signature(_) => 4,
                KeyError::NonContributoryKey => 5,
            }
        }
    }

    pub fn value(self) -> Box<Curve25519PublicKey> {
        self.0.unwrap()
    }
}


// ### Public Key
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ed25519PublicKey(pub(crate) vodozemac::Ed25519PublicKey);

impl Ed25519PublicKey {
    pub fn from_base64(key: &str) -> Result<Box<Ed25519PublicKey>, KeyError> {
        Ok(Ed25519PublicKey(vodozemac::Ed25519PublicKey::from_base64(key)?).into())
    }

    #[allow(clippy::wrong_self_convention)]
    pub fn to_base64(&self) -> String {
        self.0.to_base64()
    }
    pub fn verify(&self, message: &[u8], signature: &Ed25519Signature) -> bool {
        self.0.verify(message, &signature.0).is_ok()
    }
}

pub fn ed25519_public_key_from_base64(key: &str) -> Box<Ed25519PublicKeyFromBase64Result> {
    Box::new(Ed25519PublicKeyFromBase64Result(Ed25519PublicKey::from_base64(key)))
}

pub fn ed25519_public_key_from_base64_result_value(result: Box<Ed25519PublicKeyFromBase64Result>) -> Box<Ed25519PublicKey> {
    result.value()
}

pub struct Ed25519PublicKeyFromBase64Result(pub(crate) Result<Box<Ed25519PublicKey>, KeyError>);

impl Ed25519PublicKeyFromBase64Result {
    pub fn has_error(&self) -> bool {
        self.0.is_err()
    }

    pub fn error_code(&self) -> u8 {
        match &self.0 {
            Ok(_) => 0,
            Err(error) => match error {
                KeyError::Base64Error(_) => 1,
                KeyError::Base64PrivateKey(_) => 2,
                KeyError::InvalidKeyLength { .. } => 3,
                KeyError::Signature(_) => 4,
                KeyError::NonContributoryKey => 5,
            }
        }
    }

    pub fn value(self) -> Box<Ed25519PublicKey> {
        self.0.unwrap()
    }
}

// ### Signature
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ed25519Signature(pub(crate) vodozemac::Ed25519Signature);

impl Ed25519Signature {
    pub fn from_base64(key: &str) -> Result<Box<Ed25519Signature>, SignatureError> {
        Ok(Ed25519Signature(vodozemac::Ed25519Signature::from_base64(key)?).into())
    }

    #[allow(clippy::wrong_self_convention)]
    pub fn to_base64(&self) -> String {
        self.0.to_base64()
    }
}

pub fn ed25519_signature_from_base64(key: &str) -> Box<Ed25519SignatureFromBase64Result> {
    Box::new(Ed25519SignatureFromBase64Result(Ed25519Signature::from_base64(key)))
}

pub fn ed25519_signature_from_base64_result_value(result: Box<Ed25519SignatureFromBase64Result>) -> Box<Ed25519Signature> {
    result.value()
}

pub struct Ed25519SignatureFromBase64Result(pub(crate) Result<Box<Ed25519Signature>, SignatureError>);

impl Ed25519SignatureFromBase64Result {
    pub fn has_error(&self) -> bool {
        self.0.is_err()
    }

    pub fn error_code(&self) -> u8 {
        match &self.0 {
            Ok(_) => 0,
            Err(error) => match error {
                SignatureError::Base64(_) => 1,
                SignatureError::Signature(_) => 2,
            }
        }
    }

    pub fn value(self) -> Box<Ed25519Signature> {
        self.0.unwrap()
    }
}

// ### Secret Key
pub struct Ed25519SecretKey(pub(crate) vodozemac::Ed25519SecretKey);

impl Ed25519SecretKey {
    pub fn from_base64(key: &str) -> Result<Box<Ed25519SecretKey>, KeyError> {
        Ok(Ed25519SecretKey(vodozemac::Ed25519SecretKey::from_base64(key)?).into())
    }

    #[allow(clippy::wrong_self_convention)]
    pub fn to_base64(&self) -> String {
        self.0.to_base64()
    }

    pub fn sign(&self, message: &[u8]) -> Box<Ed25519Signature> {
        Box::new(Ed25519Signature(self.0.sign(message)))
    }
}

pub fn ed25519_secret_key_from_base64(key: &str) -> Box<Ed25519SecretKeyFromBase64Result> {
    Box::new(Ed25519SecretKeyFromBase64Result(Ed25519SecretKey::from_base64(key)))
}

pub fn ed25519_secret_key_from_base64_result_value(result: Box<Ed25519SecretKeyFromBase64Result>) -> Box<Ed25519SecretKey> {
    result.value()
}

pub struct Ed25519SecretKeyFromBase64Result(pub(crate) Result<Box<Ed25519SecretKey>, KeyError>);

impl Ed25519SecretKeyFromBase64Result {
    pub fn has_error(&self) -> bool {
        self.0.is_err()
    }

    pub fn error_code(&self) -> u8 {
        match &self.0 {
            Ok(_) => 0,
            Err(error) => match error {
                KeyError::Base64Error(_) => 1,
                KeyError::Base64PrivateKey(_) => 2,
                KeyError::InvalidKeyLength { .. } => 3,
                KeyError::Signature(_) => 4,
                KeyError::NonContributoryKey => 5,
            }
        }
    }

    pub fn value(self) -> Box<Ed25519SecretKey> {
        self.0.unwrap()
    }
}
