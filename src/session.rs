use super::{ffi::SessionKeys, Curve25519PublicKey, OlmMessage};

pub struct Session(pub(crate) vodozemac::olm::Session);

impl Session {
    pub fn session_id(&self) -> String {
        self.0.session_id()
    }

    pub fn pickle(&self, pickle_key: &[u8; 32]) -> String {
        self.0.pickle().encrypt(pickle_key)
    }

    pub fn encrypt(&mut self, plaintext: &str) -> Box<OlmMessage> {
        OlmMessage(self.0.encrypt(plaintext)).into()
    }

    pub fn decrypt(&mut self, message: &OlmMessage) -> Box<SessionDecryptResult> {
        Box::new(SessionDecryptResult(self.0.decrypt(&message.0).map(|it| String::from_utf8_lossy(&it).to_string())))
    }

    pub fn session_keys(&self) -> SessionKeys {
        let session_keys = self.0.session_keys();

        SessionKeys {
            identity_key: Curve25519PublicKey(session_keys.identity_key).into(),
            base_key: Curve25519PublicKey(session_keys.base_key).into(),
            one_time_key: Curve25519PublicKey(session_keys.one_time_key).into(),
        }
    }

    pub fn session_matches(&self, message: &OlmMessage) -> bool {
        if let vodozemac::olm::OlmMessage::PreKey(m) = &message.0 {
            self.0.session_keys() == m.session_keys()
        } else {
            false
        }
    }
}

pub struct SessionDecryptResult(pub(crate) Result<String, vodozemac::olm::DecryptionError>);

impl SessionDecryptResult {
    pub fn has_error(&self) -> bool {
        self.0.is_err()
    }

    pub fn error_code(&self) -> u8 {
        match &self.0 {
            Ok(_) => 0,
            Err(error) => match error {
                vodozemac::olm::DecryptionError::InvalidMAC(_) => 1,
                vodozemac::olm::DecryptionError::InvalidMACLength(_, _) => 2,
                vodozemac::olm::DecryptionError::InvalidPadding(_) => 3,
                vodozemac::olm::DecryptionError::MissingMessageKey(_) => 4,
                vodozemac::olm::DecryptionError::TooBigMessageGap(_, _) => 5,
            }
        }
    }

    pub fn value(self) -> String {
        self.0.unwrap()
    }
}

pub fn session_decrypt_result_value(result: Box<SessionDecryptResult>) -> String {
    result.value()
}

pub fn session_from_pickle(
    pickle: &str,
    pickle_key: &[u8; 32],
) -> Result<Box<Session>, anyhow::Error> {
    Ok(Session(vodozemac::olm::Session::from_pickle(vodozemac::olm::SessionPickle::from_encrypted(pickle, pickle_key)?)).into())
}

pub fn session_from_olm_pickle(pickle: &str, pickle_key: &[u8]) -> Result<Box<Session>, anyhow::Error> {
    Ok(Box::new(Session(vodozemac::olm::Session::from_libolm_pickle(pickle, pickle_key)?)))
}
