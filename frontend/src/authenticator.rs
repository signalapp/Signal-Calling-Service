//
// Copyright 2022 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::{
    ops::Range,
    str::FromStr,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{anyhow, Result};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use calling_common::RoomId;
use hex::FromHex;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;

use crate::{authenticator::ParsedHeader::*, frontend::UserId};

pub type HmacSha256 = Hmac<Sha256>;

pub const GV2_AUTH_MATCH_LIMIT: usize = 10;
const GV2_AUTH_MAX_HEADER_AGE: Duration = Duration::from_secs(60 * 60 * 30); // 30 hours

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum UserPermission {
    JoinAlreadyCreated,
    CreateAndJoin,
}

impl FromStr for UserPermission {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "0" => Ok(UserPermission::JoinAlreadyCreated),
            "1" => Ok(UserPermission::CreateAndJoin),
            _ => Err(anyhow!("invalid user permission string")),
        }
    }
}

impl UserPermission {
    pub fn can_create(&self) -> bool {
        match self {
            UserPermission::JoinAlreadyCreated => false,
            UserPermission::CreateAndJoin => true,
        }
    }
}

pub struct GroupAuthToken {
    pub user_id: UserId,
    pub group_id: RoomId,
    pub time: SystemTime,
    pub user_permission: UserPermission,
    pub mac_digest: Vec<u8>,
    pub validation_range: Range<usize>,
}

impl FromStr for GroupAuthToken {
    type Err = anyhow::Error;

    fn from_str(password: &str) -> Result<Self, Self::Err> {
        if let [version, user_id, group_id, time_unix_secs, user_permission, mac_digest_hex] =
            password.split(':').collect::<Vec<_>>()[..]
        {
            if version != "2" {
                return Err(anyhow!("unsupported signature"));
            }
            if user_id.is_empty() {
                return Err(anyhow!("user_id is missing"));
            }
            if group_id.is_empty() {
                return Err(anyhow!("group_id is missing"));
            }

            let time_unix_secs = time_unix_secs
                .parse::<u64>()
                .map_err(|_| anyhow!("time not encoded correctly"))?;
            let time = UNIX_EPOCH
                .checked_add(Duration::from_secs(time_unix_secs))
                .ok_or_else(|| anyhow!("time not valid"))?;
            let user_permission = user_permission
                .parse()
                .map_err(|_| anyhow!("unknown permission"))?;
            let mac_digest =
                Vec::from_hex(mac_digest_hex).map_err(|_| anyhow!("mac not hexadecimal"))?;

            Ok(GroupAuthToken {
                user_id: user_id.to_string(),
                group_id: group_id.into(),
                time,
                user_permission,
                mac_digest,
                validation_range: 0..(password.len() - mac_digest_hex.len() - 1),
            })
        } else {
            Err(anyhow!("invalid format"))
        }
    }
}

/// What we know about the authorization a client has.
#[derive(Clone, Debug, PartialEq)]
pub struct UserAuthorization {
    pub user_id: UserId,
    pub room_id: RoomId,
    pub user_permission: UserPermission,
}

#[derive(thiserror::Error, Debug, Eq, PartialEq)]
pub enum AuthenticatorError {
    #[error("invalid hmac_key length")]
    InvalidMacKeyLength,
    #[error("bad signature")]
    BadSignature,
    #[error("invalid time")]
    InvalidTime,
    #[error("expired credentials")]
    ExpiredCredentials,
    #[error("authorization header not valid")]
    AuthHeaderNotValid,
    #[error("could not parse authorization header")]
    AuthHeaderParseFailure,
    #[error("{0}")]
    DecodeFailure(#[from] base64::DecodeError),
    #[error("{0}")]
    Utf8Failure(#[from] std::str::Utf8Error),
}

/// The Authenticator is used to verify the authorization header for incoming http requests.
pub struct Authenticator {
    key: [u8; 32],
}

fn hmac_sha256_digest(key: &[u8], data: &[u8]) -> Result<impl AsRef<[u8]>, AuthenticatorError> {
    let mut hmac =
        HmacSha256::new_from_slice(key).map_err(|_| AuthenticatorError::InvalidMacKeyLength)?;
    hmac.update(data);
    Ok(hmac.finalize().into_bytes())
}

fn verify_gv2_auth_mac(
    expected_mac_digest: impl AsRef<[u8]>,
    actual_mac_digest: impl AsRef<[u8]>,
) -> Result<(), AuthenticatorError> {
    if bool::from(
        expected_mac_digest.as_ref()[..GV2_AUTH_MATCH_LIMIT].ct_eq(actual_mac_digest.as_ref()),
    ) {
        Ok(())
    } else {
        event!("calling.frontend.authenticator.bad_signature");
        Err(AuthenticatorError::BadSignature)
    }
}

#[derive(Debug, PartialEq)]
pub enum ParsedHeader<'a> {
    Basic(String, String),
    Bearer(&'a str),
}

impl Authenticator {
    pub fn from_hex_key(hex_key: &str) -> Result<Self> {
        Ok(Self {
            key: <[u8; 32]>::from_hex(hex_key)?,
        })
    }

    /// Verify the given token and return an UserAuthorization or an error.
    pub fn verify(
        &self,
        auth_token: GroupAuthToken,
        password: &str,
    ) -> Result<UserAuthorization, AuthenticatorError> {
        // Check that the MACs match (up to the match limit).
        let expected_mac_digest =
            hmac_sha256_digest(&self.key, password[auth_token.validation_range].as_bytes())?;
        let actual_mac_digest = &auth_token.mac_digest;
        verify_gv2_auth_mac(&expected_mac_digest, actual_mac_digest)?;

        // Check if the GV2 auth header expired.
        if SystemTime::now()
            > auth_token
                .time
                .checked_add(GV2_AUTH_MAX_HEADER_AGE)
                .ok_or(AuthenticatorError::InvalidTime)?
        {
            event!("calling.frontend.authenticator.expired_credentials");
            return Err(AuthenticatorError::ExpiredCredentials);
        }

        Ok(UserAuthorization {
            user_id: auth_token.user_id,
            room_id: auth_token.group_id,
            user_permission: auth_token.user_permission,
        })
    }

    /// Helper function to parse an authorization header using the Basic or Bearer authentication scheme.
    pub fn parse_authorization_header(header: &str) -> Result<ParsedHeader, AuthenticatorError> {
        // Get the credentials from the Bearer authorization header.
        match header.split_once(' ') {
            Some((scheme, token)) if scheme.eq_ignore_ascii_case("Basic") => {
                let credentials_utf8 = STANDARD.decode(token)?;
                let credentials = std::str::from_utf8(&credentials_utf8)?;
                // Split the credentials into the username and password.
                let (username, password) = credentials
                    .split_once(':')
                    .ok_or(AuthenticatorError::AuthHeaderNotValid)?;
                Ok(Basic(username.to_string(), password.to_string()))
            }
            Some((scheme, token)) if scheme.eq_ignore_ascii_case("Bearer") => {
                Ok(Bearer(token.trim_start_matches(' ')))
            }
            _ => Err(AuthenticatorError::AuthHeaderParseFailure),
        }
    }
}

#[cfg(test)]
mod authenticator_tests {
    use super::*;
    use base64::DecodeError::{InvalidLength, InvalidPadding};
    use env_logger::Env;
    use hex::ToHex;

    const AUTH_KEY_1: &str = "f00f0014fe091de31827e8d686969fad65013238aadd25ef8629eb8a9e5ef69b";
    const AUTH_KEY_2: &str = "f00f0072f8ee256b9ba24255897230342cc83b76a3964d6288a7ac8ae4e8e9ca";

    const INVALID_AUTH_KEY: &str =
        "f00f00b3403e934b8c5534d799ccca6c8ba4192dd5809133764b8fdf3e48180z";
    const SMALL_AUTH_KEY: &str = "bbf1cf3b3073c6fd8e416631391ec272";
    const EMPTY_AUTH_KEY: &str = "";

    const USER_ID_1: &str = "1111111111111111";
    const GROUP_ID_1: &str = "aaaaaaaaaaaaaaaa";

    fn initialize_logging() {
        let _ = env_logger::Builder::from_env(
            Env::default()
                .default_filter_or("calling_frontend=info")
                .default_write_style_or("never"),
        )
        .format_timestamp_millis()
        .is_test(true)
        .try_init();
    }

    #[test]
    fn test_parse_basic_authorization_header() {
        initialize_logging();

        let result = Authenticator::parse_authorization_header("");
        assert_eq!(result, Err(AuthenticatorError::AuthHeaderParseFailure));
        assert_eq!(
            result.err().unwrap().to_string(),
            "could not parse authorization header"
        );

        let is_auth_header_parse_failure = |header: &str| -> bool {
            Authenticator::parse_authorization_header(header)
                == Err(AuthenticatorError::AuthHeaderParseFailure)
        };

        // Error: could not parse authorization header
        assert!(is_auth_header_parse_failure("B"));
        assert!(is_auth_header_parse_failure("Basic"));
        assert!(is_auth_header_parse_failure("B X"));
        assert!(is_auth_header_parse_failure("Basi XYZ"));

        // DecodeError: Encoded text cannot have a 6-bit remainder.
        assert_eq!(
            Authenticator::parse_authorization_header("Basic X"),
            Err(AuthenticatorError::DecodeFailure(InvalidLength))
        );

        // DecodeError: Invalid padding.
        assert_eq!(
            Authenticator::parse_authorization_header("Basic XYZ"),
            Err(AuthenticatorError::DecodeFailure(InvalidPadding))
        );

        // Utf8Error: invalid utf-8 sequence of 1 bytes from index 0
        assert!(Authenticator::parse_authorization_header("Basic //3//Q==").is_err());

        // Utf8Error: invalid utf-8 sequence of 1 bytes from index 8
        assert!(Authenticator::parse_authorization_header(
            "Basic MTIzNDU2Nzj95v3n/ej96f3q/ev97P3t/e797w=="
        )
        .is_err());

        let result = Authenticator::parse_authorization_header("Basic VGVzdA==");
        assert!(result.is_err());
        assert_eq!(
            result.err().unwrap().to_string(),
            "authorization header not valid"
        );

        let is_auth_header_not_valid = |header: &str| -> bool {
            Authenticator::parse_authorization_header(header)
                == Err(AuthenticatorError::AuthHeaderNotValid)
        };

        // Error: authorization header not valid
        assert!(is_auth_header_not_valid("Basic "));
        assert!(is_auth_header_not_valid("Basic MSAy"));
        assert!(is_auth_header_not_valid("Basic MWIgMmI="));

        // ":"
        assert_eq!(
            Authenticator::parse_authorization_header("Basic Og==").unwrap(),
            Basic("".to_string(), "".to_string())
        );

        // "username:password"
        assert_eq!(
            Authenticator::parse_authorization_header("Basic dXNlcm5hbWU6cGFzc3dvcmQ=").unwrap(),
            Basic("username".to_string(), "password".to_string())
        );

        // ":password"
        assert_eq!(
            Authenticator::parse_authorization_header("Basic OnBhc3N3b3Jk").unwrap(),
            Basic("".to_string(), "password".to_string())
        );

        // "username:"
        assert_eq!(
            Authenticator::parse_authorization_header("Basic dXNlcm5hbWU6").unwrap(),
            Basic("username".to_string(), "".to_string())
        );

        // "::"
        assert_eq!(
            Authenticator::parse_authorization_header("Basic Ojo=").unwrap(),
            Basic("".to_string(), ":".to_string())
        );

        // ":::::"
        assert_eq!(
            Authenticator::parse_authorization_header("Basic Ojo6Ojo=").unwrap(),
            Basic("".to_string(), "::::".to_string())
        );

        // "1a2b3c:1a2b3c:1a2b3c:1a2b3c"
        assert_eq!(
            Authenticator::parse_authorization_header("Basic MWEyYjNjOjFhMmIzYzoxYTJiM2M6MWEyYjNj")
                .unwrap(),
            Basic("1a2b3c".to_string(), "1a2b3c:1a2b3c:1a2b3c".to_string())
        );
    }

    #[test]
    fn test_parse_bearer_authorization_header() {
        initialize_logging();

        let result = Authenticator::parse_authorization_header("");
        assert_eq!(result, Err(AuthenticatorError::AuthHeaderParseFailure));
        assert_eq!(
            result.err().unwrap().to_string(),
            "could not parse authorization header"
        );

        let is_auth_header_parse_failure = |header: &str| -> bool {
            Authenticator::parse_authorization_header(header)
                == Err(AuthenticatorError::AuthHeaderParseFailure)
        };

        // Error: could not parse authorization header
        assert!(is_auth_header_parse_failure("B"));
        assert!(is_auth_header_parse_failure("Bearer"));
        assert!(is_auth_header_parse_failure("B X"));
        assert!(is_auth_header_parse_failure("Bear XYZ"));
        assert!(is_auth_header_parse_failure("Bearerr XYZ"));

        assert_eq!(
            Authenticator::parse_authorization_header("Bearer XYZ"),
            Ok(Bearer("XYZ"))
        );

        assert_eq!(
            Authenticator::parse_authorization_header("bEaReR XYZ"),
            Ok(Bearer("XYZ"))
        );

        assert_eq!(
            Authenticator::parse_authorization_header("Bearer           XYZ"),
            Ok(Bearer("XYZ"))
        );
    }

    fn generate_signed_v2_password(
        user_id_hex: &str,
        group_id_hex: &str,
        timestamp: u64,
        permission: &str,
        key: &[u8; 32],
    ) -> String {
        initialize_logging();

        // Format the credentials string.
        let credentials = format!(
            "2:{}:{}:{}:{}",
            user_id_hex, group_id_hex, timestamp, permission
        );

        // Get the MAC for the credentials.
        let mut hmac = HmacSha256::new_from_slice(key).unwrap();
        hmac.update(credentials.as_bytes());
        let mac = hmac.finalize().into_bytes();
        let mac = &mac[..GV2_AUTH_MATCH_LIMIT];

        // Append the MAC to the credentials.
        format!("{}:{}", credentials, mac.encode_hex::<String>())
    }

    #[test]
    fn test_authenticate_success() {
        initialize_logging();

        let authenticator = Authenticator::from_hex_key(AUTH_KEY_1).unwrap();
        let key = <[u8; 32]>::from_hex(AUTH_KEY_1).unwrap();

        let timestamp = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap();

        let password =
            generate_signed_v2_password(USER_ID_1, GROUP_ID_1, timestamp.as_secs(), "1", &key);

        let result = authenticator.verify(GroupAuthToken::from_str(&password).unwrap(), &password);
        assert!(result.is_ok());
        let user_authorization = result.unwrap();
        assert_eq!(user_authorization.user_id, USER_ID_1);
        assert_eq!(user_authorization.room_id, RoomId::from(GROUP_ID_1));
        assert_eq!(
            user_authorization.user_permission,
            UserPermission::CreateAndJoin
        );
    }

    #[test]
    fn test_authenticate_invalid_key() {
        initialize_logging();

        let authenticator = Authenticator::from_hex_key(INVALID_AUTH_KEY);
        assert!(authenticator.is_err());

        let authenticator = Authenticator::from_hex_key(SMALL_AUTH_KEY);
        assert!(authenticator.is_err());

        let authenticator = Authenticator::from_hex_key(EMPTY_AUTH_KEY);
        assert!(authenticator.is_err());
    }

    #[test]
    fn test_auth_token_malformed() {
        initialize_logging();

        let result = GroupAuthToken::from_str("1:2");
        assert!(result.is_err());

        // Error: Password not valid
        assert!(GroupAuthToken::from_str("").is_err());
        assert!(GroupAuthToken::from_str(":").is_err());
        assert!(GroupAuthToken::from_str("::").is_err());
        assert!(GroupAuthToken::from_str(":::").is_err());
        assert!(GroupAuthToken::from_str("::::").is_err());
        assert!(GroupAuthToken::from_str(":::::").is_err());
        assert!(GroupAuthToken::from_str("2:::::").is_err());
        assert!(GroupAuthToken::from_str("1:2:3").is_err());
        assert!(GroupAuthToken::from_str("1:2:3:4:5").is_err());

        // Error: Odd number of digits
        assert!(GroupAuthToken::from_str("1:2b::").is_err());
        assert!(GroupAuthToken::from_str("1a:2::").is_err());
        assert!(GroupAuthToken::from_str("1a2:2b:1:3c").is_err());
        assert!(GroupAuthToken::from_str("2:1:2b:::").is_err());
        assert!(GroupAuthToken::from_str("2:1a:2:::").is_err());

        // Error: Invalid character 'x' at position 1
        assert!(GroupAuthToken::from_str("1x:2b:1:").is_err());
        assert!(GroupAuthToken::from_str("1a:2x:1:").is_err());
        assert!(GroupAuthToken::from_str("2:1x:2b:1::").is_err());
        assert!(GroupAuthToken::from_str("2:1a:2x:1::").is_err());

        // Error: Unknown version
        assert!(GroupAuthToken::from_str(":1a:2b:1:2:3").is_err());
        assert!(GroupAuthToken::from_str("1:1a:2b:1:2:3").is_err());
        assert!(GroupAuthToken::from_str("3:1a:2b:1:2:3").is_err());

        let key = <[u8; 32]>::from_hex(AUTH_KEY_2).unwrap();

        let timestamp = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap();

        let password =
            generate_signed_v2_password(USER_ID_1, GROUP_ID_1, timestamp.as_secs(), "1", &key);

        // Save the password without the mac part.
        let (password_no_mac, _) = password
            .match_indices(':')
            .nth(4)
            .map(|(index, _)| password.split_at(index))
            .unwrap();

        // Make the mac not hex.
        let mac_not_hex = format!("{}:{}", password_no_mac, "not hex");
        let result = GroupAuthToken::from_str(&mac_not_hex);
        assert_eq!(result.err().unwrap().to_string(), "mac not hexadecimal");

        let password =
            generate_signed_v2_password(USER_ID_1, GROUP_ID_1, timestamp.as_secs(), "", &key);
        let result = GroupAuthToken::from_str(&password);
        assert!(result.is_err());

        let password =
            generate_signed_v2_password(USER_ID_1, GROUP_ID_1, timestamp.as_secs(), "11", &key);
        let result = GroupAuthToken::from_str(&password);
        assert!(result.is_err());
    }

    #[test]
    fn test_authenticate_bad_signature() {
        initialize_logging();

        let authenticator = Authenticator::from_hex_key(AUTH_KEY_1).unwrap();

        // Use a different key for this test.
        let key = <[u8; 32]>::from_hex(AUTH_KEY_2).unwrap();

        let timestamp = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap();

        let password =
            generate_signed_v2_password(USER_ID_1, GROUP_ID_1, timestamp.as_secs(), "1", &key);

        let result = authenticator.verify(GroupAuthToken::from_str(&password).unwrap(), &password);
        assert_eq!(result, Err(AuthenticatorError::BadSignature));

        // Save the password without the mac part.
        let (password_no_mac, _) = password
            .match_indices(':')
            .nth(4)
            .map(|(index, _)| password.split_at(index))
            .unwrap();

        // Make the mac garbage hex.
        let password = format!("{}:{}", password_no_mac, "deadbeefdeadbeef");
        let result = authenticator.verify(GroupAuthToken::from_str(&password).unwrap(), &password);
        assert_eq!(result, Err(AuthenticatorError::BadSignature));
    }

    fn get_signed_v2_password_for_duration(timestamp: Duration) -> String {
        initialize_logging();

        // A standard valid password with timestamp as the invariant.
        let key = <[u8; 32]>::from_hex(AUTH_KEY_1).unwrap();
        generate_signed_v2_password(USER_ID_1, GROUP_ID_1, timestamp.as_secs(), "1", &key)
    }

    #[test]
    fn test_authenticate_expired_credentials() {
        initialize_logging();

        let authenticator = Authenticator::from_hex_key(AUTH_KEY_1).unwrap();

        // dummy timestamp (no go).
        let password = get_signed_v2_password_for_duration(Duration::from_secs(1));
        let result = authenticator.verify(GroupAuthToken::from_str(&password).unwrap(), &password);
        assert_eq!(result, Err(AuthenticatorError::ExpiredCredentials));

        // 48 hour old timestamp (no go).
        let password = get_signed_v2_password_for_duration(
            SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .checked_sub(Duration::from_secs(60 * 60 * 48))
                .unwrap(),
        );
        let result = authenticator.verify(GroupAuthToken::from_str(&password).unwrap(), &password);
        assert_eq!(result, Err(AuthenticatorError::ExpiredCredentials));

        // 30 hour and 1 second old timestamp (no go).
        let password = get_signed_v2_password_for_duration(
            SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .checked_sub(Duration::from_secs(60 * 60 * 30 + 1))
                .unwrap(),
        );
        let result = authenticator.verify(GroupAuthToken::from_str(&password).unwrap(), &password);
        assert_eq!(result, Err(AuthenticatorError::ExpiredCredentials));

        // 30 hour old timestamp (no go).
        let password = get_signed_v2_password_for_duration(
            SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .checked_sub(Duration::from_secs(60 * 60 * 30))
                .unwrap(),
        );
        let result = authenticator.verify(GroupAuthToken::from_str(&password).unwrap(), &password);
        assert_eq!(result, Err(AuthenticatorError::ExpiredCredentials));

        // 30 hour less 1 second new timestamp (ok).
        let password = get_signed_v2_password_for_duration(
            SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .checked_sub(Duration::from_secs(60 * 60 * 30 - 1))
                .unwrap(),
        );
        let result = authenticator.verify(GroupAuthToken::from_str(&password).unwrap(), &password);
        assert!(result.is_ok());
        let user_authorization = result.unwrap();
        assert_eq!(user_authorization.user_id, USER_ID_1);
        assert_eq!(user_authorization.room_id, RoomId::from(GROUP_ID_1));
        assert_eq!(
            user_authorization.user_permission,
            UserPermission::CreateAndJoin
        );
    }

    #[test]
    fn test_authenticate_permission() {
        initialize_logging();

        let authenticator = Authenticator::from_hex_key(AUTH_KEY_1).unwrap();
        let key = <[u8; 32]>::from_hex(AUTH_KEY_1).unwrap();

        let timestamp = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap();

        let password =
            generate_signed_v2_password(USER_ID_1, GROUP_ID_1, timestamp.as_secs(), "0", &key);
        let result = authenticator.verify(GroupAuthToken::from_str(&password).unwrap(), &password);
        assert!(result.is_ok());
        let user_authorization = result.unwrap();
        assert_eq!(
            user_authorization.user_permission,
            UserPermission::JoinAlreadyCreated
        );
    }
}
