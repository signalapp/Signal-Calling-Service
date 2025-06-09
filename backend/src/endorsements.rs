//
// Copyright 2025 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::{
    collections::{HashMap, HashSet},
    ops::Add,
    sync::Arc,
};

use calling_common::{Duration, SystemTime};
use itertools::Itertools;
use parking_lot::Mutex;
use rand::Rng;
use thiserror::Error;
use zkgroup::{
    groups::{GroupSendEndorsementsResponse, UuidCiphertext},
    EndorsementServerRootKeyPair, RandomnessBytes, Timestamp,
};

use crate::sfu::UserId;

/// Minimum amount of time between SendEndorsementUpdates
const ENDORSEMENT_DEBOUNCE_INTERVAL: Duration = Duration::from_millis(300);
/// How far ahead to rotate a call's send endorsements. Should never happen with Endorsement Refreshes
const ENDORSEMENT_ROTATE_AHEAD_INTERVAL: Duration = Duration::from_secs(60 * 60);

/// The serialized endorsement response and its expiration time.
pub type SerializedEndorsementResponse = (Vec<u8>, SystemTime);

/// Contains Endorsement response to send to clients
#[derive(Clone, Eq, PartialEq, Hash)]
pub struct EndorsementResponse {
    pub serialized: Vec<u8>,
    pub expiration: SystemTime,
    /// Member ciphertexts used to compute endorsements
    pub user_ids: Vec<UserId>,
}

#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum EndorsementIssuerError {
    #[error("Invalid expiration timestamp, expected post Unix Epoch timestamps")]
    PreEpochTimestamp,
}

/// Issues GroupSendEndorsements, caching key pairs. Issues endorsements with expirations
/// rounded up to the nearest day (aligned to 00:00:00). Automatically clears expired keys.
pub struct EndorsementIssuer {
    endorsement_server_root_key: EndorsementServerRootKeyPair,
    /// Minimum amount of time we want endorsements to be valid for. Has to be multiple of 24 hours
    endorsement_duration: Duration,
    /// Caches key pair for each unique expiration
    expiration_to_key_cache: HashMap<SystemTime, zkgroup::groups::GroupSendDerivedKeyPair>,
}

impl EndorsementIssuer {
    pub fn new(
        endorsement_server_root_key: EndorsementServerRootKeyPair,
        endorsement_duration: Duration,
    ) -> Self {
        Self {
            endorsement_server_root_key,
            endorsement_duration,
            expiration_to_key_cache: HashMap::new(),
        }
    }

    /// Computes endorsements. Creates and caches key pair if needed, cleans up expired key pairs.
    pub fn compute_endorsements(
        &mut self,
        member_ciphertexts: Vec<UuidCiphertext>,
        now: SystemTime,
    ) -> Result<Option<SerializedEndorsementResponse>, EndorsementIssuerError> {
        if now < SystemTime::UNIX_EPOCH {
            return Err(EndorsementIssuerError::PreEpochTimestamp);
        }
        if member_ciphertexts.is_empty() {
            return Ok(None);
        }

        let expiration = self.compute_expiration_time(now);
        self.clear_expired_keys(now);
        let endorsements = zkgroup::serialize(
            &self.compute_endorsements_with_expiration(member_ciphertexts, expiration),
        );
        Ok(Some((endorsements, expiration)))
    }

    fn compute_endorsements_with_expiration(
        &mut self,
        member_ciphertexts: Vec<UuidCiphertext>,
        expiration: SystemTime,
    ) -> GroupSendEndorsementsResponse {
        let rng = &mut rand::thread_rng();
        let randomness: RandomnessBytes = rng.gen();
        let key_pair = self
            .expiration_to_key_cache
            .entry(expiration)
            .or_insert_with(|| {
                Self::generate_key_pair(&self.endorsement_server_root_key, expiration)
            });
        GroupSendEndorsementsResponse::issue(member_ciphertexts, key_pair, randomness)
    }

    fn generate_key_pair(
        endorsement_server_root_key: &EndorsementServerRootKeyPair,
        expiration: SystemTime,
    ) -> zkgroup::groups::GroupSendDerivedKeyPair {
        let expiration = expiration.saturating_duration_since_epoch();
        zkgroup::groups::GroupSendDerivedKeyPair::for_expiration(
            Timestamp::from_epoch_seconds(expiration.as_secs()),
            endorsement_server_root_key,
        )
    }

    /// Computes an expiration time rounded up to the nearest day so that result.elapsed(now) >= term.
    fn compute_expiration_time(&self, now: SystemTime) -> SystemTime {
        let min = now.add(self.endorsement_duration);
        min.round_up_day().unwrap_or(min)
    }

    fn clear_expired_keys(&mut self, now: SystemTime) {
        self.expiration_to_key_cache
            .retain(|expiration, _| expiration > &now);
    }
}

/// Returned from CallEndorsementIssuer. Maps user ids to the correct endorsements they should receive.
#[derive(Clone, Default)]
pub struct CallSendEndorsements {
    full_endorsements: Option<EndorsementResponse>,
    diff_endorsements: Option<EndorsementResponse>,
    receive_full: HashSet<UserId>,
    receive_diff: HashSet<UserId>,
}

impl CallSendEndorsements {
    pub fn get_endorsements_for(&self, user_id: &UserId) -> Option<&EndorsementResponse> {
        if self.receive_full.contains(user_id) {
            self.full_endorsements.as_ref()
        } else if self.receive_diff.contains(user_id) {
            self.diff_endorsements.as_ref()
        } else {
            None
        }
    }
}

/// Tracks state for issuing endorsements for a call, generating a map of userIds to the endorsements
/// they should be sent. This also reissues ahead of expirations and debounce the rate of issuing
/// endorsements. Must be notified via [track_member_added] when members change.
pub struct CallEndorsementIssuer {
    /// Endorsement Issuer that contains secret material for issuing endorsements
    endorsement_issuer: Arc<Mutex<EndorsementIssuer>>,
    /// Minimum duration between issuing endorsements
    debounce_interval: Duration,
    /// Periodically send a full endorsement set on this interval
    refresh_interval: Option<Duration>,
    /// Rollover endorsements to a new expiration ahead of the current expiration
    rollover_ahead_interval: Option<Duration>,
    /// Last time endorsements were issued
    last_issued_ts: Option<SystemTime>,
    /// Expiration of last issue endorsements
    last_issued_expiration: Option<SystemTime>,
    /// Tracks whether members have changed since last endorsement issuance
    members_added: HashSet<UserId>,
}

impl CallEndorsementIssuer {
    pub fn new(endorsement_issuer: Arc<Mutex<EndorsementIssuer>>) -> Self {
        Self::new_with_intervals(
            endorsement_issuer,
            ENDORSEMENT_DEBOUNCE_INTERVAL,
            None,
            Some(ENDORSEMENT_ROTATE_AHEAD_INTERVAL),
        )
    }
    pub fn new_with_intervals(
        endorsement_issuer: Arc<Mutex<EndorsementIssuer>>,
        debounce_interval: Duration,
        refresh_interval: Option<Duration>,
        rollover_ahead_interval: Option<Duration>,
    ) -> Self {
        Self {
            endorsement_issuer,
            last_issued_ts: None,
            last_issued_expiration: None,
            members_added: HashSet::new(),
            debounce_interval,
            refresh_interval,
            rollover_ahead_interval,
        }
    }

    pub fn issue_endorsements(
        &mut self,
        members: Vec<(UserId, UuidCiphertext)>,
        now: SystemTime,
    ) -> Result<CallSendEndorsements, EndorsementIssuerError> {
        if members.is_empty() {
            return Ok(CallSendEndorsements::default());
        }

        let members = members
            .into_iter()
            .sorted_by(|(a, _), (b, _)| Ord::cmp(a, b))
            .dedup();
        let (full_user_ids, full_ciphertexts, receive_full, diff_ciphertexts, receive_diff) =
            if self.need_refresh(now) || self.need_rollover(now) {
                let (full_user_ids, full_ciphertexts): (Vec<_>, Vec<_>) = members.unzip();
                let receive_full = full_user_ids.iter().cloned().collect();
                (
                    full_user_ids,
                    full_ciphertexts,
                    receive_full,
                    vec![],
                    HashSet::new(),
                )
            } else {
                let mut full_user_ids = vec![];
                let mut full_ciphertexts = vec![];
                let mut diff_ciphertexts = vec![];
                let mut receive_full = HashSet::new();
                let mut receive_diff = HashSet::new();
                for (user_id, ciphertext) in members {
                    if self.members_added.contains(&user_id) {
                        // we cannot assume receive_full == members_added. We only issue endorsements for members
                        // currently in the call, so we find the intersection of current members and members_added
                        receive_full.insert(user_id.clone());
                        diff_ciphertexts.push(ciphertext);
                    } else {
                        receive_diff.insert(user_id.clone());
                    }

                    full_user_ids.push(user_id);
                    full_ciphertexts.push(ciphertext);
                }
                (
                    full_user_ids,
                    full_ciphertexts,
                    receive_full,
                    diff_ciphertexts,
                    receive_diff,
                )
            };

        let mut endorsement_issuer = self.endorsement_issuer.lock();
        let full_endorsements =
            endorsement_issuer.compute_endorsements(full_ciphertexts.to_vec(), now)?;

        let diff_endorsements =
            if self
                .last_issued_expiration
                .as_ref()
                .is_some_and(|old_expiration| {
                    full_endorsements
                        .as_ref()
                        .is_some_and(|(_, new_expiration)| new_expiration != old_expiration)
                })
            {
                full_endorsements.clone()
            } else {
                endorsement_issuer.compute_endorsements(diff_ciphertexts.to_vec(), now)?
            };

        self.last_issued_ts = Some(now);
        self.last_issued_expiration = full_endorsements
            .as_ref()
            .map(|(_, expiration)| *expiration);
        self.members_added.clear();
        Ok(CallSendEndorsements {
            full_endorsements: full_endorsements.map(|(serialized, expiration)| {
                EndorsementResponse {
                    serialized,
                    expiration,
                    user_ids: full_user_ids,
                }
            }),
            diff_endorsements: diff_endorsements.map(|(serialized, expiration)| {
                EndorsementResponse {
                    serialized,
                    expiration,
                    user_ids: receive_full.iter().cloned().collect(),
                }
            }),
            receive_full,
            receive_diff,
        })
    }

    /// Checks whether the endorsements need to refreshed due to impending expiration or new members
    /// joining, debouncing the reissue rate.
    pub fn need_reissue(&self, now: SystemTime) -> bool {
        self.need_refresh(now) || self.need_endorsement_update(now) || self.need_rollover(now)
    }

    /// Checks whether new members joined and the debounce interval has passed
    fn need_endorsement_update(&self, now: SystemTime) -> bool {
        !self.members_added.is_empty()
            && (self.last_issued_ts.is_none()
                || self.last_issued_ts.is_some_and(|last_ts| {
                    now.saturating_duration_since(last_ts) >= self.debounce_interval
                }))
    }

    /// Checks whether the last sent endorsements need to be refreshed before expiring.
    /// should never happen if with a regular endorsement refresh
    fn need_rollover(&self, now: SystemTime) -> bool {
        if let Some(rollover_ahead_interval) = self.rollover_ahead_interval {
            self.last_issued_expiration.is_some_and(|expiration| {
                expiration.saturating_duration_since(now) <= rollover_ahead_interval
            })
        } else {
            false
        }
    }

    /// Checks whether it's time to send a periodic full set of endorsements to all clients
    fn need_refresh(&self, now: SystemTime) -> bool {
        if let Some(refresh_interval) = self.refresh_interval {
            self.last_issued_ts.is_some_and(|last_issued_ts| {
                now.saturating_duration_since(last_issued_ts) >= refresh_interval
            })
        } else {
            false
        }
    }

    /// Should be called every time a new client becomes a call participant
    pub fn track_member_added(&mut self, user_id: UserId) {
        self.members_added.insert(user_id);
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::HashSet, sync::LazyLock};

    use calling_common::{Duration, SystemTime};
    use libsignal_core::Aci;
    use zkgroup::{
        call_links::CallLinkSecretParams,
        groups::{GroupSendEndorsementsResponse, UuidCiphertext},
        EndorsementPublicKey, EndorsementServerRootKeyPair, RandomnessBytes, ServerPublicParams,
        ServerSecretParams, Timestamp, RANDOMNESS_LEN, UUID_LEN,
    };

    use crate::{
        call::UserId,
        endorsements::{EndorsementIssuer, EndorsementIssuerError},
    };

    type CallLinkRootKey = [u8; 16];

    static RANDOMNESS: LazyLock<RandomnessBytes> = LazyLock::new(|| [0x44u8; RANDOMNESS_LEN]);
    static SERVER_SECRET_PARAMS: LazyLock<ServerSecretParams> =
        LazyLock::new(|| ServerSecretParams::generate(*RANDOMNESS));
    static ENDORSEMENT_SERVER_ROOT_KEY: LazyLock<EndorsementServerRootKeyPair> =
        LazyLock::new(|| SERVER_SECRET_PARAMS.get_endorsement_root_key_pair());
    static SERVER_PUBLIC_PARAMS: LazyLock<ServerPublicParams> =
        LazyLock::new(|| SERVER_SECRET_PARAMS.get_public_params());
    static ENDORSEMENT_PUBLIC_ROOT_KEY: LazyLock<EndorsementPublicKey> =
        LazyLock::new(|| SERVER_PUBLIC_PARAMS.get_endorsement_public_key());
    static MEMBER_IDS: LazyLock<Vec<Aci>> = LazyLock::new(|| {
        (1..=3)
            .map(|i| Aci::from_uuid_bytes([i; UUID_LEN]))
            .collect()
    });
    static CALL_LINK_ROOT_KEY: LazyLock<CallLinkRootKey> = LazyLock::new(|| [0x43u8; 16]);
    static CALL_LINK_SECRET_PARAMS: LazyLock<CallLinkSecretParams> =
        LazyLock::new(|| CallLinkSecretParams::derive_from_root_key(&*CALL_LINK_ROOT_KEY));
    static MEMBER_CIPHERTEXTS: LazyLock<Vec<UuidCiphertext>> = LazyLock::new(|| {
        MEMBER_IDS
            .iter()
            .map(|id| CALL_LINK_SECRET_PARAMS.encrypt_uid(*id))
            .collect::<Vec<_>>()
    });
    static MEMBER_USER_IDS: LazyLock<Vec<UserId>> = LazyLock::new(|| {
        MEMBER_CIPHERTEXTS
            .iter()
            .map(|id| id.try_into().unwrap())
            .collect::<Vec<_>>()
    });

    mod endorsement_issuer_tests {
        use super::*;

        #[test]
        fn test_clear_expired_keys() {
            let epoch = SystemTime::UNIX_EPOCH;
            let one_hour = Duration::from_secs(60 * 60);
            let one_day = 24 * one_hour;
            let nows: Vec<SystemTime> = (1..24).map(|i| epoch + (one_hour * i)).collect();
            let mut issuer = EndorsementIssuer::new(ENDORSEMENT_SERVER_ROOT_KEY.clone(), one_day);

            let mut expected_keys = HashSet::new();
            assert_eq!(
                issuer
                    .expiration_to_key_cache
                    .keys()
                    .cloned()
                    .collect::<HashSet<_>>(),
                expected_keys,
                "Cache is empty initially"
            );

            expected_keys.insert(epoch + one_day);
            assert!(issuer
                .compute_endorsements(MEMBER_CIPHERTEXTS.clone(), epoch)
                .is_ok());
            assert_eq!(
                issuer
                    .expiration_to_key_cache
                    .keys()
                    .cloned()
                    .collect::<HashSet<_>>(),
                expected_keys,
                "One key with one day expiration should be created"
            );

            expected_keys.insert(epoch + (2 * one_day));
            for now in nows.into_iter() {
                assert!(issuer
                    .compute_endorsements(MEMBER_CIPHERTEXTS.clone(), now)
                    .is_ok());

                assert_eq!(
                    issuer
                        .expiration_to_key_cache
                        .keys()
                        .cloned()
                        .collect::<HashSet<_>>(),
                    expected_keys,
                    "One should be created, first one remains cached",
                );
            }

            expected_keys.remove(&(epoch + one_day));
            assert!(issuer
                .compute_endorsements(MEMBER_CIPHERTEXTS.clone(), epoch + one_day)
                .is_ok());
            assert_eq!(
                issuer
                    .expiration_to_key_cache
                    .keys()
                    .cloned()
                    .collect::<HashSet<_>>(),
                expected_keys,
                "First key expires, second key should be used"
            );

            let expirations = (2..10).map(|i| epoch + (i * one_day)).collect::<Vec<_>>();
            for expiration in expirations.into_iter() {
                assert!(issuer
                    .compute_endorsements(MEMBER_CIPHERTEXTS.clone(), expiration)
                    .is_ok());
                assert_eq!(
                    issuer
                        .expiration_to_key_cache
                        .keys()
                        .cloned()
                        .collect::<HashSet<_>>(),
                    HashSet::from([expiration + one_day]),
                    "One key should expire for every new key added"
                );
            }
        }

        #[test]
        fn test_invalid_now() {
            let one_day = Duration::from_secs(24 * 60 * 60);
            let invalid_now = SystemTime::UNIX_EPOCH - Duration::from_secs(1);
            let mut issuer = EndorsementIssuer::new(ENDORSEMENT_SERVER_ROOT_KEY.clone(), one_day);

            let result = issuer.compute_endorsements(MEMBER_CIPHERTEXTS.clone(), invalid_now);
            assert!(result.is_err());
            assert_eq!(
                EndorsementIssuerError::PreEpochTimestamp,
                result.unwrap_err()
            );
        }

        #[test]
        fn test_endorsements_issued_correctly() {
            fn validate_key_correctly_used(
                now: SystemTime,
                expected_expiration: SystemTime,
                issuer: &mut EndorsementIssuer,
            ) {
                let now_ts =
                    Timestamp::from_epoch_seconds(now.saturating_duration_since_epoch().as_secs());
                let expected_expiration_ts = Timestamp::from_epoch_seconds(
                    expected_expiration
                        .saturating_duration_since_epoch()
                        .as_secs(),
                );
                let expected_todays_key = zkgroup::groups::GroupSendDerivedKeyPair::for_expiration(
                    expected_expiration_ts,
                    &*ENDORSEMENT_SERVER_ROOT_KEY,
                );
                let (endorsements, expiration) = issuer
                    .compute_endorsements(MEMBER_CIPHERTEXTS.clone(), now)
                    .unwrap()
                    .unwrap();
                assert_eq!(expected_expiration, expiration);
                assert!(
                    issuer
                        .expiration_to_key_cache
                        .contains_key(&expected_expiration),
                    "Should contain key for creating endorsements with a specific expiration"
                );
                assert_eq!(
                    zkgroup::serialize(&issuer.expiration_to_key_cache[&expected_expiration]),
                    zkgroup::serialize(&expected_todays_key),
                    "Should generate expected key for specific expiration"
                );

                let (_, expiration) = issuer
                    .compute_endorsements(MEMBER_CIPHERTEXTS.clone(), now)
                    .unwrap()
                    .unwrap();
                assert_eq!(expected_expiration, expiration,"expect matching expiration, endorsements have randomness injected and won't match");

                let endorsements_response: GroupSendEndorsementsResponse =
                    zkgroup::deserialize(&endorsements).expect("Issued valid serialized response");
                let received_expiration = endorsements_response.expiration();
                assert_eq!(
                    endorsements_response.expiration(),
                    Timestamp::from_epoch_seconds(
                        expected_expiration
                            .saturating_duration_since_epoch()
                            .as_secs()
                    )
                );

                let endorsements = endorsements_response
                    .receive_with_ciphertexts(
                        MEMBER_CIPHERTEXTS.clone(),
                        now_ts,
                        &*ENDORSEMENT_PUBLIC_ROOT_KEY,
                    )
                    .expect("serialized endorsement response contained ciphertexts")
                    .into_iter()
                    .map(|received| received.decompressed)
                    .collect::<Vec<_>>();
                assert_eq!(endorsements.len(), MEMBER_CIPHERTEXTS.len());

                let combined_endorsements =
                    zkgroup::groups::GroupSendEndorsement::combine(endorsements.clone())
                        .remove(&endorsements[0]);

                let token = combined_endorsements
                    .to_token(*CALL_LINK_SECRET_PARAMS)
                    .into_full_token(received_expiration);

                // server verification of the credential presentation
                assert_eq!(token.expiration(), expected_expiration_ts);
                token
                    .verify(
                        MEMBER_IDS.iter().skip(1).map(|id| (*id).into()),
                        expected_expiration_ts,
                        &expected_todays_key,
                    )
                    .expect("credential should be valid for the timestamp given");
            }

            let epoch = SystemTime::UNIX_EPOCH;
            let one_hour = Duration::from_secs(60 * 60);
            let one_day = 24 * one_hour;
            let nows: Vec<SystemTime> =
                (4..24).step_by(4).map(|i| epoch + (one_hour * i)).collect();
            let mut issuer = EndorsementIssuer::new(ENDORSEMENT_SERVER_ROOT_KEY.clone(), one_day);

            let expected_expiration = epoch + one_day;
            validate_key_correctly_used(epoch, expected_expiration, &mut issuer);

            let expected_expiration = epoch + (2 * one_day);
            for now in nows.into_iter() {
                validate_key_correctly_used(now, expected_expiration, &mut issuer);
            }

            let nows: Vec<SystemTime> = (3..5).map(|i| epoch + (i * one_day)).collect();
            let expirations = nows.iter().map(|&now| now + one_day).collect::<Vec<_>>();
            for (now, expected_expiration) in nows.into_iter().zip(expirations) {
                validate_key_correctly_used(now, expected_expiration, &mut issuer);
            }
        }
    }

    mod call_issuer_tests {
        use std::sync::Arc;

        use parking_lot::Mutex;
        use zkgroup::groups::GroupSendEndorsement;

        use super::*;
        use crate::endorsements::{
            CallEndorsementIssuer, CallSendEndorsements, EndorsementResponse,
        };

        #[test]
        fn test_call_endorsement_issued_correctly() {
            /// endorsements are not sorted and cannot be sorted
            /// this handles comparing two slices
            fn assert_eq_endorsements(
                left: &Option<Vec<GroupSendEndorsement>>,
                right: &Option<Vec<GroupSendEndorsement>>,
            ) {
                assert_eq!(left.is_some(), right.is_some());

                let left = left.as_ref().unwrap();
                let right = right.as_ref().unwrap();
                for l in left {
                    assert!(right.contains(l), "Could not find endorsement");
                }
                for r in right {
                    assert!(left.contains(r), "Could not find endorsement");
                }
            }

            fn endorsements_for(
                member_ciphertexts: &[UuidCiphertext],
                now: SystemTime,
            ) -> Option<Vec<zkgroup::api::groups::GroupSendEndorsement>> {
                let mut issuer = EndorsementIssuer::new(
                    SERVER_SECRET_PARAMS.get_endorsement_root_key_pair(),
                    Duration::from_secs(24 * 60 * 60),
                );
                issuer
                    .compute_endorsements(member_ciphertexts.to_vec(), now)
                    .unwrap()
                    .map(|(serialized, _)| {
                        let response: GroupSendEndorsementsResponse =
                            zkgroup::deserialize(&serialized)
                                .expect("Issued valid serialized response");
                        let now_ts = Timestamp::from_epoch_seconds(
                            now.saturating_duration_since_epoch().as_secs(),
                        );
                        response
                            .receive_with_ciphertexts(
                                member_ciphertexts.to_vec(),
                                now_ts,
                                &*ENDORSEMENT_PUBLIC_ROOT_KEY,
                            )
                            .unwrap()
                            .into_iter()
                            .map(|received| received.decompressed)
                            .collect()
                    })
            }

            fn unwrap_call_endorsements(
                endorsements: Option<&EndorsementResponse>,
                now_ts: Timestamp,
            ) -> Option<Vec<GroupSendEndorsement>> {
                endorsements.map(|endorsements| {
                    let ciphertexts = endorsements
                        .user_ids
                        .iter()
                        .map(TryInto::try_into)
                        .map(Result::unwrap)
                        .collect::<Vec<_>>();
                    let response: GroupSendEndorsementsResponse =
                        zkgroup::deserialize(&endorsements.serialized).unwrap();
                    response
                        .receive_with_ciphertexts(
                            ciphertexts,
                            now_ts,
                            &*ENDORSEMENT_PUBLIC_ROOT_KEY,
                        )
                        .unwrap()
                        .iter()
                        .map(|received| received.decompressed)
                        .collect()
                })
            }

            fn validate_endorsements(
                now: SystemTime,
                endorsements: CallSendEndorsements,
                diff_receivers: Vec<&UserId>,
                full_receivers: Vec<&UserId>,
                expected_diff_endorsements: Option<Vec<GroupSendEndorsement>>,
                expected_full_endorsements: Option<Vec<GroupSendEndorsement>>,
            ) {
                let now_ts =
                    Timestamp::from_epoch_seconds(now.saturating_duration_since_epoch().as_secs());
                for user_id in diff_receivers {
                    let actual_endorsements = unwrap_call_endorsements(
                        endorsements.get_endorsements_for(user_id),
                        now_ts,
                    );
                    assert_eq_endorsements(&expected_diff_endorsements, &actual_endorsements);
                }
                for user_id in full_receivers {
                    let actual_endorsements = unwrap_call_endorsements(
                        endorsements.get_endorsements_for(user_id),
                        now_ts,
                    );
                    assert_eq_endorsements(&expected_full_endorsements, &actual_endorsements);
                }
            }

            let debounce = Duration::from_millis(500);
            let refresh = Duration::from_millis(10_000);
            let one_hour = Duration::from_secs(60 * 60);
            let one_day = 24 * one_hour;
            let issuer = EndorsementIssuer::new(
                SERVER_SECRET_PARAMS.get_endorsement_root_key_pair(),
                one_day,
            );
            let mut issuer = CallEndorsementIssuer::new_with_intervals(
                Arc::new(Mutex::new(issuer)),
                debounce,
                Some(refresh),
                None,
            );

            let now = SystemTime::UNIX_EPOCH;
            assert!(!issuer.need_reissue(now), "no new members, do not reissue");

            let mut user_ids = vec![MEMBER_USER_IDS[0].clone()];
            let mut member_ciphertexts = vec![MEMBER_CIPHERTEXTS[0]];
            let members: Vec<(UserId, UuidCiphertext)> = user_ids
                .iter()
                .cloned()
                .zip(member_ciphertexts.clone())
                .collect();
            issuer.track_member_added(MEMBER_USER_IDS[0].clone());
            assert!(
                issuer.need_reissue(now),
                "new member, no recent issues, should reissue"
            );
            let call_endorsements = issuer.issue_endorsements(members.clone(), now).unwrap();
            validate_endorsements(
                now,
                call_endorsements,
                vec![],
                vec![&MEMBER_USER_IDS[0]],
                None,
                endorsements_for(&member_ciphertexts, now),
            );
            assert!(
                !issuer.need_reissue(now),
                "issuing clears new member tracker, do not reissue"
            );

            user_ids.push(MEMBER_USER_IDS[1].clone());
            member_ciphertexts.push(MEMBER_CIPHERTEXTS[1]);
            let members: Vec<(UserId, UuidCiphertext)> = user_ids
                .iter()
                .cloned()
                .zip(member_ciphertexts.clone())
                .collect();
            issuer.track_member_added(user_ids[1].clone());
            let now = now + (debounce.saturating_sub(Duration::from_millis(1)));
            assert!(
                !issuer.need_reissue(now),
                "new members, but within debounce interval, do not reissue"
            );

            let now = now + Duration::from_millis(1);
            assert!(
                issuer.need_reissue(now),
                "new member, outside debounce interval, should reissue"
            );
            let call_endorsements = issuer.issue_endorsements(members.clone(), now).unwrap();
            validate_endorsements(
                now,
                call_endorsements,
                vec![&user_ids[0]],
                vec![&user_ids[1]],
                endorsements_for(&member_ciphertexts[1..], now),
                endorsements_for(&member_ciphertexts, now),
            );

            let now = now + (refresh.saturating_sub(Duration::from_millis(1)));
            assert!(
                !issuer.need_reissue(now),
                "no new members, within refresh interval, do not reissue"
            );
            let now = now + Duration::from_millis(1);
            assert!(
                issuer.need_reissue(now),
                "refresh interval passed, should reissue"
            );

            let call_endorsements = issuer.issue_endorsements(members.clone(), now).unwrap();
            validate_endorsements(
                now,
                call_endorsements,
                vec![],
                user_ids.iter().collect(),
                None,
                endorsements_for(&member_ciphertexts, now),
            );

            // create issuer with no refresh, no debounce
            let rollover = Duration::from_secs(60 * 60);
            let issuer = EndorsementIssuer::new(
                SERVER_SECRET_PARAMS.get_endorsement_root_key_pair(),
                one_day,
            );
            let mut issuer = CallEndorsementIssuer::new_with_intervals(
                Arc::new(Mutex::new(issuer)),
                Duration::from_secs(0),
                None,
                Some(rollover),
            );

            let now = SystemTime::UNIX_EPOCH;
            issuer.track_member_added(MEMBER_USER_IDS[0].clone());
            issuer.track_member_added(MEMBER_USER_IDS[1].clone());
            let endorsements = issuer.issue_endorsements(members.clone(), now).unwrap();
            let EndorsementResponse { expiration, .. } = endorsements
                .get_endorsements_for(&MEMBER_USER_IDS[0])
                .unwrap();

            let now = *expiration - rollover - Duration::from_millis(1);
            assert!(
                !issuer.need_reissue(now),
                "outside rotate interval, do not reissue"
            );
            let now = *expiration + Duration::from_millis(1);
            assert!(
                issuer.need_reissue(now),
                "inside rotate interval, should reissue"
            );
            let call_endorsements = issuer.issue_endorsements(members.clone(), now).unwrap();
            validate_endorsements(
                now,
                call_endorsements,
                vec![],
                user_ids.iter().collect(),
                None,
                endorsements_for(&member_ciphertexts, now),
            );
        }
    }
}
