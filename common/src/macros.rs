//
// Copyright 2025 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only
//

#[macro_export]
macro_rules! rate_limit {
    ($quota:expr, $body:expr) => {
        static __RATE_LIMITER: once_cell::sync::Lazy<
            std::sync::Arc<
                governor::RateLimiter<
                    governor::state::NotKeyed,
                    governor::state::InMemoryState,
                    governor::clock::DefaultClock,
                    governor::middleware::NoOpMiddleware,
                >,
            >,
        > = once_cell::sync::Lazy::new(|| Arc::new(governor::RateLimiter::direct($quota)));

        if __RATE_LIMITER.check().is_ok() {
            $body
        }
    };
}
