# isideload 0.4.6, patched for appman

Upstream: https://github.com/nab138/isideload (MIT, see Cargo.toml). One change:

`src/anisette/mod.rs`, `AnisetteData::needs_refresh` now always returns true. Upstream reused anisette data
for 60 seconds, but the data carries a one-time password, and Apple's GrandSlam answers a replayed one with
HTTP 503. A sign-in that needs 2FA logs in twice (before and after the code), so when the code is typed within
a minute the second login replays the first one's OTP and fails with 503 "Service Temporarily Unavailable".
