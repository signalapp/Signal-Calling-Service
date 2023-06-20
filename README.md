# Calling Service

## Backend

Media forwarding server for group calls. Forwards media from 1 to N devices.

## Frontend

Signaling server for group calls that helps direct client requests to appropriate backends.

# Contributing

Signal does accept external contributions to this project. However, unless the change is
simple and easily understood, for example fixing a bug, adding a new test, or improving performance,
first open an issue to discuss your intended change as not all changes can be accepted.

Contributions that will not be used directly by one of Signal's official client apps may still be
considered, but only if they do not pose an undue maintenance burden or conflict with the goals of
the project.

Signing a [CLA (Contributor License Agreement)](https://signal.org/cla/) is required for all contributions.

# Thanks

We thank WebRTC for the "googcc" congestion control algorithm (see googcc.rs for more details).

We thank Ilana Volfin, Israel Cohen, and Jitsi for the "Dominant Speaker Identification" algorithm (see audio.rs for more details).

# Legal things
## Cryptography Notice

This distribution includes cryptographic software. The country in which you currently reside may have restrictions on the import, possession, use, and/or re-export to another country, of encryption software. BEFORE using any encryption software, please check your country's laws, regulations and policies concerning the import, possession, or use, and re-export of encryption software, to see if this is permitted.  See <http://www.wassenaar.org/> for more information.

The U.S. Government Department of Commerce, Bureau of Industry and Security (BIS), has classified this software as Export Commodity Control Number (ECCN) 5D002.C.1, which includes information security software using or performing cryptographic functions with asymmetric algorithms. The form and manner of this distribution makes it eligible for export under the License Exception ENC Technology Software Unrestricted (TSU) exception (see the BIS Export Administration Regulations, Section 740.13) for both object code and source code.

## License

Copyright 2019-2022 Signal Messenger, LLC<br/>

Licensed under [AGPLv3](https://www.gnu.org/licenses/agpl-3.0.html) only.
