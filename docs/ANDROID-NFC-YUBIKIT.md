# Android NFC: YubiKit integration changes and test report

Test date: November 17, 2026 (PST; saved UTC timestamps fall on November 18).

## Summary

PQ Mail continues to use **YubiKit Android 3.3.0 without a patched SDK or a YubiKit fork**. The fixes are in PQ Mail's lifecycle handling, smart-card connection wrapper and PIV backend. They apply to the common backend used by S/MIME and OpenPGP; the latest physical NFC validation was S/MIME, not OpenPGP.

On Pixel 10 / Android 17 with PQC Ready YubiKey Beta0 firmware, an earlier build completed three consecutive ten-cycle Level 5 public-read checks, followed by pure and hybrid NFC signing/decryption round trips. These establish successful operation on this setup, not a proven root cause for every earlier transport failure.

## Observed failures and controls

Failures occurred before PIN submission during PIV SELECT, serial reads, large public-key metadata reads (`F7`), and GET RESPONSE (`C0`). Examples included Android `IOException: Transceive failed` and unexpected statuses `C403` and `4190`. We have not established authoritative meanings or a firmware cause for those two statuses. They are not treated as PIN errors or successful responses.

An early `6A82` SELECT failure was traced to a comparison key with PIV disabled over NFC. Selecting the identity for a different serial also correctly failed. Those configuration cases are distinct from intermittent transport failures with matching identities and NFC PIV enabled.

Level 3 pure and hybrid USB S/MIME controls each passed twice. The tester also reported three successful PIV reads in Yubico Authenticator 7.5.0. Authenticator's private results were not available for independent inspection, and its reads were not the same ten-cycle PQ metadata workload. A second Beta0 key at Level 5 reproduced intermittent failures, so changing keys alone did not resolve them; it also changed key sizes/profile, limiting direct comparison.

## Changes around YubiKit

| Area | Previous behavior / finding | Final application-side change |
|---|---|---|
| Foreground discovery | PQ Mail used skipped NDEF checks and a 15-second timeout. | Align discovery settings with the inspected Authenticator 7.5.0 integration: normal NDEF checking and a 5-second timeout. Keep discovery tied to activity resume/pause. This alignment alone did not eliminate failures. |
| Fresh taps and removal | Detected tags could arrive outside an active request; transitions did not explicitly await physical removal. | Accept NFC devices only while waiting, track the active device, call YubiKit `remove`, and await removal before the next request. Cancel pending requests on pause; serialize end-of-operation cleanup before accepting another operation. |
| PIN flow and recovery | A failed setup could leave the user repeating the entire operation. | Collect PIN before the tap. Offer at most two user-confirmed fresh-tap retries for NFC transport failures during read-only setup, rechecking serial and all bound keys each time. Retain the entered PIN only for that operation and clear it on termination. Never retry VERIFY or a private-key command automatically. |
| Response continuation | YubiKit's `ChainedResponseProcessor` emits short GET RESPONSE with Le=0, including after `61xx` with a nonzero SW2. | The wrapper honors the preceding `61xx` remaining length. The latest update also caps short NFC F7 metadata requests and their C0 continuations at 240 data bytes, including when `6100` advertises at least 256. USB and private-operation responses retain their existing behavior. YubiKit still assembles the response chain. |
| Framing and diagnostics | Last-command status alone gave insufficient context for large chained responses. | Reject responses shorter than two status bytes. Preserve unknown statuses for YubiKit to reject. Keep eight header/length/status/timing records, including GET RESPONSE Le; never record APDU payloads, PINs or private-key material. Malformed framing is not classified as a retryable transport failure. |
| Diagnostic session | Each of ten cycles reinitialized PIV; development-firmware resolution also switched through Management each time. | Open PIV once, then perform ten serial and bound-public-key read cycles on that session. This removes artificial applet switching while retaining repeated real public reads. It is a different stress workload from the earlier diagnostic. |
| Backend metadata | After verifying all bound public keys, authorization downloaded the selected slot's entire metadata again after VERIFY solely to obtain its key type. | Retain the verified key type only for the current connection. Use it after VERIFY without another large metadata download. Clear it when closing the connection; re-read and compare all bound keys on every new connection. |
| Saved history | Per-profile results could obscure an earlier pass with a later failure. | Retain bounded timestamped test history, add the PIN-free connection diagnostic, and persist up to 50 pre-PIN transport-failure records before recovery. Public-read reports identify the expected serial; successful checks verify the actual serial. |

### Existing Beta firmware adaptation

`PivSessions` already resolves a development firmware version by opening Management on the same connection and allowing YubiKit's `SessionVersionOverride` to receive the device's version qualifier, then reselecting PIV. It clears the global override in a synchronized/finally scope and does not hard-code a production version. This was retained, not introduced by the final NFC fixes. The diagnostic now performs it once per connection.

### What the framing change proves—and does not prove

Before the change, GET RESPONSE Le=0 requested the maximum short response regardless of the advertised remaining length. Requesting that maximum is not, by itself, proof that the SDK violated the protocol. Using the advertised length is an application compatibility measure pending broader testing.

The physical trace now shows `6132`, followed by `GET RESPONSE Le=50`, followed by 52 response bytes (50 data + `9000`). This proves the change is active. No `4190` or `C403` was recorded in the subsequent checked runs, but the limited sample does not prove those statuses were caused by Le handling. Do not reinterpret unexpected status bytes as payload or replay a continuation after a transport error: the card's response state may already have advanced.

## Validation

| Stage | Saved result |
|---|---|
| Second key, before continuation change | One ten-cycle pass and two failures, including `4190` on GET RESPONSE. |
| After continuation change | Two ten-cycle passes; one transport failure after four cycles on the initial public-key metadata command. |
| After one-session diagnostic / redundant-read removal | Three consecutive Level 5 public-read passes, ten cycles and 200 APDUs each: 600 exchanges total. |
| Earlier Level 5 pure NFC S/MIME | ML-DSA-87 signature verified; ML-KEM-1024 message decrypted. Both operations used NFC. |
| Earlier Level 5 hybrid NFC S/MIME | MLDSA87-ECDSA-P384-SHA512 signature verified; MLKEM1024-ECDH-P384-SHA3-256 message decrypted. Both operations used NFC. |

Those successful checks were saved at 03:50:49, 03:51:08 and 03:51:22 UTC on November 18; pure and hybrid round trips at 03:52:55 and 03:53:35 UTC. The tests sent no email and changed no token keys. Raw device histories remain local and are not included in this repository.

Twenty-two focused emulator instrumentation tests passed on the latest build, covering the real YubiKit protocol against simulated cards, all three profiles, S/MIME and OpenPGP backend operations, PIN cleanup, serial/key mismatch rejection, bounded pre-PIN recovery, no retry after VERIFY/private-command failures, large chained public reads requiring advertised continuation lengths, malformed responses, fresh-device gating, and UI startup. Additional tests prove one PIV initialization with repeated public reads, no redundant metadata after VERIFY, and rejection of a changed key after reconnecting. Emulator tests do not simulate RF reliability.

The three earlier public-read runs cannot be directly compared as an identical workload with the old 290-APDU diagnostic: the new test removes repeated management/PIV initialization and uses 200 APDUs. More devices, repeated cold taps and longer use are needed before claiming general NFC reliability. The latest Level 3 phone comparison is recorded below.

## Follow-up: 7E84 and response-size limit

A subsequent Level 3 hybrid run returned 253 bytes from a public-key continuation, ending in `7E84`. The saved public ML-DSA-65 key contains those bytes at exactly the position expected if that metadata chunk were truncated to 253 bytes: metadata offsets 507–508, after the first 256-byte chunk. The metadata layout totals 1970 bytes (1952 public-key bytes plus 18 bytes of TLV prefix). Thus both response length and trailing bytes match a truncation hypothesis. Because full response payloads were deliberately not logged, this does not prove the truncation layer or cause.

The application now requests at most 240 data bytes for short NFC F7 metadata commands and their C0 continuation chain (242 including status), still honoring smaller advertised remaining lengths. It never repairs missing bytes, interprets an unknown status as success, or replays an ambiguous continuation. USB and private-operation response sizes are unchanged.

A regression test models a transport truncating responses larger than 253 bytes. An unrestricted read fails; capped reads complete ten cycles for all three profiles. Other tests verify USB/private responses are unchanged, command buffers are not mutated, unknown statuses including `7E84` fail closed, and retry records persist without exception payloads. The test is a model of the observed symptom, not a reproduction of the physical NFC stack.

Pixel 10 traces confirm the key honors `Le=240` with 242-byte responses, but transport failures still occurred during continuation, small metadata reads and management reads. Smaller public responses therefore did not resolve Pixel 10 reliability.

## Pixel 9 versus Pixel 10: same APK and Level 3 key

Both phones ran Android 17. The same debug APK was installed on Pixel 9 and verified by SHA-256 against the Pixel 10 build. The same Level 3 key and four public certificates were used; only public certificates and serial/slot mappings were copied. No private keys, PINs or trust decisions were copied.

| Saved comparison batch | Pixel 9 | Pixel 10 |
|---|---|---|
| Completed NFC S/MIME round trips | 5: three hybrid, two pure | 1 hybrid |
| Failed round trips | 0 | 3 hybrid |
| Logged pre-PIN setup failures | 0 | 7 |

Pixel 9 hybrid passes were saved at 04:21:06, 04:21:29 and 04:21:52 UTC on November 18; pure passes at 04:22:27 and 04:22:46 UTC (8:21–8:22 PM PST on November 17). Every signature verified and every message decrypted over NFC. No PIN-free diagnostic records or retry-history file existed on this fresh installation after the runs; the recorded checks were full round trips, not public-read-only tests.

Pixel 10's same-build batch ran at 04:15:25–04:16:54 UTC. One hybrid round trip passed after recovery, two failed during signing, and one failed during decryption setup. Seven saved pre-PIN failures covered F7 metadata, C0 continuation, and 1D management commands, mostly around 300 ms. Two final signing failures contain only `Transceive failed`, without post-PIN command details. The retry log deliberately covers pre-PIN setup; it does not explain those two failures. No new PIN-free diagnostic checks were saved in this Pixel 10 batch either.

The difference supports investigating a phone-dependent NFC interaction rather than assuming the key or app always fails. It does not isolate antenna coupling, controller/firmware, Android behavior, or physical positioning, and the small unequal samples are not statistically meaningful failure-rate estimates. Successful round trips do not persist response-size traces, so Pixel 9's exact physical response sizes cannot be independently read from those success reports. The same APK contains the response-size cap, and Pixel 10 traces demonstrate the key honors it.

### Persistent retry diagnostics

`NfcRetryHistory` writes at most 50 entries to app-private preferences. Each includes time, expected serial, profile, operation, attempt number, a pre-PIN marker, and safe stage/frame metadata. The latest failed transport frame is retained alongside preceding frame summaries. PINs, command/response payloads, and arbitrary exception messages are excluded. The backend records a failure before offering recovery, including the final exhausted attempt, so later success cannot erase its evidence. The record identifies a failed attempt, not proof that the user accepted a retry; cancellation can follow it. Existing limits of two user-confirmed fresh-tap retries remain unchanged, and no VERIFY/private operation is automatically retried.

## Source and possible upstream follow-up

Application implementation:

- [MainActivity](../android/app/src/main/java/dev/hybridmail/MainActivity.java): discovery, removal, prompts and saved history.
- [FreshDeviceGate](../android/app/src/main/java/dev/hybridmail/FreshDeviceGate.java): active request handoff.
- [PivDiagnostic](../android/app/src/main/java/dev/hybridmail/PivDiagnostic.java): NFC continuation adjustment and payload-free diagnostics.
- [NfcRetryHistory](../android/app/src/main/java/dev/hybridmail/NfcRetryHistory.java): bounded, app-private intermediate failure persistence.
- [PivReadTest](../android/app/src/main/java/dev/hybridmail/PivReadTest.java): repeated public reads in one session.
- [YubiBackend](../android/app/src/main/java/dev/hybridmail/YubiBackend.java): connection-scoped key checks, metadata reuse and bounded recovery.
- [PivSessions](../android/app/src/main/java/dev/hybridmail/PivSessions.java): development-firmware resolution.
- [NfcFramingTest](../android/app/src/androidTest/java/dev/hybridmail/NfcFramingTest.java) and [YubiBackendTest](../android/app/src/androidTest/java/dev/hybridmail/YubiBackendTest.java): protocol regression tests.

Inspected upstream references: [YubiKit Android 3.3.0](https://github.com/Yubico/yubikit-android/tree/3.3.0), specifically SmartCardProtocol, ChainedResponseProcessor, ShortApduFormatter, NfcYubiKeyDevice and NfcSmartCardConnection; and [Yubico Authenticator 7.5.0](https://github.com/Yubico/yubioath-flutter/tree/7.5.0), commit `626875a2265818c8eb47b62afe65cae7ebabd27b`.

A useful upstream discussion would ask whether GET RESPONSE should use the advertised SW2 and whether the SDK should offer explicit malformed-response validation and privacy-preserving chain diagnostics. A controlled minimal reproducer would be needed to attribute the remaining historical transceive errors to Android, firmware or SDK behavior. No upstream bug or pull request is claimed here; most changes belong in application lifecycle and operation handling rather than YubiKit itself.
