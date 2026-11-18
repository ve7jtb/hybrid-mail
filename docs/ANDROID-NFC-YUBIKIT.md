# Android NFC: YubiKit integration changes and test report

Test date: November 17, 2026 (PST; saved UTC timestamps fall on November 18).

## Summary

PQ Mail continues to use **YubiKit Android 3.3.0 without a patched SDK or a YubiKit fork**. The fixes are in PQ Mail's lifecycle handling, smart-card connection wrapper and PIV backend. They apply to the common backend used by S/MIME and OpenPGP; the latest physical NFC validation was S/MIME, not OpenPGP.

On Pixel 10 / Android 17 with PQC Ready YubiKey Beta0 firmware, the final build completed three consecutive ten-cycle Level 5 public-read checks, followed by pure and hybrid NFC signing/decryption round trips. These establish successful operation on this setup, not a proven root cause for every earlier transport failure.

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
| Response continuation | YubiKit's `ChainedResponseProcessor` emits short GET RESPONSE with Le=0, including after `61xx` with a nonzero SW2. | The NFC connection wrapper substitutes the immediately preceding `61xx` SW2 as Le for the standard five-byte GET RESPONSE. `6100` remains Le=0. USB and other APDUs remain unchanged. YubiKit still assembles the response chain. |
| Framing and diagnostics | Last-command status alone gave insufficient context for large chained responses. | Reject responses shorter than two status bytes. Preserve unknown statuses for YubiKit to reject. Keep eight header/length/status/timing records, including GET RESPONSE Le; never record APDU payloads, PINs or private-key material. Malformed framing is not classified as a retryable transport failure. |
| Diagnostic session | Each of ten cycles reinitialized PIV; development-firmware resolution also switched through Management each time. | Open PIV once, then perform ten serial and bound-public-key read cycles on that session. This removes artificial applet switching while retaining repeated real public reads. It is a different stress workload from the earlier diagnostic. |
| Backend metadata | After verifying all bound public keys, authorization downloaded the selected slot's entire metadata again after VERIFY solely to obtain its key type. | Retain the verified key type only for the current connection. Use it after VERIFY without another large metadata download. Clear it when closing the connection; re-read and compare all bound keys on every new connection. |
| Saved history | Per-profile results could obscure an earlier pass with a later failure. | Retain bounded timestamped test history and add the PIN-free connection diagnostic. Public-read reports identify the expected serial; successful checks verify the actual serial. |

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
| Final pure NFC S/MIME | ML-DSA-87 signature verified; ML-KEM-1024 message decrypted. Both operations used NFC. |
| Final hybrid NFC S/MIME | MLDSA87-ECDSA-P384-SHA512 signature verified; MLKEM1024-ECDH-P384-SHA3-256 message decrypted. Both operations used NFC. |

Final successful checks were saved at 03:50:49, 03:51:08 and 03:51:22 UTC on November 18; pure and hybrid round trips at 03:52:55 and 03:53:35 UTC. The tests sent no email and changed no token keys. Raw device histories remain local and are not included in this repository.

Eighteen focused emulator instrumentation tests passed, covering the real YubiKit protocol against simulated cards, all three profiles, S/MIME and OpenPGP backend operations, PIN cleanup, serial/key mismatch rejection, bounded pre-PIN recovery, no retry after VERIFY/private-command failures, large chained public reads requiring advertised continuation lengths, malformed responses, fresh-device gating, and UI startup. Additional tests prove one PIV initialization with repeated public reads, no redundant metadata after VERIFY, and rejection of a changed key after reconnecting. Emulator tests do not simulate RF reliability.

The three final public-read runs cannot be directly compared as an identical workload with the old 290-APDU diagnostic: the new test removes repeated management/PIV initialization and uses 200 APDUs. More devices, repeated cold taps and longer use are needed before claiming general NFC reliability. Level 3 should also be retested on the final build; earlier successes used earlier builds.

## Source and possible upstream follow-up

Application implementation:

- [MainActivity](../android/app/src/main/java/dev/hybridmail/MainActivity.java): discovery, removal, prompts and saved history.
- [FreshDeviceGate](../android/app/src/main/java/dev/hybridmail/FreshDeviceGate.java): active request handoff.
- [PivDiagnostic](../android/app/src/main/java/dev/hybridmail/PivDiagnostic.java): NFC continuation adjustment and payload-free diagnostics.
- [PivReadTest](../android/app/src/main/java/dev/hybridmail/PivReadTest.java): repeated public reads in one session.
- [YubiBackend](../android/app/src/main/java/dev/hybridmail/YubiBackend.java): connection-scoped key checks, metadata reuse and bounded recovery.
- [PivSessions](../android/app/src/main/java/dev/hybridmail/PivSessions.java): development-firmware resolution.
- [NfcFramingTest](../android/app/src/androidTest/java/dev/hybridmail/NfcFramingTest.java) and [YubiBackendTest](../android/app/src/androidTest/java/dev/hybridmail/YubiBackendTest.java): protocol regression tests.

Inspected upstream references: [YubiKit Android 3.3.0](https://github.com/Yubico/yubikit-android/tree/3.3.0), specifically SmartCardProtocol, ChainedResponseProcessor, ShortApduFormatter, NfcYubiKeyDevice and NfcSmartCardConnection; and [Yubico Authenticator 7.5.0](https://github.com/Yubico/yubioath-flutter/tree/7.5.0), commit `626875a2265818c8eb47b62afe65cae7ebabd27b`.

A useful upstream discussion would ask whether GET RESPONSE should use the advertised SW2 and whether the SDK should offer explicit malformed-response validation and privacy-preserving chain diagnostics. A controlled minimal reproducer would be needed to attribute the remaining historical transceive errors to Android, firmware or SDK behavior. No upstream bug or pull request is claimed here; most changes belong in application lifecycle and operation handling rather than YubiKit itself.
