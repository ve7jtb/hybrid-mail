# November 2026 dependency review

Version matches identify dependencies needing attention; they do not establish
compromise or prove that an application reaches an affected operation.

## Gradle

Android and the pinned Bouncy Castle fork now use **Gradle 9.9.1**. Both wrapper
JARs and launch scripts were regenerated using the verified 9.9.1 distribution,
without executing the older wrappers. Distribution SHA-256 verification is
enabled in both `gradle-wrapper.properties` files.

* Distribution: `d8a18a7a841dd5df825d35a685fad6f2d7f12ac0c280e57b67c27b4a520ba228`
* Wrapper JAR: `621008afc4f5d59357fcf06ffa644dd5aade5e091bdc363742710445f73cdaf8`
* Bouncy Castle fork: `fad147c4440df867930bd9d8c14e85fbaca1c377`

This addresses the affected build-tool versions in
[GHSA-3cfg-jpcr-gfp3](https://github.com/gradle/gradle/security/advisories/GHSA-3cfg-jpcr-gfp3),
[GHSA-gqrr-4j89-5267](https://github.com/gradle/gradle/security/advisories/GHSA-gqrr-4j89-5267)
and [GHSA-pcp8-98xm-c6pr](https://github.com/gradle/gradle/security/advisories/GHSA-pcp8-98xm-c6pr).
Gradle is not included in the installed app.

## OpenSSL

Linux packaging and the iOS XCFramework share the exact source pin in
[`scripts/openssl-source.env`](../scripts/openssl-source.env):
`81162ed421d98f527f55bfff205994f53831223b` on the supported **3.5 LTS** branch.
The source identifies itself as **3.5.10-dev**, not a released 3.5.10. At the
time of this update, the 3.5.10 release tag/archive was unavailable. The downloaded
commit archive is SHA-256 pinned; iOS requires the exact clean Git revision and
uses a revision-specific build directory to avoid reusing older libraries.

All eight 3.5 fix commits linked by the
[OpenSSL advisory page](https://openssl-library.org/news/vulnerabilities-3.5/index.html)
were verified to be ancestors of the selected revision:

```
c8f6d04f8e6d40b1bf83334e4a2ec9daf5943a3d
f3acb0a3328046741479482c51cec815839e1b05
9491b0d9cc7950af1f3dc89499bd5433b9cd4f43
159e1de0c448d7b9f09ad768c8e141def4aa1eb4
a0051cfe699bf5a047bc1c4faef65f80f7987366
1a73dc590cbad62d6f0329ea4779eadaa8d8fd75
f6244675833e097c2429a40d1b206d95385bd42f
257a3427aa0ef8d9dd2ef5b3e2d1c021a221b116
```

This also moves iOS off the
[unsupported 3.6 series](https://openssl-library.org/post/2026-11-01-eol34-36/).
Linux artifacts include the source pin and the staged executable's version.
Already-downloaded packages are not changed by updating these build inputs.

## Rust RSA reachability

[`RUSTSEC-2023-0071`](https://rustsec.org/advisories/RUSTSEC-2023-0071.html)
still matches the locked `rsa 0.9.10` dependency brought in by YubiKit
`f59e6fedb4f7a75da551ba4dea5d0c7863c8a2b4`. The normal dependency declaration is
present, but inspection of that revision found the RSA crate's private-key
generation/sign/decrypt uses in `#[cfg(test)]` code in
`crates/yubikit/src/__internal/padding.rs`. PQ Mail's FIDO assertion helper does
not perform software RSA private-key operations. YubiKit's similarly named
`keys::RsaPrivateKey` is its own key-material type, not `rsa::RsaPrivateKey`.

The pinned Yubico PKCS#11 source uses `rsa 0.10.0` for RSA public-key
verification. Token private-key operations are performed on the device.
This source review found no production call to the vulnerable Rust RSA
private-key operation in these paths; it is not a proof covering every future
feature or upstream change. The 0.9.10 dependency match remains open and is not
suppressed. Recheck when updating YubiKit; a major-version dependency override
without upstream API/test changes is not an appropriate fix.
