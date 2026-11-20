//! PQ Mail's assertion-only USB HID bridge. No credential creation or management.
//! stdin: bounded JSON line, then u16be length + PIN bytes / u16be selection index.
//! stdout: bounded JSON event lines. Secrets never go to arguments, files or logs.
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B64};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    cell::Cell,
    io::{self, Read, Write},
    time::{Duration, Instant},
};
use yubikit::{
    ctap::CtapSession,
    ctap2::{Ctap2Error, Ctap2Pin, Ctap2Session, CtapStatus, Permissions},
    platform::hidapi::{HidFidoConnection, list_fido_devices},
    webauthn::{
        AuthenticationResponse, ClientError, DefaultClientDataCollector,
        PublicKeyCredentialDescriptor, PublicKeyCredentialRequestOptions, PublicKeyCredentialType,
        UserInteraction, UserVerificationRequirement, WebAuthnClient,
        extensions::{
            AuthenticationExtensionInputs,
            prf::{AuthenticationInput, PrfEval},
        },
    },
};
use zeroize::{Zeroize, Zeroizing};
const RP: &str = "ve7jtb.github.io";
const ORIGIN: &str = "https://ve7jtb.github.io";
type Result<T> = std::result::Result<T, &'static str>;
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    operation: String,
    rp: String,
    provider: String,
    name: String,
    challenge: String,
    salt: String,
    credential: Option<String>,
}
impl Request {
    fn parse(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > 8192 {
            return Err("Request too large");
        }
        let r: Self = serde_json::from_slice(bytes).map_err(|_| "Invalid request")?;
        if r.operation != "assert"
            || r.rp != RP
            || r.provider != "security-key"
            || r.name.trim().is_empty()
            || r.name.chars().count() > 80
            || r.name.chars().any(char::is_control)
        {
            return Err("Invalid assertion context");
        }
        if decode(&r.challenge)?.len() != 32 || decode(&r.salt)?.len() != 32 {
            return Err("Invalid assertion input length");
        }
        if let Some(id) = &r.credential {
            let id = decode(id)?;
            if id.is_empty() || id.len() > 2048 {
                return Err("Invalid credential length");
            }
        }
        Ok(r)
    }
    fn options(&self) -> Result<PublicKeyCredentialRequestOptions> {
        Ok(PublicKeyCredentialRequestOptions {
            challenge: decode(&self.challenge)?,
            timeout: Some(120_000),
            rp_id: Some(RP.into()),
            allow_credentials: self
                .credential
                .as_ref()
                .map(|id| {
                    Ok(vec![PublicKeyCredentialDescriptor {
                        type_: PublicKeyCredentialType::PublicKey,
                        id: decode(id)?,
                        transports: None,
                    }])
                })
                .transpose()?,
            user_verification: Some(UserVerificationRequirement::Required),
            hints: None,
            // Pass the RAW vault salt; YubiKit hashes WebAuthn PRF\0 || salt exactly once.
            extensions: Some(AuthenticationExtensionInputs {
                prf: Some(AuthenticationInput {
                    eval: Some(PrfEval {
                        first: decode(&self.salt)?,
                        second: None,
                    }),
                    eval_by_credential: Default::default(),
                }),
                ..Default::default()
            }),
        })
    }
}
fn decode(s: &str) -> Result<Vec<u8>> {
    B64.decode(s).map_err(|_| "Invalid base64url")
}
fn send(v: &Value) -> Result<()> {
    let mut wire = Zeroizing::new(serde_json::to_vec(v).map_err(|_| "Cannot encode event")?);
    if wire.len() > 131072 {
        return Err("Response too large");
    }
    wire.push(b'\n');
    let mut out = io::stdout().lock();
    out.write_all(&wire)
        .and_then(|_| out.flush())
        .map_err(|_| "Parent disconnected")
}
fn read_request(mut input: impl Read) -> Result<Vec<u8>> {
    let mut data = Vec::new();
    let mut byte = [0];
    loop {
        input
            .read_exact(&mut byte)
            .map_err(|_| "Incomplete request")?;
        if byte[0] == b'\n' {
            return Ok(data);
        }
        if data.len() == 8192 {
            return Err("Request too large");
        }
        data.push(byte[0]);
    }
}
fn read_u16(mut input: impl Read) -> Result<usize> {
    let mut b = [0; 2];
    input
        .read_exact(&mut b)
        .map_err(|_| "Parent disconnected")?;
    Ok(u16::from_be_bytes(b) as usize)
}
fn pin_from(mut input: impl Read) -> Result<Option<Ctap2Pin>> {
    let len = read_u16(&mut input)?;
    if len == 0 {
        return Ok(None);
    }
    if len > 63 {
        return Err("Invalid FIDO PIN length");
    }
    let mut bytes = Zeroizing::new(vec![0; len]);
    input.read_exact(&mut bytes).map_err(|_| "Incomplete PIN")?;
    let text = std::str::from_utf8(&bytes).map_err(|_| "Invalid PIN encoding")?;
    if text.chars().count() < 4 || text.contains('\0') {
        return Err("FIDO PIN must have at least four characters and at most 63 UTF-8 bytes");
    }
    Ctap2Pin::new(text)
        .map(Some)
        .map_err(|_| "Invalid FIDO PIN")
}
struct Interaction {
    pin_used: Cell<bool>,
    touched: Cell<bool>,
}
impl UserInteraction for Interaction {
    fn prompt_up(&self) {
        if !self.touched.replace(true) {
            let _ = send(&json!({"event":"touch"}));
        }
    }
    fn request_pin(&self, _: Permissions, rp: Option<&str>) -> Option<Ctap2Pin> {
        if rp != Some(RP) || self.pin_used.replace(true) {
            return None;
        }
        send(&json!({"event":"pin"})).ok()?;
        pin_from(io::stdin().lock()).ok().flatten()
    }
    fn request_uv(&self, _: Permissions, _: Option<&str>) -> bool {
        false
    } // explicit FIDO PIN, never silent fallback from failed UV
}
struct Responses(Vec<AuthenticationResponse>);
impl Drop for Responses {
    fn drop(&mut self) {
        for r in &mut self.0 {
            if let Some(p) = r
                .client_extension_results
                .as_mut()
                .and_then(|e| e.prf.as_mut())
            {
                p.results.first.zeroize();
                if let Some(s) = &mut p.results.second {
                    s.zeroize()
                }
            }
        }
    }
}
fn validate_response(r: &AuthenticationResponse, request: &Request) -> Result<()> {
    let id = if r.id.is_empty() {
        request
            .credential
            .as_ref()
            .map(|s| decode(s))
            .transpose()?
            .ok_or("Missing discovered credential ID")?
    } else {
        r.id.clone()
    };
    if id.is_empty() || id.len() > 2048 {
        return Err("Invalid returned credential");
    }
    if let Some(expected) = &request.credential {
        if decode(expected)? != id {
            return Err("Wrong credential returned");
        }
    }
    let auth = &r.response.authenticator_data;
    if auth.len() < 37 || auth[..32] != Sha256::digest(RP.as_bytes())[..] || auth[32] & 5 != 5 {
        return Err("Authenticator did not verify user presence and FIDO PIN");
    }
    let client: Value =
        serde_json::from_slice(&r.response.client_data_json).map_err(|_| "Invalid client data")?;
    if client["type"] != "webauthn.get"
        || client["origin"] != ORIGIN
        || client["challenge"] != request.challenge
        || client["crossOrigin"] != false
    {
        return Err("Assertion context mismatch");
    }
    let prf = r
        .client_extension_results
        .as_ref()
        .and_then(|e| e.prf.as_ref())
        .ok_or("This credential has no PRF output; vault remains locked")?;
    if prf.results.first.len() != 32 || r.response.signature.is_empty() {
        return Err("Invalid assertion/PRF output");
    }
    Ok(())
}
fn response_json(r: &AuthenticationResponse, request: &Request) -> Result<Value> {
    validate_response(r, request)?;
    let id = if r.id.is_empty() {
        decode(request.credential.as_ref().ok_or("Missing credential")?)?
    } else {
        r.id.clone()
    };
    let prf = &r
        .client_extension_results
        .as_ref()
        .unwrap()
        .prf
        .as_ref()
        .unwrap()
        .results
        .first;
    Ok(
        json!({"event":"result","result":{"type":"public-key","rawId":B64.encode(id),"response":{
  "clientDataJSON":B64.encode(&r.response.client_data_json),"authenticatorData":B64.encode(&r.response.authenticator_data),
  "signature":B64.encode(&r.response.signature),"userHandle":B64.encode(r.response.user_handle.as_deref().unwrap_or(&[]))},
  "clientExtensionResults":{"prf":{"results":{"first":B64.encode(prf)}}}}}),
    )
}
fn wipe_json(value: &mut Value) {
    match value {
        Value::String(s) => s.zeroize(),
        Value::Array(a) => {
            for v in a {
                wipe_json(v)
            }
        }
        Value::Object(m) => {
            for v in m.values_mut() {
                wipe_json(v)
            }
        }
        _ => {}
    }
}
fn error_text<E: std::error::Error + Send + Sync + 'static>(e: ClientError<E>) -> &'static str {
    match e {
        ClientError::Ctap(Ctap2Error::StatusError(CtapStatus::PinInvalid)) => {
            "FIDO PIN rejected. No retry was attempted. Check the PIN before trying again."
        }
        ClientError::Ctap(Ctap2Error::StatusError(
            CtapStatus::PinBlocked | CtapStatus::PinAuthBlocked,
        )) => "FIDO PIN is blocked. No retry was attempted.",
        ClientError::Ctap(Ctap2Error::StatusError(CtapStatus::NoCredentials)) => {
            "This YubiKey does not contain the selected PQ Mail passkey."
        }
        ClientError::PinRequired => "FIDO PIN entry cancelled or invalid; vault remains locked.",
        ClientError::ConfigurationUnsupported(_) => {
            "YubiKey requires configured FIDO2 PIN and hmac-secret/PRF support."
        }
        _ => {
            "FIDO assertion failed or timed out; no PIN retry was attempted. Keep the key connected and touch when requested."
        }
    }
}
fn authenticate(request: &Request) -> Result<()> {
    let devices =
        list_fido_devices().map_err(|_| "Cannot enumerate YubiKeys; check USB HID permissions")?;
    if devices.is_empty() {
        return Err(
            "No accessible FIDO YubiKey. Connect it, enable FIDO2, and check Linux hidraw permissions.",
        );
    }
    if devices.len() != 1 {
        return Err("Connect only the YubiKey you want to use, then retry. No PIN was submitted.");
    }
    let connection = HidFidoConnection::open(&devices[0]).map_err(
        |_| "Cannot open YubiKey HID device. Check udev permissions; do not run PQ Mail as root.",
    )?;
    let ctap = CtapSession::new_fido(connection).map_err(|_| "Cannot initialize FIDO transport")?;
    let mut session = Ctap2Session::new(ctap).map_err(|_| "This YubiKey does not support FIDO2")?;
    let info = session
        .get_info()
        .map_err(|_| "Cannot read FIDO capabilities")?;
    if !info.extensions.iter().any(|e| e == "hmac-secret") {
        return Err("YubiKey does not support hmac-secret/PRF");
    }
    let interaction = Interaction {
        pin_used: Cell::new(false),
        touched: Cell::new(false),
    };
    let mut client = WebAuthnClient::new(
        session,
        interaction,
        DefaultClientDataCollector::new(ORIGIN),
    );
    let start = Instant::now();
    let cancel = || start.elapsed() > Duration::from_secs(240);
    let responses = Responses(
        client
            .get_assertion(&request.options()?, Some(&cancel))
            .map_err(error_text)?,
    );
    if responses.0.is_empty() || responses.0.len() > 64 {
        return Err("Invalid number of matching passkeys");
    }
    let selected = if responses.0.len() == 1 {
        0
    } else {
        if request.credential.is_some() {
            return Err("Ambiguous response for selected credential");
        }
        let choices: Vec<String> = responses
            .0
            .iter()
            .enumerate()
            .map(|(i, r)| format!("Passkey {} — ID {}", i + 1, B64.encode(&r.id)))
            .collect();
        send(&json!({"event":"select","choices":choices}))?;
        let n = read_u16(io::stdin().lock())?;
        if n >= responses.0.len() {
            return Err("Passkey selection cancelled");
        }
        n
    };
    let mut result = response_json(&responses.0[selected], request)?;
    let sent = send(&result);
    wipe_json(&mut result);
    sent
}
fn main() {
    // Avoid core dumps containing a PIN, PRF output, or PIN/UV token.
    #[cfg(unix)]
    unsafe {
        let limit = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        libc::setrlimit(libc::RLIMIT_CORE, &limit);
    }
    std::panic::set_hook(Box::new(|_| {}));
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args == ["--probe"] {
        println!("{{\"backend\":\"YubiKit USB HID\",\"protocol\":1,\"assertionOnly\":true}}");
        return;
    }
    let outcome = std::panic::catch_unwind(|| {
        if !args.is_empty() {
            return Err("No command-line credentials accepted");
        }
        let request = Request::parse(&read_request(io::stdin().lock())?)?;
        authenticate(&request)
    })
    .unwrap_or(Err("Native passkey helper failed"));
    if let Err(message) = outcome {
        let _ = send(&json!({"event":"error","error":message}));
        std::process::exit(1)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn request() -> Request {
        Request::parse(serde_json::to_vec(&json!({"operation":"assert","rp":RP,"provider":"security-key","name":"Test YubiKey","challenge":B64.encode([7;32]),"salt":B64.encode([3;32]),"credential":B64.encode([4;16])})).unwrap().as_slice()).unwrap()
    }
    #[test]
    fn raw_salt_and_context() {
        let r = request();
        let o = r.options().unwrap();
        assert_eq!(
            o.extensions.unwrap().prf.unwrap().eval.unwrap().first,
            vec![3; 32]
        );
        assert_eq!(
            o.user_verification,
            Some(UserVerificationRequirement::Required)
        );
        assert_eq!(o.allow_credentials.unwrap()[0].id, vec![4; 16]);
    }
    #[test]
    fn bounded_request() {
        assert!(read_request(&vec![b'x'; 8194][..]).is_err());
        assert!(Request::parse(b"{}").is_err());
        let mut r = request();
        r.rp = "evil.example".into();
        assert!(Request::parse(serde_json::to_vec(&json!({"operation":r.operation,"rp":r.rp,"provider":r.provider,"name":r.name,"challenge":r.challenge,"salt":r.salt})).unwrap().as_slice()).is_err());
    }
    #[test]
    fn pin_bounds() {
        assert!(pin_from(&b"\0\0"[..]).unwrap().is_none());
        assert!(pin_from(&b"\0\x041234"[..]).unwrap().is_some());
        assert!(pin_from(&b"\0\x03abc"[..]).is_err());
        assert!(pin_from(&b"\0\x40"[..]).is_err());
        assert!(pin_from(&b"\0\x04\xff\xff\xff\xff"[..]).is_err());
    }
    fn response() -> AuthenticationResponse {
        let r = request();
        let mut auth = Sha256::digest(RP.as_bytes()).to_vec();
        auth.extend_from_slice(&[5, 0, 0, 0, 1]);
        serde_json::from_value(json!({"id":r.credential,"type":"public-key","response":{"clientDataJSON":B64.encode(serde_json::to_vec(&json!({"type":"webauthn.get","origin":ORIGIN,"challenge":r.challenge,"crossOrigin":false})).unwrap()),"authenticatorData":B64.encode(auth),"signature":B64.encode([1;64])},"clientExtensionResults":{"prf":{"results":{"first":B64.encode([9;32])}}}})).unwrap()
    }
    #[test]
    fn output_context_and_missing_id() {
        let r = request();
        let mut a = response();
        assert!(validate_response(&a, &r).is_ok());
        a.id.clear();
        assert!(validate_response(&a, &r).is_ok());
        let mut discovery = request();
        discovery.credential = None;
        assert!(validate_response(&a, &discovery).is_err());
        a.id = vec![8; 16];
        assert!(validate_response(&a, &r).is_err());
    }
    #[test]
    fn output_requires_uv_up_prf_and_rp() {
        for flag in [0, 1, 4] {
            let mut a = response();
            a.response.authenticator_data[32] = flag;
            assert!(validate_response(&a, &request()).is_err());
        }
        let mut a = response();
        a.response.authenticator_data[0] ^= 1;
        assert!(validate_response(&a, &request()).is_err());
        let mut a = response();
        a.client_extension_results = None;
        assert!(validate_response(&a, &request()).is_err());
        let mut a = response();
        a.response.client_data_json = b"{}".to_vec();
        assert!(validate_response(&a, &request()).is_err());
    }
    #[test]
    fn output_wiped_on_drop_path() {
        let mut responses = Responses(vec![response()]);
        let mut result = response_json(&responses.0[0], &request()).unwrap();
        assert_eq!(
            result["result"]["clientExtensionResults"]["prf"]["results"]["first"],
            B64.encode([9; 32])
        );
        wipe_json(&mut result);
        assert_eq!(
            result["result"]["clientExtensionResults"]["prf"]["results"]["first"],
            ""
        );
        responses.0[0]
            .client_extension_results
            .as_mut()
            .unwrap()
            .prf
            .as_mut()
            .unwrap()
            .results
            .first
            .zeroize();
        assert!(
            responses.0[0]
                .client_extension_results
                .as_ref()
                .unwrap()
                .prf
                .as_ref()
                .unwrap()
                .results
                .first
                .is_empty()
        );
    }
    #[test]
    fn wipe_output() {
        let mut j = json!({"clientExtensionResults":{"prf":{"results":{"first":"secret"}}}});
        wipe_json(&mut j);
        assert!(!j.to_string().contains("secret"));
    }
}
