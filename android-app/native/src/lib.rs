//! Small FFI adapter; the existing iroh-ssh library owns the tunnel protocol.
use serde_json::{Value, json};
use std::{
    ffi::{CStr, CString, c_char},
    sync::LazyLock,
    time::Duration,
};

static RUNTIME: LazyLock<tokio::runtime::Runtime> = LazyLock::new(|| {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("Tokio runtime")
});

fn verify_audit_signature(request: &Value) -> Result<Value, String> {
    let bytes = |name: &str| {
        serde_json::from_value::<Vec<u8>>(request[name].clone()).map_err(|e| e.to_string())
    };
    let key: [u8; 32] = bytes("public_key")?
        .try_into()
        .map_err(|_| "invalid audit public key length".to_owned())?;
    let signature: [u8; 64] = bytes("signature")?
        .try_into()
        .map_err(|_| "invalid audit signature length".to_owned())?;
    let message = bytes("message")?;
    let mut prime = [0xff; 32];
    prime[0] = 0xed;
    prime[31] = 0x7f;
    for point in [&key[..], &signature[..32]] {
        let mut y: [u8; 32] = point.try_into().unwrap();
        y[31] &= 0x7f;
        if y.iter().rev().cmp(prime.iter().rev()) != std::cmp::Ordering::Less {
            return Err("noncanonical audit signature point".to_owned());
        }
    }
    ed25519_dalek::VerifyingKey::from_bytes(&key)
        .map_err(|e| e.to_string())?
        .verify_strict(&message, &ed25519_dalek::Signature::from_bytes(&signature))
        .map_err(|_| "invalid audit signature".to_owned())?;
    Ok(json!({}))
}

async fn request(text: &str) -> Result<Value, String> {
    let request: Value = serde_json::from_str(text).map_err(|e| e.to_string())?;
    match request["method"].as_str() {
        Some("verify_audit_signature") => verify_audit_signature(&request),
        Some("connect") => {
            let endpoint = request["endpoint"].as_str().ok_or("missing endpoint")?;
            let relays = request["relays"]
                .as_array()
                .map(|items| {
                    items
                        .iter()
                        .map(|value| value.as_str().ok_or("invalid relay").map(str::to_owned))
                        .collect::<Result<Vec<_>, _>>()
                })
                .transpose()?
                .unwrap_or_default();
            let port = iroh_ssh::bridge::connect(
                endpoint.to_owned(),
                iroh_ssh::bridge::ConnectOptions {
                    relay_urls: relays,
                    ..Default::default()
                },
            )
            .await
            .map_err(|e| e.to_string())?;
            Ok(json!({"port":port}))
        }
        Some("disconnect") => {
            let port = request["port"]
                .as_u64()
                .filter(|p| *p > 0 && *p <= u16::MAX as u64)
                .ok_or("invalid port")?;
            iroh_ssh::bridge::disconnect(port as u16)
                .await
                .map_err(|e| e.to_string())?;
            Ok(json!({}))
        }
        _ => Err("unknown transport method".into()),
    }
}

/// # Safety
/// `input` must be a valid NUL-terminated UTF-8 C string for the duration of this call.
/// The caller owns the returned string and must release it with `zondd_iroh_free`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zondd_iroh_request(input: *const c_char) -> *mut c_char {
    let result = std::panic::catch_unwind(|| {
        // SAFETY: the FFI caller supplies a live NUL-terminated string.
        let text = unsafe { CStr::from_ptr(input) }
            .to_str()
            .map_err(|e| e.to_string())?;
        RUNTIME.block_on(async {
            tokio::time::timeout(Duration::from_secs(30), request(text))
                .await
                .map_err(|_| "Iroh transport timed out".to_owned())?
        })
    })
    .unwrap_or_else(|_| Err("Iroh transport panic".into()));
    let response = match result {
        Ok(value) => json!({"ok":true,"result":value}),
        Err(error) => json!({"ok":false,"error":error}),
    };
    CString::new(response.to_string())
        .expect("JSON has no NUL bytes")
        .into_raw()
}

/// # Safety
/// `pointer` must be a live string returned by `zondd_iroh_request`, freed exactly once.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zondd_iroh_free(pointer: *mut c_char) {
    // SAFETY: ownership of this allocated string is returned by the FFI caller.
    drop(unsafe { CString::from_raw(pointer) });
}

#[cfg(target_os = "android")]
#[jni::jni_mangle("io.github.futpib.zondd_control.MainActivity")]
pub fn initVerifier<'caller>(
    mut env: jni::EnvUnowned<'caller>,
    _this: jni::objects::JObject<'caller>,
    context: jni::objects::JObject<'caller>,
) {
    env.with_env(|env| rustls_platform_verifier::android::init_with_env(env, context))
        .resolve::<jni::errors::ThrowRuntimeExAndDefault>();
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unhex(text: &str) -> Vec<u8> {
        text.as_bytes()
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect()
    }

    fn signed_request() -> Value {
        let fixture: Value =
            serde_json::from_str(include_str!("../../../testdata/audit-v1.json")).unwrap();
        let proof = &fixture["events"][2]["detail"]["proof"];
        json!({
            "method":"verify_audit_signature",
            "public_key":unhex(proof["public_key"].as_str().unwrap()),
            "signature":unhex(proof["signature"].as_str().unwrap()),
            "message":format!("zondd-audit-decision-v1\n{}", proof["payload"].as_str().unwrap()).into_bytes(),
        })
    }

    fn ffi_verify(value: Value) -> bool {
        let input = CString::new(value.to_string()).unwrap();
        // SAFETY: input stays live and the returned allocation is freed once.
        unsafe {
            let response = zondd_iroh_request(input.as_ptr());
            let decoded: Value =
                serde_json::from_str(CStr::from_ptr(response).to_str().unwrap()).unwrap();
            zondd_iroh_free(response);
            decoded["ok"] == true
        }
    }

    #[test]
    fn ffi_verification_accepts_the_shared_vector_and_rejects_changed_bytes() {
        let value = signed_request();
        assert!(ffi_verify(value.clone()));
        for field in ["public_key", "signature", "message"] {
            let mut altered = value.clone();
            altered[field][0] = json!(altered[field][0].as_u64().unwrap() ^ 1);
            assert!(!ffi_verify(altered), "accepted changed {field}");
        }
    }

    #[test]
    fn ffi_verification_rejects_weak_and_noncanonical_signatures() {
        let vectors: Value =
            serde_json::from_str(include_str!("../../../testdata/audit-ed25519-strict.json"))
                .unwrap();
        let value = json!({
            "method":"verify_audit_signature",
            "public_key":unhex(vectors["public_key"].as_str().unwrap()),
            "message":vectors["message"].as_str().unwrap().as_bytes(),
        });
        for point in vectors["weak_points"].as_array().unwrap() {
            let mut altered = value.clone();
            altered["public_key"] = json!(unhex(point.as_str().unwrap()));
            let mut signature = vec![0; 64];
            signature[0] = 1;
            altered["signature"] = json!(signature);
            assert!(!ffi_verify(altered));
        }
        for field in ["weak_r", "noncanonical_s"] {
            let mut altered = value.clone();
            altered["signature"] = json!(unhex(vectors[field].as_str().unwrap()));
            assert!(!ffi_verify(altered), "accepted {field}");
        }
        for field in ["public_key", "signature"] {
            let mut altered = signed_request();
            for i in 0..32 {
                altered[field][i] = json!(255);
            }
            assert!(!ffi_verify(altered));
        }
    }

    #[test]
    fn ffi_verification_rejects_malformed_byte_arrays() {
        for field in ["public_key", "signature", "message"] {
            for invalid in [Value::Null, json!("not bytes"), json!([256]), json!([-1])] {
                let mut altered = signed_request();
                altered[field] = invalid;
                assert!(!ffi_verify(altered));
            }
        }
        for field in ["public_key", "signature"] {
            let mut altered = signed_request();
            altered[field].as_array_mut().unwrap().pop();
            assert!(!ffi_verify(altered));
        }
    }
}
