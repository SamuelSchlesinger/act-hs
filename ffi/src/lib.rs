use anonymous_credit_tokens::{
    CreditToken, IssuanceRequest, IssuanceResponse, Params, PreIssuance, PreRefund, PrivateKey,
    PublicKey, Refund, Scalar, SpendProof,
};
use paste::paste;
use rand_core::OsRng;
use std::ffi::CStr;
use std::os::raw::c_char;
use std::panic::catch_unwind;
use std::slice;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

unsafe fn write_output(data: Vec<u8>, out_ptr: *mut *mut u8, out_len: *mut usize) {
    let boxed = data.into_boxed_slice();
    let len = boxed.len();
    let ptr = Box::into_raw(boxed) as *mut u8;
    *out_ptr = ptr;
    *out_len = len;
}

unsafe fn read_slice<'a>(ptr: *const u8, len: usize) -> &'a [u8] {
    if len == 0 {
        &[]
    } else {
        slice::from_raw_parts(ptr, len)
    }
}

unsafe fn read_scalar(ptr: *const u8) -> Option<Scalar> {
    let bytes = slice::from_raw_parts(ptr, 32);
    let mut arr = [0u8; 32];
    arr.copy_from_slice(bytes);
    Option::from(Scalar::from_canonical_bytes(arr))
}

unsafe fn write_scalar(scalar: &Scalar, out: *mut u8) {
    let bytes = scalar.as_bytes();
    std::ptr::copy_nonoverlapping(bytes.as_ptr(), out, 32);
}

// ---------------------------------------------------------------------------
// Params: opaque pointer management
// ---------------------------------------------------------------------------

#[no_mangle]
pub unsafe extern "C" fn act_params_new(
    org: *const c_char,
    svc: *const c_char,
    dep: *const c_char,
    ver: *const c_char,
) -> *mut Params {
    let result = catch_unwind(|| {
        let org = CStr::from_ptr(org).to_str().ok()?;
        let svc = CStr::from_ptr(svc).to_str().ok()?;
        let dep = CStr::from_ptr(dep).to_str().ok()?;
        let ver = CStr::from_ptr(ver).to_str().ok()?;
        Some(Box::into_raw(Box::new(Params::new(org, svc, dep, ver))))
    });
    match result {
        Ok(Some(ptr)) => ptr,
        _ => std::ptr::null_mut(),
    }
}

#[no_mangle]
pub unsafe extern "C" fn act_params_free(ptr: *mut Params) {
    if !ptr.is_null() {
        drop(Box::from_raw(ptr));
    }
}

// ---------------------------------------------------------------------------
// Buffer management
// ---------------------------------------------------------------------------

#[no_mangle]
pub unsafe extern "C" fn act_free_buffer(ptr: *mut u8, len: usize) {
    if !ptr.is_null() && len > 0 {
        drop(Box::from_raw(slice::from_raw_parts_mut(ptr, len)));
    }
}

// ---------------------------------------------------------------------------
// PrivateKey
// ---------------------------------------------------------------------------

#[no_mangle]
pub unsafe extern "C" fn act_private_key_random(
    out_ptr: *mut *mut u8,
    out_len: *mut usize,
) -> i32 {
    match catch_unwind(|| PrivateKey::random(OsRng).to_cbor()) {
        Ok(Ok(bytes)) => {
            write_output(bytes, out_ptr, out_len);
            0
        }
        _ => -1,
    }
}

#[no_mangle]
pub unsafe extern "C" fn act_private_key_public(
    pk_ptr: *const u8,
    pk_len: usize,
    out_ptr: *mut *mut u8,
    out_len: *mut usize,
) -> i32 {
    let pk_bytes = read_slice(pk_ptr, pk_len);
    let pk = match PrivateKey::from_cbor(pk_bytes) {
        Ok(pk) => pk,
        Err(_) => return 3,
    };
    match pk.public().to_cbor() {
        Ok(bytes) => {
            write_output(bytes, out_ptr, out_len);
            0
        }
        Err(_) => -1,
    }
}

// ---------------------------------------------------------------------------
// PreIssuance
// ---------------------------------------------------------------------------

#[no_mangle]
pub unsafe extern "C" fn act_pre_issuance_random(
    out_ptr: *mut *mut u8,
    out_len: *mut usize,
) -> i32 {
    match catch_unwind(|| PreIssuance::random(OsRng).to_cbor()) {
        Ok(Ok(bytes)) => {
            write_output(bytes, out_ptr, out_len);
            0
        }
        _ => -1,
    }
}

#[no_mangle]
pub unsafe extern "C" fn act_pre_issuance_request(
    pi_ptr: *const u8,
    pi_len: usize,
    params: *const Params,
    out_ptr: *mut *mut u8,
    out_len: *mut usize,
) -> i32 {
    let pi_bytes = read_slice(pi_ptr, pi_len);
    let pi = match PreIssuance::from_cbor(pi_bytes) {
        Ok(pi) => pi,
        Err(_) => return 3,
    };
    let params = &*params;
    match pi.request(params, OsRng).to_cbor() {
        Ok(bytes) => {
            write_output(bytes, out_ptr, out_len);
            0
        }
        Err(_) => -1,
    }
}

// ---------------------------------------------------------------------------
// to_credit_token (L-independent)
// ---------------------------------------------------------------------------

#[no_mangle]
pub unsafe extern "C" fn act_to_credit_token(
    pi_ptr: *const u8,
    pi_len: usize,
    params: *const Params,
    pubkey_ptr: *const u8,
    pubkey_len: usize,
    req_ptr: *const u8,
    req_len: usize,
    resp_ptr: *const u8,
    resp_len: usize,
    out_ptr: *mut *mut u8,
    out_len: *mut usize,
) -> i32 {
    let pi_bytes = read_slice(pi_ptr, pi_len);
    let pubkey_bytes = read_slice(pubkey_ptr, pubkey_len);
    let req_bytes = read_slice(req_ptr, req_len);
    let resp_bytes = read_slice(resp_ptr, resp_len);
    let params = &*params;

    let pi = match PreIssuance::from_cbor(pi_bytes) {
        Ok(pi) => pi,
        Err(_) => return 3,
    };
    let pubkey = match PublicKey::from_cbor(pubkey_bytes) {
        Ok(pk) => pk,
        Err(_) => return 3,
    };
    let req = match IssuanceRequest::from_cbor(req_bytes) {
        Ok(r) => r,
        Err(_) => return 3,
    };
    let resp = match IssuanceResponse::from_cbor(resp_bytes) {
        Ok(r) => r,
        Err(_) => return 3,
    };

    match pi.to_credit_token(params, &pubkey, &req, &resp) {
        Ok(token) => match token.to_cbor() {
            Ok(bytes) => {
                write_output(bytes, out_ptr, out_len);
                0
            }
            Err(_) => -1,
        },
        Err(e) => e as i32,
    }
}

// ---------------------------------------------------------------------------
// CreditToken accessors (L-independent)
// ---------------------------------------------------------------------------

#[no_mangle]
pub unsafe extern "C" fn act_credit_token_nullifier(
    tok_ptr: *const u8,
    tok_len: usize,
    out_32: *mut u8,
) -> i32 {
    let tok_bytes = read_slice(tok_ptr, tok_len);
    let token = match CreditToken::from_cbor(tok_bytes) {
        Ok(t) => t,
        Err(_) => return 3,
    };
    write_scalar(&token.nullifier(), out_32);
    0
}

#[no_mangle]
pub unsafe extern "C" fn act_credit_token_credits(
    tok_ptr: *const u8,
    tok_len: usize,
    out_32: *mut u8,
) -> i32 {
    let tok_bytes = read_slice(tok_ptr, tok_len);
    let token = match CreditToken::from_cbor(tok_bytes) {
        Ok(t) => t,
        Err(_) => return 3,
    };
    write_scalar(&token.credits(), out_32);
    0
}

// ---------------------------------------------------------------------------
// L-dependent implementation functions
// ---------------------------------------------------------------------------

unsafe fn issue_impl<const L: usize>(
    pk_ptr: *const u8,
    pk_len: usize,
    params: *const Params,
    req_ptr: *const u8,
    req_len: usize,
    c_bytes: *const u8,
    ctx_bytes: *const u8,
    out_ptr: *mut *mut u8,
    out_len: *mut usize,
) -> i32 {
    let pk_bytes = read_slice(pk_ptr, pk_len);
    let req_bytes = read_slice(req_ptr, req_len);
    let params = &*params;

    let c = match read_scalar(c_bytes) {
        Some(s) => s,
        None => return 3,
    };
    let ctx = match read_scalar(ctx_bytes) {
        Some(s) => s,
        None => return 3,
    };
    let pk = match PrivateKey::from_cbor(pk_bytes) {
        Ok(pk) => pk,
        Err(_) => return 3,
    };
    let req = match IssuanceRequest::from_cbor(req_bytes) {
        Ok(r) => r,
        Err(_) => return 3,
    };

    match pk.issue::<L>(params, &req, c, ctx, OsRng) {
        Ok(resp) => match resp.to_cbor() {
            Ok(bytes) => {
                write_output(bytes, out_ptr, out_len);
                0
            }
            Err(_) => -1,
        },
        Err(e) => e as i32,
    }
}

unsafe fn prove_spend_impl<const L: usize>(
    tok_ptr: *const u8,
    tok_len: usize,
    params: *const Params,
    s_bytes: *const u8,
    out_proof_ptr: *mut *mut u8,
    out_proof_len: *mut usize,
    out_pr_ptr: *mut *mut u8,
    out_pr_len: *mut usize,
) -> i32 {
    let tok_bytes = read_slice(tok_ptr, tok_len);
    let params = &*params;
    let s = match read_scalar(s_bytes) {
        Some(s) => s,
        None => return 3,
    };
    let token = match CreditToken::from_cbor(tok_bytes) {
        Ok(t) => t,
        Err(_) => return 3,
    };

    let (proof, prerefund) = token.prove_spend::<L>(params, s, OsRng);

    let proof_bytes = match proof.to_cbor() {
        Ok(b) => b,
        Err(_) => return -1,
    };
    let pr_bytes = match prerefund.to_cbor() {
        Ok(b) => b,
        Err(_) => return -1,
    };
    write_output(proof_bytes, out_proof_ptr, out_proof_len);
    write_output(pr_bytes, out_pr_ptr, out_pr_len);
    0
}

unsafe fn refund_impl<const L: usize>(
    pk_ptr: *const u8,
    pk_len: usize,
    params: *const Params,
    proof_ptr: *const u8,
    proof_len: usize,
    out_ptr: *mut *mut u8,
    out_len: *mut usize,
) -> i32 {
    let pk_bytes = read_slice(pk_ptr, pk_len);
    let proof_bytes = read_slice(proof_ptr, proof_len);
    let params = &*params;

    let pk = match PrivateKey::from_cbor(pk_bytes) {
        Ok(pk) => pk,
        Err(_) => return 3,
    };
    let proof = match SpendProof::<L>::from_cbor(proof_bytes) {
        Ok(p) => p,
        Err(_) => return 3,
    };

    match pk.refund(params, &proof, OsRng) {
        Ok(refund) => match refund.to_cbor() {
            Ok(bytes) => {
                write_output(bytes, out_ptr, out_len);
                0
            }
            Err(_) => -1,
        },
        Err(e) => e as i32,
    }
}

unsafe fn refund_to_credit_token_impl<const L: usize>(
    pr_ptr: *const u8,
    pr_len: usize,
    params: *const Params,
    proof_ptr: *const u8,
    proof_len: usize,
    refund_ptr: *const u8,
    refund_len: usize,
    pubkey_ptr: *const u8,
    pubkey_len: usize,
    out_ptr: *mut *mut u8,
    out_len: *mut usize,
) -> i32 {
    let pr_bytes = read_slice(pr_ptr, pr_len);
    let proof_bytes = read_slice(proof_ptr, proof_len);
    let refund_bytes = read_slice(refund_ptr, refund_len);
    let pubkey_bytes = read_slice(pubkey_ptr, pubkey_len);
    let params = &*params;

    let pr = match PreRefund::from_cbor(pr_bytes) {
        Ok(pr) => pr,
        Err(_) => return 3,
    };
    let proof = match SpendProof::<L>::from_cbor(proof_bytes) {
        Ok(p) => p,
        Err(_) => return 3,
    };
    let refund = match Refund::from_cbor(refund_bytes) {
        Ok(r) => r,
        Err(_) => return 3,
    };
    let pubkey = match PublicKey::from_cbor(pubkey_bytes) {
        Ok(pk) => pk,
        Err(_) => return 3,
    };

    match pr.to_credit_token(params, &proof, &refund, &pubkey) {
        Ok(token) => match token.to_cbor() {
            Ok(bytes) => {
                write_output(bytes, out_ptr, out_len);
                0
            }
            Err(_) => -1,
        },
        Err(e) => e as i32,
    }
}

unsafe fn spend_proof_nullifier_impl<const L: usize>(
    proof_ptr: *const u8,
    proof_len: usize,
    out_32: *mut u8,
) -> i32 {
    let proof_bytes = read_slice(proof_ptr, proof_len);
    let proof = match SpendProof::<L>::from_cbor(proof_bytes) {
        Ok(p) => p,
        Err(_) => return 3,
    };
    write_scalar(&proof.nullifier(), out_32);
    0
}

unsafe fn spend_proof_charge_impl<const L: usize>(
    proof_ptr: *const u8,
    proof_len: usize,
    out_32: *mut u8,
) -> i32 {
    let proof_bytes = read_slice(proof_ptr, proof_len);
    let proof = match SpendProof::<L>::from_cbor(proof_bytes) {
        Ok(p) => p,
        Err(_) => return 3,
    };
    write_scalar(&proof.charge(), out_32);
    0
}

unsafe fn spend_proof_context_impl<const L: usize>(
    proof_ptr: *const u8,
    proof_len: usize,
    out_32: *mut u8,
) -> i32 {
    let proof_bytes = read_slice(proof_ptr, proof_len);
    let proof = match SpendProof::<L>::from_cbor(proof_bytes) {
        Ok(p) => p,
        Err(_) => return 3,
    };
    write_scalar(&proof.context(), out_32);
    0
}

// ---------------------------------------------------------------------------
// Macro to generate L-suffixed extern "C" wrappers
// ---------------------------------------------------------------------------

macro_rules! impl_l_ffi {
    ($L:literal) => {
        paste! {
            #[no_mangle]
            pub unsafe extern "C" fn [<act_issue_ $L>](
                pk_ptr: *const u8,
                pk_len: usize,
                params: *const Params,
                req_ptr: *const u8,
                req_len: usize,
                c_bytes: *const u8,
                ctx_bytes: *const u8,
                out_ptr: *mut *mut u8,
                out_len: *mut usize,
            ) -> i32 {
                issue_impl::<$L>(pk_ptr, pk_len, params, req_ptr, req_len, c_bytes, ctx_bytes, out_ptr, out_len)
            }

            #[no_mangle]
            pub unsafe extern "C" fn [<act_prove_spend_ $L>](
                tok_ptr: *const u8,
                tok_len: usize,
                params: *const Params,
                s_bytes: *const u8,
                out_proof_ptr: *mut *mut u8,
                out_proof_len: *mut usize,
                out_pr_ptr: *mut *mut u8,
                out_pr_len: *mut usize,
            ) -> i32 {
                prove_spend_impl::<$L>(tok_ptr, tok_len, params, s_bytes, out_proof_ptr, out_proof_len, out_pr_ptr, out_pr_len)
            }

            #[no_mangle]
            pub unsafe extern "C" fn [<act_refund_ $L>](
                pk_ptr: *const u8,
                pk_len: usize,
                params: *const Params,
                proof_ptr: *const u8,
                proof_len: usize,
                out_ptr: *mut *mut u8,
                out_len: *mut usize,
            ) -> i32 {
                refund_impl::<$L>(pk_ptr, pk_len, params, proof_ptr, proof_len, out_ptr, out_len)
            }

            #[no_mangle]
            pub unsafe extern "C" fn [<act_refund_to_credit_token_ $L>](
                pr_ptr: *const u8,
                pr_len: usize,
                params: *const Params,
                proof_ptr: *const u8,
                proof_len: usize,
                refund_ptr: *const u8,
                refund_len: usize,
                pubkey_ptr: *const u8,
                pubkey_len: usize,
                out_ptr: *mut *mut u8,
                out_len: *mut usize,
            ) -> i32 {
                refund_to_credit_token_impl::<$L>(pr_ptr, pr_len, params, proof_ptr, proof_len, refund_ptr, refund_len, pubkey_ptr, pubkey_len, out_ptr, out_len)
            }

            #[no_mangle]
            pub unsafe extern "C" fn [<act_spend_proof_nullifier_ $L>](
                proof_ptr: *const u8,
                proof_len: usize,
                out_32: *mut u8,
            ) -> i32 {
                spend_proof_nullifier_impl::<$L>(proof_ptr, proof_len, out_32)
            }

            #[no_mangle]
            pub unsafe extern "C" fn [<act_spend_proof_charge_ $L>](
                proof_ptr: *const u8,
                proof_len: usize,
                out_32: *mut u8,
            ) -> i32 {
                spend_proof_charge_impl::<$L>(proof_ptr, proof_len, out_32)
            }

            #[no_mangle]
            pub unsafe extern "C" fn [<act_spend_proof_context_ $L>](
                proof_ptr: *const u8,
                proof_len: usize,
                out_32: *mut u8,
            ) -> i32 {
                spend_proof_context_impl::<$L>(proof_ptr, proof_len, out_32)
            }
        }
    };
}

impl_l_ffi!(8);
impl_l_ffi!(16);
impl_l_ffi!(32);
impl_l_ffi!(64);
impl_l_ffi!(128);
