# act-hs

Haskell bindings to the [Anonymous Credit Tokens](https://github.com/SamuelSchlesinger/anonymous-credit-tokens) library and a [Privacy Pass](https://datatracker.ietf.org/doc/rfc9576/) server implementing the ACT issuance and redemption protocols.

## WARNING

This cryptography is experimental and unaudited. Do not use in production environments without thorough security review.

## Project Structure

This repository is a cabal multi-package project containing two packages:

```
act-hs/          Haskell FFI bindings to the Rust ACT library
act-server/      Privacy Pass ACT server (issuance + redemption)
```

## act-hs (Library)

Haskell FFI bindings to a Rust implementation of the Anonymous Credit Scheme designed by Jonathan Katz and Samuel Schlesinger (see [design document](https://github.com/SamuelSchlesinger/anonymous-credit-tokens/blob/v0/docs/design.pdf)). The system allows:

- **Credit Issuance**: Services can issue digital credit tokens to users
- **Anonymous Spending**: Users can spend credits without revealing their identity
- **Double-Spend Prevention**: The system prevents credits from being used multiple times
- **Privacy-Preserving Refunds**: Unspent credits can be refunded without compromising user privacy

The `L` parameter controls the bit-length of range proofs, determining the maximum credit value a token can hold (`2^L - 1`). This library supports L = 8, 16, 32, 64, and 128, selectable via `TypeApplications` and the `KnownL` type class.

### Library Usage

```haskell
{-# LANGUAGE TypeApplications #-}

import Crypto.AnonymousCreditTokens

main :: IO ()
main = do
  -- Setup
  params <- newParams "my-org" "my-service" "production" "2025-01-01"
  sk     <- generatePrivateKey
  let pk = publicKey sk

  -- Issue 100 credits (L=16 range proof)
  pre  <- generatePreIssuance
  req  <- issuanceRequest pre params
  Right resp  <- issue @L16 sk params req (scalarFromWord64 100) scalarZero
  Right token <- toCreditToken pre params pk req resp

  -- Spend 30 credits
  (proof, preRef) <- proveSpend @L16 token params (scalarFromWord64 30)
  Right ref       <- refund sk params proof
  Right newToken  <- refundToCreditToken preRef params proof ref pk

  -- newToken now holds 70 credits
  print (scalarToWord64 (creditTokenCredits newToken))
```

### The `L` Parameter

Operations that involve range proofs are parameterized by a phantom type (`L8`, `L16`, `L32`, `L64`, `L128`) selected via `TypeApplications`:

| Tag   | Max credits | Use case               |
|-------|-------------|------------------------|
| `L8`  | 255         | Small token systems    |
| `L16` | 65,535      | Moderate credit ranges |
| `L32` | ~4 billion  | Large credit systems   |
| `L64` | ~1.8 * 10^19 | Very large amounts   |
| `L128`| ~3.4 * 10^38 | Maximum range        |

Larger `L` values increase proof size. Choose the smallest `L` that fits your credit range.

`CreditToken` is L-independent: you can issue with one L and spend with another. The L parameter only affects the range proof used for a given operation, not the token itself.

### Cabal Flags

Each L variant can be independently enabled or disabled:

| Flag   | Default | CPP symbol |
|--------|---------|------------|
| `l8`   | True    | `ACT_L8`   |
| `l16`  | True    | `ACT_L16`  |
| `l32`  | True    | `ACT_L32`  |
| `l64`  | True    | `ACT_L64`  |
| `l128` | True    | `ACT_L128` |

Disabling unused variants reduces compile time and binary size.

## act-server (Privacy Pass ACT Server)

A [servant](https://docs.servant.dev/) web server implementing the issuance and redemption protocols for Anonymous Credit Tokens as specified in [draft-schlesinger-privacypass-act](https://samuelschlesinger.github.io/draft-act/draft-schlesinger-privacypass-act.html). The server acts as a joint Issuer and Origin ([Section 4 of RFC 9576](https://datatracker.ietf.org/doc/rfc9576/)), using SQLite for nullifier storage and key persistence.

### Endpoints

| Method | Path | Content Type | Description |
|--------|------|-------------|-------------|
| `POST` | `/token-request` | `application/private-credential-request` / `application/private-credential-response` | Credential issuance (Section 7 of the draft) |
| `POST` | `/token-redeem` | `application/octet-stream` | Token redemption with spend proof (Section 8 of the draft) |
| `GET` | `/issuer-directory` | `application/json` | Issuer public key and configuration |

For detailed wire formats and protocol descriptions, see [act-server/API.md](act-server/API.md).

### Running the Server

```bash
cabal run act-server -- --issuer-name issuer.example.net --origin-info origin.example.com
```

#### CLI Options

| Flag | Default | Description |
|------|---------|-------------|
| `--port` | 8080 | Listen port |
| `--db` | `act-server.db` | SQLite database path |
| `--issuer-name` | (required) | Issuer hostname |
| `--origin-info` | (required) | Origin info string |
| `--credential-context` | (empty) | Hex-encoded context (0 or 32 bytes) |
| `--initial-credits` | 1000 | Credits per issuance |
| `--params-org` | `act-server` | Params domain separator (org) |
| `--params-svc` | `privacy-pass` | Params domain separator (svc) |
| `--params-dep` | `production` | Params domain separator (dep) |
| `--params-ver` | `2026-01-01` | Params domain separator (ver) |

The server automatically generates and persists an issuer key pair in the SQLite database on first run.

### Protocol Flow

1. **Issuance**: Client sends a `TokenRequest` to `POST /token-request`. The server validates the request, issues a credential with `initial_credits`, and returns a `TokenResponse`.

2. **Redemption**: Client spends credits by sending a `Token` (containing a spend proof) to `POST /token-redeem`. The server checks the nullifier for double-spend, verifies the proof, and returns a `Refund`. The client uses the refund to construct a new credential with the remaining balance.

3. **Discovery**: Client queries `GET /issuer-directory` for the issuer's public key and configuration.

Each credential can only be spent once. After spending, the client must wait for the refund before spending again, enforcing concurrency control per credential chain.

### API Documentation

Generated API documentation with wire format details is available at [act-server/API.md](act-server/API.md).

To regenerate:

```bash
cabal run act-server-docs > act-server/API.md
```

## Prerequisites

- GHC >= 9.6
- Cabal >= 3.0
- Rust toolchain (stable) with `cargo`

The build system automatically compiles the Rust FFI library via a custom `Setup.hs`.

## Building

```bash
cabal build all
```

## Testing

```bash
cabal test all --enable-tests
```

This runs:
- **act-hs-test**: Full issue/spend/refund roundtrip for each enabled L variant
- **act-server-test**: End-to-end server test covering issuance, redemption, double-spend rejection, and re-spend from refunded credentials

## API Summary (Library)

### Setup (L-independent)

| Function             | Type                                            |
|----------------------|-------------------------------------------------|
| `newParams`          | `String -> String -> String -> String -> IO Params` |
| `generatePrivateKey` | `IO PrivateKey`                                 |
| `publicKey`          | `PrivateKey -> PublicKey`                        |

### Issuance (L-independent)

| Function              | Type                                             |
|-----------------------|--------------------------------------------------|
| `generatePreIssuance` | `IO PreIssuance`                                 |
| `issuanceRequest`     | `PreIssuance -> Params -> IO IssuanceRequest`    |
| `toCreditToken`       | `PreIssuance -> Params -> PublicKey -> IssuanceRequest -> IssuanceResponse l -> IO (Either ErrorCode CreditToken)` |

### Token Accessors (L-independent)

| Function               | Type                    |
|------------------------|-------------------------|
| `creditTokenNullifier` | `CreditToken -> Scalar` |
| `creditTokenCredits`   | `CreditToken -> Scalar` |

### KnownL Class (L-dependent)

| Method                | Type                                                |
|-----------------------|-----------------------------------------------------|
| `issue`               | `PrivateKey -> Params -> IssuanceRequest -> Scalar -> Scalar -> IO (Either ErrorCode (IssuanceResponse l))` |
| `proveSpend`          | `CreditToken -> Params -> Scalar -> IO (SpendProof l, PreRefund l)` |
| `refund`              | `PrivateKey -> Params -> SpendProof l -> IO (Either ErrorCode Refund)` |
| `refundToCreditToken` | `PreRefund l -> Params -> SpendProof l -> Refund -> PublicKey -> IO (Either ErrorCode CreditToken)` |
| `spendProofNullifier` | `SpendProof l -> Scalar` |
| `spendProofCharge`    | `SpendProof l -> Scalar` |
| `spendProofContext`   | `SpendProof l -> Scalar` |

### Scalar Helpers

| Function          | Type                 |
|-------------------|----------------------|
| `scalarFromWord64`| `Word64 -> Scalar`   |
| `scalarToWord64`  | `Scalar -> Word64`   |
| `scalarZero`      | `Scalar`             |

## References

- [Privacy Pass Architecture (RFC 9576)](https://datatracker.ietf.org/doc/rfc9576/)
- [Privacy Pass ACT Draft (draft-schlesinger-privacypass-act)](https://samuelschlesinger.github.io/draft-act/draft-schlesinger-privacypass-act.html)
- [ACT Cryptographic Scheme (draft-schlesinger-cfrg-act)](https://samuelschlesinger.github.io/ietf-anonymous-credit-tokens/draft-schlesinger-cfrg-act.html)
- [Design Document](https://github.com/SamuelSchlesinger/anonymous-credit-tokens/blob/v0/docs/design.pdf)
- [Rust Library](https://github.com/SamuelSchlesinger/anonymous-credit-tokens)

## License

See the [LICENSE](LICENSE) file for details.
