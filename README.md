# act-hs

Haskell bindings to the [Anonymous Credit Tokens](https://github.com/SamuelSchlesinger/anonymous-credit-tokens) library, enabling privacy-preserving payment systems for web applications and services.

## WARNING

This cryptography is experimental and unaudited. Do not use in production environments without thorough security review.

## Overview

This library provides Haskell FFI bindings to a Rust implementation of the Anonymous Credit Scheme designed by Jonathan Katz and Samuel Schlesinger (see [design document](https://github.com/SamuelSchlesinger/anonymous-credit-tokens/blob/v0/docs/design.pdf)). The system allows:

- **Credit Issuance**: Services can issue digital credit tokens to users
- **Anonymous Spending**: Users can spend credits without revealing their identity
- **Double-Spend Prevention**: The system prevents credits from being used multiple times
- **Privacy-Preserving Refunds**: Unspent credits can be refunded without compromising user privacy

The `L` parameter controls the bit-length of range proofs, determining the maximum credit value a token can hold (`2^L - 1`). This library supports L = 8, 16, 32, 64, and 128, selectable via `TypeApplications` and the `KnownL` type class.

## Prerequisites

- GHC >= 9.6
- Cabal >= 3.0
- Rust toolchain (stable) with `cargo`

The build system automatically compiles the Rust FFI library via a custom `Setup.hs`.

## Building

```bash
cabal build
```

All five L variants are enabled by default. To disable specific variants:

```bash
cabal build -f -l128    # disable L=128
cabal build -f -l64     # disable L=64
```

## Usage

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

### Mixing L Values

`CreditToken` is L-independent: you can issue with one L and spend with another. The L parameter only affects the range proof used for a given operation, not the token itself.

```haskell
-- Issue with L=8 range proof
Right resp  <- issue @L8 sk params req (scalarFromWord64 100) scalarZero
Right token <- toCreditToken pre params pk req resp

-- Spend with L=16 range proof (same token)
(proof, preRef) <- proveSpend @L16 token params (scalarFromWord64 30)
```

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

## API Summary

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

## Testing

```bash
cabal test
```

Runs a full issue/spend/refund roundtrip for each enabled L variant.

## References

- [IETF Draft Specification](https://samuelschlesinger.github.io/ietf-anonymous-credit-tokens/draft-schlesinger-cfrg-act.html)
- [Design Document](https://github.com/SamuelSchlesinger/anonymous-credit-tokens/blob/v0/docs/design.pdf)
- [Rust Library](https://github.com/SamuelSchlesinger/anonymous-credit-tokens)

## License

See the [LICENSE](LICENSE) file for details.
