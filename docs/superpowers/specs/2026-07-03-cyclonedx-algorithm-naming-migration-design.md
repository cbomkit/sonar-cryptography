# CycloneDX Algorithm-Name Migration (Composed Output)

**Branch:** `feature/update-algorithm-names`
**Date:** 2026-07-03
**Status:** Design approved (approach), pending spec review

## 1. Goal

Make the algorithm classes in `mapper/src/main/java/com/ibm/mapper/model` emit names that
conform to the CycloneDX cryptography algorithm **pattern format** defined at
<https://cyclonedx.org/registry/cryptography/#pattern-format> and enumerated in
<https://cyclonedx.org/schema/cryptography-defs.json>.

Two commits already landed a partial migration (`SHA-1`, `ChaCha20-Poly1305`, `RSA-PSS`,
`FFDH`, `SP800_108_CounterKDF` / `SP800_108_FeedbackKDF`, `SLH-DSA`). The full test suite
currently passes. This spec covers the **remaining** work and one **correction** to the prior
commits.

## 2. Pattern format (authoritative rules)

| Notation | Meaning |
|---|---|
| `[ ]` | optional component |
| `( )` | choice between alternatives |
| `\|` | OR |
| `{ }` | placeholder substituted with a variable value |
| `-` | separator between family / components / parameters |

A concrete name is the pattern with every present optional resolved and every placeholder
substituted, e.g. `AES[-{keyLength}][-{mode}]` → `AES-256-CBC`.

## 3. Scope

**In scope:** only the ~65 algorithm classes the schema explicitly names (Section 6 table).

**Out of scope (left byte-for-byte untouched):** the ~110 classes with no schema pattern —
BouncyCastle lightweight-crypto candidates and pre-standardization schemes. This explicitly
includes, and the migration must **not** touch: `Elephant`/`Dumbo`/`Jumbo`/`Delirium`,
`Sparkle`/`Schwaemm`/`Esch`/`XOEsch`, `Isap*`, `PhotonBeetle*`, `Xoodyak`, `Grain*`,
`Kalyna`, `Kupyna`, `Ascon` (base dispatcher), `Ascon128a`/`Ascon80pq`, `BLAKE`/`BLAKE2X`,
`Skein`, `Threefish`, `Tiger`, `TEA`/`XTEA`, `VMPC*`, `ZUC`, `NOEKEON`, `LEA`,
`NTRU*`, `Kyber`, `Dilithium`, `Falcon`, `FrodoKEM`, `SABER`, `BIKE`,
`HQC`, `ClassicMcEliece`, `GMSS`, `HSS`, `Rainbow`, `Picnic`, `QTESLA`, `GeMSS`, `Fernet`,
`PSK`, `Kerberos`, `DSS`, `DSTU4145`, `ECCPWD`, `ECNR`, `DLIES`, `IES`, `ECIESKEM`, `DESede`,
`RSAKEM`, `NaccacheStern`, `ConcatenationKDF`, `KDF1`/`KDF2`/`KDFSession`, `ANSIX931`,
`ISO9796`, `RFC3211Wrap`, `MarsupilamiFourteen`, `KangarooTwelve`, `Keccak`, `PKCS12PBE`,
`CryptoPro`, and all GOST classes (Section 3.1).

### 3.1 Ambiguous cases — resolved decisions

- **GOST family — out of scope.** Schema names are version-less (`GOSTR3410`, `GOSTR3411`,
  `GOST38147`) while the model has year-versioned classes (`GOSTR341012`, `GOSTR341094`,
  `GOST28147`, `GOST341194`, `GOSTR341112`, `GOSTR34122015`). The mapping is lossy and the
  schema's `GOST38147` appears to be a typo for the real `28147`. Leave all GOST classes
  untouched; record the divergence here.
- **`DESede` — left as-is.** Both `DESede` (a BouncyCastle triple-DES engine class) and
  `TripleDES` (already `3DES`) are triple DES. Only `TripleDES` carries the schema name so two
  classes never emit the identical string `3DES`. `DESede` keeps its current name.
- **`MQV` → `FFMQV`.** The class models finite-field MQV, which the schema names `FFMQV`.
  `ECMQV` already matches its schema name.

## 4. Design: three layers of change

### Layer 1 — base `NAME` constants
Rename the static `NAME` string in each in-scope class to the schema family token
(Section 6 "Target NAME" column).

### Layer 2 — composition separators & component tokens
The core "composed output" fix. Today `KeyLength.asString()` returns a bare number (`"256"`)
and `AES.asString()` appends it **without a separator**, producing `AES256-CBC`. The schema
requires `AES-256-CBC`.

- **Fix locally in each algorithm's `asString()`**, not globally: change
  `sb.append(k.asString())` → `sb.append("-").append(k.asString())`. `KeyLength.asString()`,
  `DigestSize.asString()`, `TagLength.asString()`, etc. keep returning bare numbers so that
  non-schema consumers are unaffected and the number renders correctly *inside* a hyphenated
  pattern.
- **Verify component sub-tokens** match schema spelling. Modes (`CBC`, `GCM`, `ECB`, `CFB`,
  `OFB`, `CTR`, `XTS`, `CTS`, `CCM`, `KW`, `KWP`, `SIV`, `OCB`, `GCM-SIV`), paddings
  (`PKCS7`, …), and digest tokens (`SHA-256`, `SHA3-256`) are checked against the pattern
  strings. Any mismatch is corrected in the component class (affects only how that token
  renders inside schema-named algorithms; document any cross-cutting effect).

### Layer 2.1 — per-pattern composition rule (authoritative)

**Compose exactly the parameters the schema pattern lists, in the pattern's order, and no
others.** A parameter that a class captures as a child but that the pattern omits is NOT
appended. Consequences:

- `AES[-(128|192|256)][-mode][-{padding}][-{ivlen}]` → keyLength + mode + **padding** kept.
- `DES[-{keyLength}][-{mode}]` / `3DES[-{keyLength}][-{mode}]` → keyLength + mode; **padding
  dropped** (DES currently appends padding — remove it).
- `CAST5[-{keyLength}][-{mode}]`, `RC2/RC5/RC6[-{keyLength}][-{mode}]` → keyLength + mode, no
  padding.
- `RC4[-{keyLength}]`, `ElGamal[-{keyLength}]` → keyLength only, no mode/padding.
- `SM4[-{mode}][-{padding}]` → mode + padding, no keyLength.
- `IDEA[-{mode}]` → mode only.
- `SEED-128[-{mode}][-{padding}]` → keyLength (always default 128) + mode + padding →
  `SEED-128-CBC`.
- `Ascon-AEAD128`, `Ascon-Hash256`, `Ascon-XOF128` → no parameters (pattern is a fixed
  token); rename only, compose nothing.
- **IV length and tag length are out of scope** for this migration even where a pattern lists
  them (e.g. AES-GCM `[-{tagLength}][-{ivLength}]`): the model does not capture them uniformly
  and AES does not compose them today. Deferred and noted here.

Block ciphers use a shared helper on `Algorithm` to avoid ~13 near-identical `asString()`
copies (DRY, and an improvement to the existing AES/DES duplication):

```java
/** Composes name as base[-keyLength][-mode][-padding] per the CycloneDX pattern format. */
protected @Nonnull String composeName(boolean keyLength, boolean mode, boolean padding) {
    final StringBuilder sb = new StringBuilder(this.name);
    if (keyLength) this.hasChildOfType(KeyLength.class).ifPresent(k -> sb.append("-").append(k.asString()));
    if (mode) this.hasChildOfType(Mode.class).ifPresent(m -> sb.append("-").append(m.asString()));
    if (padding) this.hasChildOfType(Padding.class).ifPresent(p -> sb.append("-").append(p.asString()));
    return sb.toString();
}
```

Per-class wiring: AES `composeName(true,true,true)`; DES/3DES `(true,true,false)`;
ARIA/CAMELLIA/Twofish/Serpent/Blowfish/SEED `(true,true,true)`; CAST5/CAST6/RC2/RC5/RC6
`(true,true,false)`; RC4/ElGamal `(true,false,false)`; SM4 `(false,true,true)`; IDEA
`(false,true,false)`.

### Layer 3 — component ordering per class
Several classes currently compose components in the wrong order relative to the schema and
must be reworked (not just separator-fixed):

| Class | Current output | Schema pattern | Target output |
|---|---|---|---|
| `CMAC` | `AES-CMAC` (`cipher-name`) | `CMAC[-{cipherAlgorithm}][-{length}]` | `CMAC-AES` |
| `DSA` | `SHA-256-DSA` (`digest-name`) | `DSA[-{length}][-{hashAlgorithm}]` | `DSA-2048-SHA-256` |
| `RSA` (sig) | `SHA-256-RSA` (`digest-name`) | `RSA-PKCS1-1.5[-{digestAlgorithm}][-{keyLength}]` | `RSA-PKCS1-1.5-SHA-256` |
| `RSAssaPSS` | (base) | `RSA-PSS[-{hash}][-{mgf}][-{saltLen}][-{keyLen}]` | `RSA-PSS-SHA-256-…` |
| `ChaCha20` (+Poly1305) | `ChaCha20Poly1305` | `ChaCha20-Poly1305` | `ChaCha20-Poly1305` |

`RSA` needs the most care: the schema splits RSA by padding into three families —
`RSA-PKCS1-1.5` (default signature / PKCS#1 v1.5), `RSA-OAEP` (OAEP padding), and `RSA-PSS`
(the `RSAssaPSS` class). The `RSA` class `asString()` must select the family from its
padding/usage children. The current OAEP branch already yields `RSA-OAEP`; the signature and
key-length branches must be re-ordered to `RSA-PKCS1-1.5[-{digest}][-{keyLength}]`.

## 5. Correction to prior commits: `SHA3`

Commit `09240342` renamed `SHA3` → `SHA-3` and added a JavaDoc claiming the schema says
`SHA-3-256`. The schema pattern is `SHA3-(224|256|384|512)` → `SHA3-256` (no hyphen after
`SHA`). **Revert `SHA3.java`** so `NAME = "SHA3"` (composed output `SHA3-256`), and fix the
misquoted JavaDoc to state the correct pattern.

## 6. Mapping table (in-scope classes)

Legend for "Change": **R** = base NAME rename only · **S** = separator/composition fix ·
**O** = component-order rework · **✓** = already correct (verify only).

### Symmetric block ciphers
| Class | Current NAME | Target NAME | Schema pattern | Change |
|---|---|---|---|---|
| `AES` | `AES` | `AES` | `AES[-{keyLength}][-{mode}]…` | S (keyLength hyphen) |
| `Aria` | `Aria` | `ARIA` | `ARIA-(128\|192\|256)[-{mode}]` | R+S |
| `Camellia` | `Camellia` | `CAMELLIA` | `CAMELLIA-(128\|192\|256)[-{mode}]` | R+S |
| `Twofish` | `Twofish` | `Twofish` | `Twofish-(128\|192\|256)[-{mode}]` | S |
| `Serpent` | `Serpent` | `Serpent` | `Serpent-(128\|192\|256)[-{mode}]` | S |
| `Blowfish` | `Blowfish` | `Blowfish` | `Blowfish[-{keyLength}][-{mode}]` | S |
| `CAST128` | `CAST-128` | `CAST5` | `CAST5[-{keyLength}][-{mode}]` | R+S |
| `CAST256` | `CAST-256` | `CAST6` | `CAST6[-{keyLength}][-{mode}]` | R+S |
| `DES` | `DES` | `DES` | `DES[-{keyLength}][-{mode}]` | S (keyLength hyphen) |
| `TripleDES` | `3DES` | `3DES` | `3DES[-{keyLength}][-{mode}]` | ✓ |
| `IDEA` | `IDEA` | `IDEA` | `IDEA[-{mode}]` | ✓ |
| `RC2` | `RC2` | `RC2` | `RC2[-{keyLength}][-{mode}]` | S |
| `RC5` | `RC5` | `RC5` | `RC5[-{keyLength}][-{mode}]` | S |
| `RC6` | `RC6` | `RC6` | `RC6[-{keyLength}][-{mode}]` | S |
| `SEED` | `SEED` | `SEED` | `SEED-128[-{mode}]` | S |
| `SM4` | `SM4` | `SM4` | `SM4[-{mode}]` | ✓/S |

### Stream ciphers
| Class | Current | Target | Schema | Change |
|---|---|---|---|---|
| `RC4` | `RC4` | `RC4` | `RC4[-{keyLength}]` | S |
| `ChaCha20` | `ChaCha20` | `ChaCha20` | `ChaCha20` | ✓ (Poly1305 join → O) |
| `Salsa20` | `Salsa20` | `Salsa20` | `Salsa20` | ✓ |
| `Poly1305` | `Poly1305` | `Poly1305` | `Poly1305` | ✓ |
| `ChaCha20Poly1305` | `ChaCha20-Poly1305` | `ChaCha20-Poly1305` | `ChaCha20-Poly1305` | ✓ |
| `HC` | `HC` | `HC` | `HC-(128\|256)` | S |
| `SipHash` | `SipHash` | `SipHash` | `SipHash[-{c}-{f}]` | ✓ |

### AEAD (Ascon standardized subset)
| Class | Current | Target | Schema | Change |
|---|---|---|---|---|
| `Ascon128` | `Ascon-128` | `Ascon-AEAD128` | `Ascon-AEAD128` | R |
| `AsconHash` | `Ascon-Hash` | `Ascon-Hash256` | `Ascon-Hash256` | R |
| `AsconXof` | `Ascon-Xof` | `Ascon-XOF128` | `Ascon-XOF128` | R |

### Hashes / XOFs
| Class | Current | Target | Schema | Change |
|---|---|---|---|---|
| `SHA2` | `SHA-` | `SHA-` | `SHA-1`, `SHA-(224\|256\|384\|512…)` | ✓ |
| `SHA3` | `SHA-3` | `SHA3` | `SHA3-(224\|256\|384\|512)` | **R (correction)** |
| `SHAKE` | `SHAKE` | `SHAKE` | `SHAKE(128\|256)` | ✓ |
| `CSHAKE` | `cSHAKE` | `cSHAKE` | `cSHAKE(128\|256)` | ✓ |
| `MD2` | `MD2` | `MD2` | `MD2` | ✓ |
| `MD4` | `MD4` | `MD4` | `MD4` | ✓ |
| `MD5` | `MD5` | `MD5` | `MD5` | ✓ |
| `RIPEMD` | `RIPEMD` | `RIPEMD` | `RIPEMD-(128\|160\|256\|320)` | ✓ |
| `Whirlpool` | `Whirlpool` | `Whirlpool` | `Whirlpool` | ✓ |
| `BLAKE2b` | `BLAKE2b` | `BLAKE2b` | `BLAKE2b-(160\|256\|384\|512)` | S (verify) |
| `BLAKE2s` | `BLAKE2s` | `BLAKE2s` | `BLAKE2s-(160\|256)` | S (verify) |
| `BLAKE3` | `BLAKE3` | `BLAKE3` | `BLAKE3[-{outputLength}]` | S (verify) |
| `TupleHash` | `TupleHash` | `TupleHash` | `TupleHash(128\|256)` | ✓ |
| `ParallelHash` | `ParallelHash` | `ParallelHash` | `ParallelHash(128\|256)` | ✓ |
| `SM3` | `SM3` | `SM3` | `SM3` | ✓ |

### MACs
| Class | Current | Target | Schema | Change |
|---|---|---|---|---|
| `HMAC` | `HMAC` | `HMAC` | `HMAC[-{hash}][-{tagLength}]` | ✓ |
| `CMAC` | `CMAC` | `CMAC` | `CMAC[-{cipher}][-{length}]` | **O** |
| `KMAC` | `KMAC` | `KMAC` | `KMAC(128\|256)`, `KMACXOF(128\|256)` | ✓ |
| `Poly1305` | `Poly1305` | `Poly1305` | `Poly1305` | ✓ |

### Asymmetric / signatures / KEX
| Class | Current | Target | Schema | Change |
|---|---|---|---|---|
| `RSA` | `RSA` | `RSA` (→ `RSA-PKCS1-1.5`/`RSA-OAEP` composed) | `RSA-PKCS1-1.5…`, `RSA-OAEP…` | **O** |
| `RSAssaPSS` | (empty/base) | `RSA-PSS` | `RSA-PSS[-{hash}][-{mgf}]…` | O (verify prior commit) |
| `MGF1` | (empty/base) | `MGF1` | `{maskGenAlgorithm}` = `MGF1` | ✓ |
| `DSA` | `DSA` | `DSA` | `DSA[-{length}][-{hash}]` | **O** |
| `ECDSA` | `ECDSA` | `ECDSA` | `ECDSA[-{curve}][-{hash}]` | ✓ |
| `EdDSA` | `EdDSA` | `EdDSA` | (family) | ✓ |
| `Ed25519` | `Ed25519` | `Ed25519` | `Ed(25519\|448)[-(ph\|ctx)]` | ✓ |
| `Ed448` | `Ed448` | `Ed448` | `Ed(25519\|448)[-(ph\|ctx)]` | ✓ |
| `ElGamal` | `ElGamal` | `ElGamal` | `ElGamal[-{keyLength}]` | S |
| `ECDH` | `ECDH` | `ECDH` | `ECDH[E][-{curve}]` | ✓ |
| `DH` | `FFDH` | `FFDH` | `FFDH(E)[-{namedGroup}]` | ✓ |
| `X25519` | `x25519` | `x25519` | `x25519` | ✓ |
| `X448` | `x448` | `x448` | `x448` | ✓ |
| `ECMQV` | `ECMQV` | `ECMQV` | `ECMQV[-{curve}]` | ✓ |
| `MQV` | `MQV` | `FFMQV` | `FFMQV[-{namedGroup}]` | R |
| `ECIES` | `ECIES` | `ECIES` | `ECIES[-{curve}][-{kdf}]…` | ✓ |
| `SM2` | `SM2` | `SM2` | `SM2[-256]` | ✓ |

### PQC
| Class | Current | Target | Schema | Change |
|---|---|---|---|---|
| `MLDSA` | `ML-DSA` | `ML-DSA` | `ML-DSA-(44\|65\|87)` | ✓ |
| `MLKEM` | `ML-KEM` | `ML-KEM` | `ML-KEM-(512\|768\|1024)` | ✓ |
| `SPHINCSPlus` | `SLH-DSA` | `SLH-DSA` | `SLH-DSA-(SHA2\|SHAKE)-…` | ✓ (verify) |
| `XMSS` | `XMSS` | `XMSS` | `XMSS-(SHA2\|SHAKE)…` | S (verify) |
| `XMSSMT` | `XMSS^MT` | `XMSSMT` | `XMSSMT-(SHA2\|SHAKE)…` | R |
| `LMS` | `LMS` | `LMS` | `LMS[_{hash}]…` (underscore) | ✓ |

### KDFs / PBE
| Class | Current | Target | Schema | Change |
|---|---|---|---|---|
| `HKDF` | `HKDF` | `HKDF` | `HKDF[-{hash}]` | ✓ |
| `PBKDF1` | `PBKDF1` | `PBKDF1` | `PBKDF1[-{hash}]…` | ✓ (verify) |
| `PBKDF2` | `PBKDF2` | `PBKDF2` | `PBKDF2[-{hash}]…` | ✓ (verify) |
| `PBES1` | `PBES1` | `PBES1` | `PBES1[-{enc}][-{kdf}]…` | ✓ (verify) |
| `PBES2` | `PBES2` | `PBES2` | `PBES2[-{enc}][-{kdf}]…` | ✓ (verify) |
| `Scrypt` | `SCRYPT` | `scrypt` | `scrypt[-{N}][-{r}][-{p}][-{dkLen}]` | R |
| `KDFCounter` | `SP800_108_CounterKDF` | `SP800_108_CounterKDF` | `SP800_108_(CounterKDF\|…)` | ✓ |
| `KDFFeedback` | `SP800_108_FeedbackKDF` | `SP800_108_FeedbackKDF` | `SP800_108_(…\|FeedbackKDF\|…)` | ✓ |
| `KDFDoublePipeline` | `KDF in Double-Pipeline Mode` | `SP800_108_DoublePipelineKDF` | `SP800_108_(…\|DoublePipelineKDF\|…)` | R |
| `ANSIX942` | `ANSI X9.42` | `ANSI-KDF-X9.42` | `ANSI-KDF-X9.42[-{hash}]` | R |
| `ANSIX963` | `ANSI X9.63` | `ANSI-KDF-X9.63` | `ANSI-KDF-X9.63[-{hash}]` | R |

> Rows marked "verify" require confirming the composed output already matches the pattern
> before concluding no change is needed; the implementation plan will make each an explicit
> check with a unit assertion.

## 7. Test & fixture strategy

~130 test files across `java`, `python`, `go` modules assert `asString()` values, plus the
`sonar-cryptography-plugin/bom/bom.json` fixture and any golden CBOM outputs.

Process, per module in the order `mapper → java → python → go`:
1. Apply the Section 6 model changes.
2. Run `mvn test -pl <module>`.
3. For each failure, the diff is a deterministic old-name → new-name substitution; update the
   assertion to the new composed name. Do **not** weaken assertions or delete tests to make
   them pass — every changed expectation must correspond to a Section 6 rename.
4. Regenerate `bom.json` from a clean run and commit the regenerated fixture.
5. Re-run the full suite (`mvn test`) to confirm green.

`mvn spotless:apply` and `mvn checkstyle:check` must pass before committing (JavaDoc updated
where NAME changes; Apache license headers preserved).

## 8. Non-goals

- No changes to detection rules, enricher logic, or CBOM structure beyond names.
- No renaming of out-of-scope (non-schema) algorithms.
- No changes to `KeyLength`/`DigestSize`/`TagLength` `asString()` return values (separators
  are added at the algorithm-composition site instead).

## 9. Risks

- **Order-rework classes (RSA, DSA, CMAC)** carry the most behavioral risk; they get dedicated
  unit tests asserting the full composed string for each variant.
- **`bom.json` churn** is large but mechanical; review it as a rename-only diff.
- **Cross-module drift:** a name used by a Java test may also appear in Python/Go fixtures;
  Section 7's module ordering plus a final full-suite run catches stragglers.
