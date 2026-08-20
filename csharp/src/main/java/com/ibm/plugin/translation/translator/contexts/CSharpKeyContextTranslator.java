/*
 * Sonar Cryptography Plugin
 * Copyright (C) 2024 PQCA
 *
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to you under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.ibm.plugin.translation.translator.contexts;

import com.ibm.engine.language.csharp.tree.CSharpTree;
import com.ibm.engine.model.Algorithm;
import com.ibm.engine.model.IValue;
import com.ibm.engine.model.KeyAction;
import com.ibm.engine.model.KeySize;
import com.ibm.engine.model.ParameterIdentifier;
import com.ibm.engine.model.ValueAction;
import com.ibm.engine.model.context.DetectionContext;
import com.ibm.engine.model.context.IDetectionContext;
import com.ibm.engine.rule.IBundle;
import com.ibm.mapper.IContextTranslation;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.KeyLength;
import com.ibm.mapper.model.ParameterSetIdentifier;
import com.ibm.mapper.model.algorithms.DSA;
import com.ibm.mapper.model.algorithms.ECDH;
import com.ibm.mapper.model.algorithms.ECDSA;
import com.ibm.mapper.model.algorithms.HKDF;
import com.ibm.mapper.model.algorithms.KDFCounter;
import com.ibm.mapper.model.algorithms.MGF1;
import com.ibm.mapper.model.algorithms.MLDSA;
import com.ibm.mapper.model.algorithms.MLKEM;
import com.ibm.mapper.model.algorithms.PBKDF1;
import com.ibm.mapper.model.algorithms.PBKDF2;
import com.ibm.mapper.model.algorithms.RSA;
import com.ibm.mapper.model.algorithms.SPHINCSPlus;
import com.ibm.mapper.model.algorithms.X25519;
import com.ibm.mapper.model.functionality.Decapsulate;
import com.ibm.mapper.model.functionality.Encapsulate;
import com.ibm.mapper.model.functionality.Generate;
import com.ibm.mapper.model.functionality.KeyDerivation;
import com.ibm.mapper.utils.DetectionLocation;
import java.util.Optional;
import javax.annotation.Nonnull;

/** Translates {@link com.ibm.engine.model.context.KeyContext} detections for .NET APIs. */
public final class CSharpKeyContextTranslator implements IContextTranslation<CSharpTree> {

    @Override
    public @Nonnull Optional<INode> translate(
            @Nonnull IBundle bundleIdentifier,
            @Nonnull IValue<CSharpTree> value,
            @Nonnull IDetectionContext detectionContext,
            @Nonnull DetectionLocation detectionLocation) {

        if (value instanceof ValueAction<?>
                && detectionContext instanceof DetectionContext context) {
            String kind = context.get("kind").orElse("");
            return switch (kind) {
                case "RSA" -> Optional.of(new RSA(detectionLocation));
                case "ECDSA" -> Optional.of(new ECDSA(detectionLocation));
                case "ECDH" -> Optional.of(new ECDH(detectionLocation));
                // X25519 (DotNetX25519DiffieHellman.java): reuses the existing X25519 mapper
                // model class (already used by the JCA XDH/X25519 and Go crypto/ecdh
                // translations) — no new mapper model class was needed. See that rule class's
                // javadoc for why X25519DiffieHellman's API shape (no Create(), no
                // DeriveKeyMaterial/FromHash/FromHmac/Tls, no settable KeySize) differs from
                // ECDiffieHellman's.
                case "X25519" -> Optional.of(new X25519(detectionLocation));
                case "DSA" -> Optional.of(new DSA(detectionLocation));
                // MGF1 (DotNetLegacyFormatters.java, PKCS1MaskGenerationMethod): reuses the
                // existing MGF1 mapper model class (already used by JcaMGFMapper/
                // JcaOAEPPaddingMapper for JCA's OAEP padding translation) — no new mapper model
                // class was needed. KeyContext is reused here purely as the generic "identify
                // which standalone algorithm was just constructed" context already used for the
                // other cases in this switch, not because MGF1 is a "key" algorithm per se — see
                // that rule class's javadoc for the full rationale.
                case "MGF1" -> Optional.of(new MGF1(detectionLocation));
                // ML-KEM (DotNetMLKem.java): generic top-level node. The parameter set (when
                // captured — see the ParameterIdentifier branch below) is attached as a child by
                // the tree-shape-preserving translation process, yielding "ML-KEM-768" etc. via
                // MLKEM#asString(). Reuses the mapper model class already used by the JCA,
                // BouncyCastle and Go crypto/mlkem translations — no new model class needed.
                case "KEM" -> Optional.of(new MLKEM(detectionLocation));
                // ML-DSA (DotNetMLDsa.java): generic top-level node, same shape as the "KEM" case
                // above. The parameter set (when captured — see the ParameterIdentifier branch
                // below) is attached as a child, yielding "ML-DSA-44"/"ML-DSA-65"/"ML-DSA-87" via
                // MLDSA#asString(). Reuses the MLDSA mapper model class that already existed
                // (added alongside MLKEM) — no new model class needed for plain ML-DSA.
                // "MLDSA_COMPOSITE" (CompositeMLDsa/CompositeMLDsaCng) intentionally maps to the
                // very same MLDSA node: no composite/hybrid algorithm concept exists yet in the
                // mapper model (verified: grep -rl "Composite\|Hybrid" mapper/ found nothing), so
                // rather than fabricate one or drop the detection, the full CompositeMLDsaAlgorithm
                // name (e.g. "MLDsa44WithECDsaP256") is captured verbatim as the
                // ParameterSetIdentifier below — see DotNetMLDsa's class javadoc for the full
                // rationale and the recommendation for a future proper composite/hybrid model.
                case "MLDSA", "MLDSA_COMPOSITE" -> Optional.of(new MLDSA(detectionLocation));
                // SLH-DSA (DotNetSlhDsa.java): generic top-level node, same shape as the "MLDSA"
                // case above. The parameter set (when captured — see the ParameterIdentifier
                // branch below) is attached as a child, yielding e.g. "SLH-DSA-SHA2-128s" via
                // SPHINCSPlus#asString(). Reuses the SPHINCSPlus mapper model class that already
                // existed (used by the BouncyCastle SPHINCSPlusSigner translation) — no new model
                // class needed, per the class's "SLH-DSA .. Other Names: SPHINCS+" documentation.
                case "SLHDSA" -> Optional.of(new SPHINCSPlus(detectionLocation));
                case "KDF" -> Optional.of(new PBKDF2(detectionLocation));
                // Key derivation functions (DotNetKeyDerivation.java): HKDF and
                // SP800108HmacCounterKdf's static one-shot calls, and PasswordDeriveBytes's
                // constructor, map directly to their KDF algorithm model node — the class itself
                // *is* the KDF (mirrors the "KDF" -> PBKDF2 case above for Rfc2898DeriveBytes),
                // unlike the ECDiffieHellman derive operations below (see that case's comment).
                case "KDF_HKDF" -> Optional.of(new HKDF(detectionLocation));
                case "KDF_SP800108" -> Optional.of(new KDFCounter(detectionLocation));
                case "KDF_PASSWORD_DERIVE_BYTES" -> Optional.of(new PBKDF1(detectionLocation));
                // Instance derive-operations on an already-identified KDF object
                // (SP800108HmacCounterKdf.DeriveKey, PasswordDeriveBytes.GetBytes/
                // CryptDeriveKey): reuses the same generic KeyDerivation functionality node as
                // the ECDiffieHellman derive operations below (Batch 3 pattern), captured as a
                // child of the already-typed KDF algorithm node rather than folded into it.
                case "KDF_SP800108_DERIVE_KEY", "KDF_PDB_GET_BYTES", "KDF_PDB_CRYPT_DERIVE_KEY" ->
                        Optional.of(new KeyDerivation(detectionLocation));
                // ECDiffieHellman key-derivation operations (DotNetECDiffieHellman.java):
                // no typed CipherAction.Action fits "derive a key", so each operation is
                // captured with a generic ValueActionFactory under its own "kind" and
                // dispatched here (see that class's javadoc for the full rationale).
                case "ECDH_DERIVE_KEY_MATERIAL",
                        "ECDH_DERIVE_KEY_FROM_HASH",
                        "ECDH_DERIVE_KEY_FROM_HMAC",
                        "ECDH_DERIVE_KEY_TLS" ->
                        Optional.of(new KeyDerivation(detectionLocation));
                // DeriveRawSecretAgreement returns the raw shared secret with no KDF
                // post-processing, so it maps to the generic Generate functionality instead
                // of KeyDerivation (mirroring how GenerateIV is translated in
                // CSharpCipherContextTranslator).
                case "ECDH_DERIVE_RAW_SECRET_AGREEMENT" ->
                        Optional.of(new Generate(detectionLocation));
                // X25519 DeriveRawSecretAgreement (DotNetX25519DiffieHellman.java): same
                // reasoning as the ECDH case immediately above — raw shared secret, no KDF
                // post-processing, so it maps to Generate rather than KeyDerivation.
                case "X25519_DERIVE_RAW_SECRET_AGREEMENT" ->
                        Optional.of(new Generate(detectionLocation));
                default -> Optional.empty();
            };
        } else if (value instanceof KeySize<?> keySize) {
            return Optional.of(new KeyLength(keySize.getValue(), detectionLocation));
        } else if (value instanceof ParameterIdentifier<?> parameterIdentifier
                && detectionContext instanceof DetectionContext context
                && "KEM".equals(context.get("kind").orElse(""))) {
            // ML-KEM parameter set (DotNetMLKem.java): captured from the MLKemAlgorithm argument
            // (e.g. MLKemAlgorithm.MLKem768, resolved to the bare enum member name "MLKem768" — see
            // that class's javadoc). Mapped to the numeric suffix expected by
            // MLKEM(int, DetectionLocation) / ParameterSetIdentifier, matching the
            // "768"/"512"/"1024"
            // values already produced by JcaKemMapper/GoCryptoKEMMapper for the same algorithm.
            return switch (parameterIdentifier.asString()) {
                case "MLKem512" ->
                        Optional.of(new ParameterSetIdentifier("512", detectionLocation));
                case "MLKem768" ->
                        Optional.of(new ParameterSetIdentifier("768", detectionLocation));
                case "MLKem1024" ->
                        Optional.of(new ParameterSetIdentifier("1024", detectionLocation));
                default -> Optional.empty();
            };
        } else if (value instanceof ParameterIdentifier<?> parameterIdentifier
                && detectionContext instanceof DetectionContext context
                && "MLDSA".equals(context.get("kind").orElse(""))) {
            // ML-DSA parameter set (DotNetMLDsa.java): captured from the MLDsaAlgorithm argument
            // (e.g. MLDsaAlgorithm.MLDsa65, resolved to the bare enum member name "MLDsa65"),
            // mapped to the numeric suffix expected by MLDSA(int, DetectionLocation) /
            // ParameterSetIdentifier — mirrors the "KEM" branch above for MLKemAlgorithm.
            return switch (parameterIdentifier.asString()) {
                case "MLDsa44" -> Optional.of(new ParameterSetIdentifier("44", detectionLocation));
                case "MLDsa65" -> Optional.of(new ParameterSetIdentifier("65", detectionLocation));
                case "MLDsa87" -> Optional.of(new ParameterSetIdentifier("87", detectionLocation));
                default -> Optional.empty();
            };
        } else if (value instanceof ParameterIdentifier<?> parameterIdentifier
                && detectionContext instanceof DetectionContext context
                && "MLDSA_COMPOSITE".equals(context.get("kind").orElse(""))) {
            // Composite ML-DSA parameter set (DotNetMLDsa.java): the CompositeMLDsaAlgorithm
            // member name (e.g. "MLDsa44WithECDsaP256") is a compound identifier, not a simple
            // numeric parameter set, so it is captured verbatim rather than parsed — see
            // DotNetMLDsa's class javadoc for why no structured composite/hybrid model is used.
            return Optional.of(
                    new ParameterSetIdentifier(parameterIdentifier.asString(), detectionLocation));
        } else if (value instanceof ParameterIdentifier<?> parameterIdentifier
                && detectionContext instanceof DetectionContext context
                && "SLHDSA".equals(context.get("kind").orElse(""))) {
            // SLH-DSA parameter set (DotNetSlhDsa.java): captured from the SlhDsaAlgorithm
            // argument (e.g. SlhDsaAlgorithm.SlhDsaSha2_128s, resolved to the bare enum member
            // name "SlhDsaSha2_128s"), mapped to the FIPS 205 parameter set suffix (e.g.
            // "SHA2-128s") expected by SPHINCSPlus's String constructor / ParameterSetIdentifier —
            // mirrors the "MLDSA" branch above for MLDsaAlgorithm. All 12 values verified against
            // the official SlhDsaAlgorithm reference page (SHA2 and SHAKE families, each with
            // 128/192/256-bit security levels and s(mall)/f(ast) speed tradeoffs).
            return switch (parameterIdentifier.asString()) {
                case "SlhDsaSha2_128s" ->
                        Optional.of(new ParameterSetIdentifier("SHA2-128s", detectionLocation));
                case "SlhDsaSha2_128f" ->
                        Optional.of(new ParameterSetIdentifier("SHA2-128f", detectionLocation));
                case "SlhDsaSha2_192s" ->
                        Optional.of(new ParameterSetIdentifier("SHA2-192s", detectionLocation));
                case "SlhDsaSha2_192f" ->
                        Optional.of(new ParameterSetIdentifier("SHA2-192f", detectionLocation));
                case "SlhDsaSha2_256s" ->
                        Optional.of(new ParameterSetIdentifier("SHA2-256s", detectionLocation));
                case "SlhDsaSha2_256f" ->
                        Optional.of(new ParameterSetIdentifier("SHA2-256f", detectionLocation));
                case "SlhDsaShake128s" ->
                        Optional.of(new ParameterSetIdentifier("SHAKE-128s", detectionLocation));
                case "SlhDsaShake128f" ->
                        Optional.of(new ParameterSetIdentifier("SHAKE-128f", detectionLocation));
                case "SlhDsaShake192s" ->
                        Optional.of(new ParameterSetIdentifier("SHAKE-192s", detectionLocation));
                case "SlhDsaShake192f" ->
                        Optional.of(new ParameterSetIdentifier("SHAKE-192f", detectionLocation));
                case "SlhDsaShake256s" ->
                        Optional.of(new ParameterSetIdentifier("SHAKE-256s", detectionLocation));
                case "SlhDsaShake256f" ->
                        Optional.of(new ParameterSetIdentifier("SHAKE-256f", detectionLocation));
                default -> Optional.empty();
            };
        } else if (value instanceof KeyAction<?> keyAction) {
            // ML-KEM encapsulate/decapsulate (DotNetMLKem.java): KeyAction.Action already defines
            // ENCAPSULATION/DECAPSULATION (used identically by the Go crypto/mlkem translation in
            // GoKeyContextTranslator), so no new engine or mapper enum value was needed.
            return switch (keyAction.getAction()) {
                case ENCAPSULATION -> Optional.of(new Encapsulate(detectionLocation));
                case DECAPSULATION -> Optional.of(new Decapsulate(detectionLocation));
                default -> Optional.empty();
            };
        } else if (value instanceof Algorithm<?>) {
            // AsymmetricAlgorithm.Create(string) — string table verified against the official API
            // reference (learn.microsoft.com), see DotNetAlgorithmFactory javadoc. Unlike the
            // ValueAction branch above (dispatched by a fixed per-rule "kind" property), a single
            // AsymmetricAlgorithm.Create(string) call site can produce any of RSA/DSA/ECDSA/ECDH,
            // so the concrete algorithm here is resolved purely from the captured runtime string.
            return switch (value.asString().toUpperCase().trim()) {
                case "RSA", "SYSTEM.SECURITY.CRYPTOGRAPHY.RSA" ->
                        Optional.of(new RSA(detectionLocation));
                case "DSA", "SYSTEM.SECURITY.CRYPTOGRAPHY.DSA" ->
                        Optional.of(new DSA(detectionLocation));
                case "ECDSA", "ECDSACNG", "SYSTEM.SECURITY.CRYPTOGRAPHY.ECDSACNG" ->
                        Optional.of(new ECDSA(detectionLocation));
                case "ECDH",
                        "ECDIFFIEHELLMAN",
                        "ECDIFFIEHELLMANCNG",
                        "SYSTEM.SECURITY.CRYPTOGRAPHY.ECDIFFIEHELLMANCNG" ->
                        Optional.of(new ECDH(detectionLocation));
                // System.Security.Cryptography.AsymmetricAlgorithm has no concrete algorithm of
                // its own per the official reference table — intentionally left unresolved.
                default -> Optional.empty();
            };
        }

        return Optional.empty();
    }
}
