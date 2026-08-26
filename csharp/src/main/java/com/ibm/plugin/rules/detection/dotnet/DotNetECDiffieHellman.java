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
package com.ibm.plugin.rules.detection.dotnet;

import com.ibm.engine.detection.MethodMatcher;
import com.ibm.engine.language.csharp.tree.CSharpTree;
import com.ibm.engine.model.Size;
import com.ibm.engine.model.context.KeyContext;
import com.ibm.engine.model.factory.KeySizeFactory;
import com.ibm.engine.model.factory.ValueActionFactory;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import java.util.List;
import java.util.Map;
import javax.annotation.Nonnull;

/**
 * Detection rules for ECDH (Elliptic Curve Diffie-Hellman key agreement) usage in
 * System.Security.Cryptography.
 *
 * <p>Classes covered:
 *
 * <ul>
 *   <li>{@code ECDiffieHellman} — abstract base ({@code ECDiffieHellman.Create()}, {@code
 *       ECDiffieHellman.Create(ECCurve)}, {@code ECDiffieHellman.Create(ECParameters)}, {@code
 *       ECDiffieHellman.Create(string)})
 *   <li>{@code ECDiffieHellmanCng} — CNG-backed implementation, Windows-only
 *   <li>{@code ECDiffieHellmanOpenSsl} — OpenSSL-backed implementation, non-Windows only
 * </ul>
 *
 * <p>Architecture: all members inherited from {@code ECDiffieHellman} / {@code AsymmetricAlgorithm}
 * (the {@code KeySize} property, {@code DeriveKeyMaterial}, {@code DeriveKeyFromHash}, {@code
 * DeriveKeyFromHmac}, {@code DeriveKeyTls}, {@code DeriveRawSecretAgreement}) are expressed as
 * <em>depending rules</em> attached to each primary creation rule, mirroring {@code
 * DotNetECDsa.java} / {@code DotNetAES.java}. Method overloads that only differ by array-vs-{@code
 * Span}, {@code CngKey}-vs-{@code ECDiffieHellmanPublicKey} receiver type, optional prepend/append
 * byte arrays, or output-buffer parameters are intentionally collapsed into a single {@code
 * withAnyParameters()} rule per method name: the ANTLR4-based C# engine cannot resolve parameter
 * types (see {@code CSharpLanguageTranslation}), so distinguishing overloads by parameter type is
 * not possible.
 *
 * <p>None of the key-derivation operations ({@code DeriveKeyMaterial}, {@code DeriveKeyFromHash},
 * {@code DeriveKeyFromHmac}, {@code DeriveKeyTls}, {@code DeriveRawSecretAgreement}) fit any of the
 * typed {@code CipherAction.Action} values ({@code WRAP}, {@code HASH}, {@code ENCRYPT}, {@code
 * DECRYPT}, {@code PADDING}, {@code MAC}, {@code NONE}) — none of them mean "derive a key".
 * Following the existing convention of generic string captures for operations without a typed
 * action (e.g. {@code GenerateKey}/{@code GenerateIV} in {@code DotNetAES.java}), each derive
 * operation is captured with {@code ValueActionFactory<>(<exact method name>)} under its own {@code
 * KeyContext} "kind", and translated in {@code CSharpKeyContextTranslator} to the generic {@code
 * KeyDerivation} functionality node (or, for {@code DeriveRawSecretAgreement} — which returns the
 * raw shared secret with no KDF post-processing applied — to the generic {@code Generate}
 * functionality node, mirroring how {@code GenerateIV} is translated). This is a modeling decision
 * with real discretion (no dedicated "key agreement derive" functionality node exists yet in the
 * mapper model); it is called out here and in the task report rather than decided silently.
 *
 * <p><b>Known gap — {@code PublicKey} property:</b> reading {@code ecdh.PublicKey} (e.g. to send to
 * a peer, or to call {@code alice.PublicKey.ToByteArray()}) cannot be detected with the current
 * engine. This was verified by tracing the engine code, not assumed:
 *
 * <ul>
 *   <li>A bare property read with no chained call (e.g. {@code var pub = alice.PublicKey;}) never
 *       reaches the tree converter at all — {@code CSharpTreeConverter.convertPrimaryExpression}
 *       only emits a node when the {@code primary_expression} contains a {@code method_invocation};
 *       a lone member access produces nothing.
 *   <li>A chained call such as {@code alice.PublicKey.ToByteArray()} *does* produce a {@code
 *       CSharpMethodInvocationTree} node, but {@code resolveObjectTypeName} resolves its receiver
 *       ({@code getObjectTypeName()}) to the generic member name {@code "PublicKey"} (the member
 *       access immediately preceding the call), not the tracked variable name {@code "alice"}. In
 *       {@code CSharpDetectionEngine.isInvocationOnVariable}, the match is {@code
 *       invocation.getObjectTypeName().equals(sym.getName())} — so this always fails for the
 *       tracked {@code alice} symbol, and the depending-rule scan skips the statement before rule
 *       matching is even attempted (see {@code processStatement}).
 * </ul>
 *
 * <p>No rule is added for {@code PublicKey}; forcing one would either never fire (dead code) or
 * fire on an unrelated broad pattern (any {@code x.PublicKey.Method()} in the file, disconnected
 * from the tracked ECDH variable).
 */
@SuppressWarnings("java:S1192")
public final class DotNetECDiffieHellman {

    private DotNetECDiffieHellman() {
        // nothing
    }

    // =========================================================================
    // Property setter rules (synthetic set_X method invocations)
    // =========================================================================

    // ecdh.KeySize = 384  →  synthetic set_KeySize(384)
    private static final IDetectionRule<CSharpTree> ECDH_SET_KEY_SIZE =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes(MethodMatcher.ANY)
                    .forMethods("set_KeySize")
                    .withMethodParameter(MethodMatcher.ANY)
                    .shouldBeDetectedAs(new KeySizeFactory<>(Size.UnitType.BIT))
                    .buildForContext(new KeyContext(Map.of("kind", "ECDH")))
                    .inBundle(() -> "DotNet")
                    .withoutDependingDetectionRules();

    // =========================================================================
    // Key-derivation operation rules
    // See class javadoc for why ValueActionFactory (not a typed CipherAction) is used, and why
    // each method gets its own KeyContext "kind" (dispatched in CSharpKeyContextTranslator).
    // =========================================================================

    // ecdh.DeriveKeyMaterial(otherPartyPublicKey)
    private static final IDetectionRule<CSharpTree> ECDH_DERIVE_KEY_MATERIAL =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes(MethodMatcher.ANY)
                    .forMethods("DeriveKeyMaterial")
                    .shouldBeDetectedAs(new ValueActionFactory<>("DeriveKeyMaterial"))
                    .withAnyParameters()
                    .buildForContext(new KeyContext(Map.of("kind", "ECDH_DERIVE_KEY_MATERIAL")))
                    .inBundle(() -> "DotNet")
                    .withoutDependingDetectionRules();

    // ecdh.DeriveKeyFromHash(otherPartyPublicKey, hashAlgorithm[, secretPrepend, secretAppend])
    private static final IDetectionRule<CSharpTree> ECDH_DERIVE_KEY_FROM_HASH =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes(MethodMatcher.ANY)
                    .forMethods("DeriveKeyFromHash")
                    .shouldBeDetectedAs(new ValueActionFactory<>("DeriveKeyFromHash"))
                    .withAnyParameters()
                    .buildForContext(new KeyContext(Map.of("kind", "ECDH_DERIVE_KEY_FROM_HASH")))
                    .inBundle(() -> "DotNet")
                    .withoutDependingDetectionRules();

    // ecdh.DeriveKeyFromHmac(otherPartyPublicKey, hashAlgorithm, hmacKey[, prepend, append])
    private static final IDetectionRule<CSharpTree> ECDH_DERIVE_KEY_FROM_HMAC =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes(MethodMatcher.ANY)
                    .forMethods("DeriveKeyFromHmac")
                    .shouldBeDetectedAs(new ValueActionFactory<>("DeriveKeyFromHmac"))
                    .withAnyParameters()
                    .buildForContext(new KeyContext(Map.of("kind", "ECDH_DERIVE_KEY_FROM_HMAC")))
                    .inBundle(() -> "DotNet")
                    .withoutDependingDetectionRules();

    // ecdh.DeriveKeyTls(otherPartyPublicKey, prfLabel, prfSeed) — TLS 1.1 PRF-based derivation.
    // Per the ECDiffieHellman API reference there is only one such method (no "1_2" variant).
    private static final IDetectionRule<CSharpTree> ECDH_DERIVE_KEY_TLS =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes(MethodMatcher.ANY)
                    .forMethods("DeriveKeyTls")
                    .shouldBeDetectedAs(new ValueActionFactory<>("DeriveKeyTls"))
                    .withAnyParameters()
                    .buildForContext(new KeyContext(Map.of("kind", "ECDH_DERIVE_KEY_TLS")))
                    .inBundle(() -> "DotNet")
                    .withoutDependingDetectionRules();

    // ecdh.DeriveRawSecretAgreement(otherPartyPublicKey) — raw shared secret, no KDF applied.
    private static final IDetectionRule<CSharpTree> ECDH_DERIVE_RAW_SECRET_AGREEMENT =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes(MethodMatcher.ANY)
                    .forMethods("DeriveRawSecretAgreement")
                    .shouldBeDetectedAs(new ValueActionFactory<>("DeriveRawSecretAgreement"))
                    .withAnyParameters()
                    .buildForContext(
                            new KeyContext(Map.of("kind", "ECDH_DERIVE_RAW_SECRET_AGREEMENT")))
                    .inBundle(() -> "DotNet")
                    .withoutDependingDetectionRules();

    // =========================================================================
    // Aggregated depending-rule list
    // =========================================================================

    /** Full set of depending rules for all ECDiffieHellman-derived classes. */
    private static final List<IDetectionRule<CSharpTree>> ECDH_DEPENDING_RULES =
            List.of(
                    ECDH_SET_KEY_SIZE,
                    ECDH_DERIVE_KEY_MATERIAL,
                    ECDH_DERIVE_KEY_FROM_HASH,
                    ECDH_DERIVE_KEY_FROM_HMAC,
                    ECDH_DERIVE_KEY_TLS,
                    ECDH_DERIVE_RAW_SECRET_AGREEMENT);

    // =========================================================================
    // Primary creation rules
    // =========================================================================

    // ECDiffieHellman.Create() / Create(ECCurve) / Create(ECParameters) / Create(string)
    private static final IDetectionRule<CSharpTree> ECDH_CREATE =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes("ECDiffieHellman")
                    .forMethods("Create")
                    .shouldBeDetectedAs(new ValueActionFactory<>("ECDH"))
                    .withAnyParameters()
                    .buildForContext(new KeyContext(Map.of("kind", "ECDH")))
                    .inBundle(() -> "DotNet")
                    .withDependingDetectionRules(ECDH_DEPENDING_RULES);

    // new ECDiffieHellmanCng() / (CngKey) / (ECCurve) / (int) — CNG-backed implementation.
    // Uses withAnyParameters() to cover all constructor overloads in a single rule and avoid
    // double-detection (see AES_CNG_NAMED in DotNetAES.java / ECDSA_OPENSSL in DotNetECDsa.java).
    private static final IDetectionRule<CSharpTree> ECDH_CNG =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes("ECDiffieHellmanCng")
                    .forMethods("<init>")
                    .shouldBeDetectedAs(new ValueActionFactory<>("ECDH"))
                    .withAnyParameters()
                    .buildForContext(new KeyContext(Map.of("kind", "ECDH")))
                    .inBundle(() -> "DotNet")
                    .withDependingDetectionRules(ECDH_DEPENDING_RULES);

    // new ECDiffieHellmanOpenSsl() / (ECCurve) / (int) / (IntPtr) / (SafeEvpPKeyHandle) —
    // OpenSSL-backed implementation. Uses withAnyParameters() for the same reason as ECDH_CNG.
    private static final IDetectionRule<CSharpTree> ECDH_OPENSSL =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes("ECDiffieHellmanOpenSsl")
                    .forMethods("<init>")
                    .shouldBeDetectedAs(new ValueActionFactory<>("ECDH"))
                    .withAnyParameters()
                    .buildForContext(new KeyContext(Map.of("kind", "ECDH")))
                    .inBundle(() -> "DotNet")
                    .withDependingDetectionRules(ECDH_DEPENDING_RULES);

    @Nonnull
    public static List<IDetectionRule<CSharpTree>> rules() {
        return List.of(ECDH_CREATE, ECDH_CNG, ECDH_OPENSSL);
    }
}
