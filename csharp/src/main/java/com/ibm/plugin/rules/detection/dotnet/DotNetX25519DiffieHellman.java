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
import com.ibm.engine.model.context.KeyContext;
import com.ibm.engine.model.factory.ValueActionFactory;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import java.util.List;
import java.util.Map;
import javax.annotation.Nonnull;

/**
 * Detection rules for X25519 (Curve25519-based Diffie-Hellman key agreement) usage in {@code
 * System.Security.Cryptography}.
 *
 * <p><b>API verification (Microsoft Learn, 2026-08-20):</b> {@code X25519DiffieHellman}, {@code
 * X25519DiffieHellmanCng} and {@code X25519DiffieHellmanOpenSsl} were confirmed to exist under
 * these exact names via {@code learn.microsoft.com/en-us/dotnet/api/...?view=net-11.0}. This is a
 * <em>brand-new, still-in-preview</em> API: the doc pages show {@code Package:
 * Microsoft.Bcl.Cryptography v11.0.0-preview.7.26381.103} and {@code ms.date: 2025-07-01} — i.e. it
 * ships as a preview NuGet package layered on top of {@code System.Security.Cryptography.dll} (also
 * backportable to older TFMs per the {@code netframework-4.6.2-pp}…{@code netframework-4.8.1-pp}
 * "preview package" monikers listed on the class pages), not yet a stable in-box .NET API.
 * Detection rules are added regardless, mirroring how the rest of this plugin detects APIs across
 * their full supported version range.
 *
 * <p>Classes covered:
 *
 * <ul>
 *   <li>{@code X25519DiffieHellman} — abstract base. Verified to have <em>no</em> {@code Create()}
 *       factory (unlike {@code ECDiffieHellman}); the only way to obtain a fresh instance is the
 *       static factory {@code X25519DiffieHellman.GenerateKey()} (confirmed via the dedicated
 *       method-reference page: {@code public static X25519DiffieHellman GenerateKey()}). Its
 *       constructor is {@code protected X25519DiffieHellman()} (confirmed via the dedicated
 *       constructor page), so the class cannot be instantiated directly — only through {@code
 *       GenerateKey()} or one of the two concrete subclasses below.
 *   <li>{@code X25519DiffieHellmanCng} — CNG-backed implementation. Single constructor {@code
 *       X25519DiffieHellmanCng(CngKey)} (wraps an existing key).
 *   <li>{@code X25519DiffieHellmanOpenSsl} — OpenSSL-backed implementation. Single constructor
 *       {@code X25519DiffieHellmanOpenSsl(SafeEvpPKeyHandle)} (wraps an existing key handle).
 * </ul>
 *
 * <p>Architecture: mirrors {@code DotNetECDiffieHellman.java} (Batch 3) as closely as the actual,
 * verified API shape allows. The overload-collapsing rationale documented there (the ANTLR4-based
 * C# engine cannot resolve parameter types — see {@code CSharpLanguageTranslation}) applies here
 * too: all four {@code DeriveRawSecretAgreement} overloads (array-returning, {@code
 * Span}-returning, and both taking either a raw public-key byte array or another {@code
 * X25519DiffieHellman} instance as the peer) are collapsed into a single {@code
 * withAnyParameters()} rule per method name.
 *
 * <p><b>Deliberately NOT ported from {@code DotNetECDiffieHellman.java}:</b>
 *
 * <ul>
 *   <li>{@code DeriveKeyMaterial}, {@code DeriveKeyFromHash}, {@code DeriveKeyFromHmac}, {@code
 *       DeriveKeyTls} — these methods do <b>not</b> exist on {@code X25519DiffieHellman}. Verified
 *       against the full, official method table on the class's Microsoft Learn reference page: the
 *       only key-agreement-derivation method is {@code DeriveRawSecretAgreement} (4 overloads).
 *       X25519 in .NET is a strictly lower-level, "raw shared secret only" API compared to {@code
 *       ECDiffieHellman} — callers are expected to apply their own KDF.
 *   <li>a settable {@code KeySize} property — {@code X25519DiffieHellman} exposes {@code
 *       PrivateKeySizeInBytes}, {@code PublicKeySizeInBytes} and {@code SecretAgreementSizeInBytes}
 *       only as read-only {@code const int} <em>fields</em> (all fixed at 32 for Curve25519), not
 *       as a settable property — so there is no {@code set_KeySize}-style assignment to detect,
 *       unlike the configurable-curve {@code ECDiffieHellman.KeySize}.
 * </ul>
 *
 * <p>Following the same modeling convention as {@code DotNetECDiffieHellman.java}: {@code
 * DeriveRawSecretAgreement} returns the raw shared secret with no KDF post-processing, so it is
 * translated to the generic {@code Generate} functionality node (not {@code KeyDerivation}) in
 * {@code CSharpKeyContextTranslator}.
 *
 * <p><b>Mapper model:</b> a dedicated {@link com.ibm.mapper.model.algorithms.X25519} algorithm
 * model class already exists (verified via {@code grep -rl "X25519" mapper/} — it is already used
 * by the JCA {@code XDH}/{@code X25519} key-agreement translation and by the Go {@code crypto/ecdh}
 * curve translation), so it is reused as-is here; no new mapper model class was needed.
 *
 * <p><b>Known gaps (same reasoning as {@code DotNetECDiffieHellman.java}):</b>
 *
 * <ul>
 *   <li>Reading the public key (e.g. {@code x25519.ExportPublicKey()} to send to a peer) is not
 *       modeled as a depending rule, mirroring the {@code PublicKey} property gap documented in
 *       {@code DotNetECDiffieHellman.java} for the same underlying reason: these calls carry no
 *       additional cryptographic information beyond "an X25519 key exists" (already captured by the
 *       primary creation rule), and speculatively wiring up the full family of {@code Import} /
 *       {@code Export} / {@code TryExport} methods (PKCS8, SPKI, PEM, encrypted-PKCS8 — none of
 *       which are X25519-specific) would add many rules without adding any new detectable
 *       cryptographic fact. // TODO: revisit if a future need arises to track key material
 *       export/import as its own finding.
 *   <li>{@code X25519DiffieHellmanCng.GetKey()} and {@code
 *       X25519DiffieHellmanOpenSsl.DuplicateKeyHandle()} — these return the underlying platform key
 *       handle ({@code CngKey} / {@code SafeEvpPKeyHandle}), not a new cryptographic fact; skipped
 *       for the same reason as the export methods above.
 * </ul>
 */
@SuppressWarnings("java:S1192")
public final class DotNetX25519DiffieHellman {

    private DotNetX25519DiffieHellman() {
        // nothing
    }

    // =========================================================================
    // Key-derivation / secret-agreement operation rule
    // =========================================================================

    // x25519.DeriveRawSecretAgreement(otherPartyPublicKey) — raw shared secret, no KDF applied.
    // Collapses all 4 overloads (byte[]/Span-returning, byte[]-vs-X25519DiffieHellman peer param).
    private static final IDetectionRule<CSharpTree> X25519_DERIVE_RAW_SECRET_AGREEMENT =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes(MethodMatcher.ANY)
                    .forMethods("DeriveRawSecretAgreement")
                    .shouldBeDetectedAs(new ValueActionFactory<>("DeriveRawSecretAgreement"))
                    .withAnyParameters()
                    .buildForContext(
                            new KeyContext(Map.of("kind", "X25519_DERIVE_RAW_SECRET_AGREEMENT")))
                    .inBundle(() -> "DotNet")
                    .withoutDependingDetectionRules();

    // =========================================================================
    // Aggregated depending-rule list
    // =========================================================================

    /** Full set of depending rules for all X25519DiffieHellman-derived classes. */
    private static final List<IDetectionRule<CSharpTree>> X25519_DEPENDING_RULES =
            List.of(X25519_DERIVE_RAW_SECRET_AGREEMENT);

    // =========================================================================
    // Primary creation rules
    // =========================================================================

    // X25519DiffieHellman.GenerateKey() — static factory, no parameters (no Create() exists).
    private static final IDetectionRule<CSharpTree> X25519_GENERATE_KEY =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes("X25519DiffieHellman")
                    .forMethods("GenerateKey")
                    .shouldBeDetectedAs(new ValueActionFactory<>("X25519"))
                    .withoutParameters()
                    .buildForContext(new KeyContext(Map.of("kind", "X25519")))
                    .inBundle(() -> "DotNet")
                    .withDependingDetectionRules(X25519_DEPENDING_RULES);

    // new X25519DiffieHellmanCng(CngKey) — CNG-backed implementation, wraps an existing key.
    // Uses withAnyParameters() for consistency with ECDH_CNG / AES_CNG_NAMED even though only one
    // constructor overload exists, to avoid a brittle single-parameter-type assumption.
    private static final IDetectionRule<CSharpTree> X25519_CNG =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes("X25519DiffieHellmanCng")
                    .forMethods("<init>")
                    .shouldBeDetectedAs(new ValueActionFactory<>("X25519"))
                    .withAnyParameters()
                    .buildForContext(new KeyContext(Map.of("kind", "X25519")))
                    .inBundle(() -> "DotNet")
                    .withDependingDetectionRules(X25519_DEPENDING_RULES);

    // new X25519DiffieHellmanOpenSsl(SafeEvpPKeyHandle) — OpenSSL-backed implementation, wraps an
    // existing key handle. Uses withAnyParameters() for the same reason as X25519_CNG.
    private static final IDetectionRule<CSharpTree> X25519_OPENSSL =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes("X25519DiffieHellmanOpenSsl")
                    .forMethods("<init>")
                    .shouldBeDetectedAs(new ValueActionFactory<>("X25519"))
                    .withAnyParameters()
                    .buildForContext(new KeyContext(Map.of("kind", "X25519")))
                    .inBundle(() -> "DotNet")
                    .withDependingDetectionRules(X25519_DEPENDING_RULES);

    @Nonnull
    public static List<IDetectionRule<CSharpTree>> rules() {
        return List.of(X25519_GENERATE_KEY, X25519_CNG, X25519_OPENSSL);
    }
}
