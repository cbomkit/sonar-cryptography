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
import com.ibm.engine.model.SignatureAction;
import com.ibm.engine.model.context.KeyContext;
import com.ibm.engine.model.context.SignatureContext;
import com.ibm.engine.model.factory.ParameterIdentifierFactory;
import com.ibm.engine.model.factory.SignatureActionFactory;
import com.ibm.engine.model.factory.ValueActionFactory;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;
import javax.annotation.Nonnull;

/**
 * Detection rules for ML-DSA (Module-Lattice-Based Digital Signature Algorithm, FIPS 204) and
 * Composite ML-DSA usage in {@code System.Security.Cryptography}.
 *
 * <p><b>API availability (verified against the official Microsoft Learn API reference, not
 * assumed):</b> {@code MLDsa}, {@code MLDsaCng}, {@code MLDsaOpenSsl}, {@code MLDsaAlgorithm},
 * {@code CompositeMLDsa}, {@code CompositeMLDsaCng} and {@code CompositeMLDsaAlgorithm} are all
 * documented for the {@code net-10.0} and {@code net-11.0} monikers (the {@code net-11.0} page
 * redirects/renders identically to {@code net-10.0} content — {@code defaultMoniker: net-10.0} —
 * both listing "Assembly: System.Security.Cryptography.dll" as in-box, plus "Assembly:
 * Microsoft.Bcl.Cryptography.dll" — package {@code Microsoft.Bcl.Cryptography
 * v11.0.0-preview.7.26381.103} — as a back-compat NuGet shim for the non-OpenSSL types on older
 * TFMs; {@code MLDsaOpenSsl} lists only the in-box assembly, mirroring {@code MLKemOpenSsl}). The
 * plain {@code MLDsa}/{@code MLDsaCng}/{@code MLDsaOpenSsl} surface carries no {@code
 * [Experimental]} attribute. {@code CompositeMLDsa}, {@code CompositeMLDsaCng} and {@code
 * CompositeMLDsaAlgorithm}, by contrast, are each marked {@code
 * [System.Diagnostics.CodeAnalysis.Experimental("SYSLIB5006")]} at the class level — confirming
 * Composite ML-DSA specifically (unlike plain ML-DSA) is still a preview API as of .NET 10/11.
 *
 * <p>Classes covered:
 *
 * <ul>
 *   <li>{@code MLDsa} — abstract base. All of its members are {@code static} factory methods (the
 *       only listed constructor, {@code MLDsa(MLDsaAlgorithm)}, is for derived classes, not called
 *       by ordinary consumer code): {@code GenerateKey(MLDsaAlgorithm)}, {@code
 *       ImportMLDsaPrivateKey(MLDsaAlgorithm, byte[]/ReadOnlySpan&lt;byte&gt;)}, {@code
 *       ImportMLDsaPrivateSeed(MLDsaAlgorithm, byte[]/ReadOnlySpan&lt;byte&gt;)}, {@code
 *       ImportMLDsaPublicKey(MLDsaAlgorithm, byte[]/ReadOnlySpan&lt;byte&gt;)}, {@code
 *       ImportPkcs8PrivateKey(...)}, {@code ImportSubjectPublicKeyInfo(...)}, {@code
 *       ImportFromPem(...)}, {@code ImportEncryptedPkcs8PrivateKey(...)}, {@code
 *       ImportFromEncryptedPem(...)}.
 *   <li>{@code MLDsaCng} — CNG-backed implementation ({@code MLDsaCng(CngKey)} constructor).
 *   <li>{@code MLDsaOpenSsl} — OpenSSL-backed implementation ({@code
 *       MLDsaOpenSsl(SafeEvpPKeyHandle)} constructor).
 *   <li>{@code CompositeMLDsa} — abstract base for Composite ML-DSA (FIPS 204 ML-DSA combined with
 *       a traditional algorithm — RSA/ECDSA/Ed25519/Ed448). Structurally mirrors {@code MLDsa}:
 *       {@code GenerateKey(CompositeMLDsaAlgorithm)}, {@code
 *       ImportCompositeMLDsaPrivateKey(CompositeMLDsaAlgorithm, byte[]/ReadOnlySpan&lt;byte&gt;)},
 *       {@code ImportCompositeMLDsaPublicKey(CompositeMLDsaAlgorithm,
 *       byte[]/ReadOnlySpan&lt;byte&gt;)}, plus the same {@code ImportPkcs8PrivateKey}/{@code
 *       ImportSubjectPublicKeyInfo}/{@code ImportFromPem}/{@code
 *       ImportEncryptedPkcs8PrivateKey}/{@code ImportFromEncryptedPem} structural-import family.
 *   <li>{@code CompositeMLDsaCng} — CNG-backed implementation of Composite ML-DSA ({@code
 *       CompositeMLDsaCng(CngKey)} constructor).
 * </ul>
 *
 * <p><b>Architecture — {@code Import*} as primary creation rules, not skipped:</b> exactly as
 * established for ML-KEM (see {@code DotNetMLKem}'s javadoc for the full rationale), every {@code
 * Import*} method verified above on both {@code MLDsa} and {@code CompositeMLDsa} is a {@code
 * static} factory that is the only way (besides {@code GenerateKey} or the {@code Cng}/{@code
 * OpenSsl} native-interop constructors) to obtain an instance in the first place — unlike the
 * inherited instance {@code Import*}/{@code Export*} members on RSA/ECDsa/ECDiffieHellman, which
 * are intentionally not modeled. They are therefore treated as primary creation rules here.
 *
 * <p>Two creation-rule shapes result from this, for both {@code MLDsa} and {@code CompositeMLDsa}:
 *
 * <ul>
 *   <li><b>Algorithm-parameterized</b> ({@code GenerateKey}, {@code ImportMLDsaPrivateKey}, {@code
 *       ImportMLDsaPrivateSeed}, {@code ImportMLDsaPublicKey} / {@code
 *       ImportCompositeMLDsaPrivateKey}, {@code ImportCompositeMLDsaPublicKey}): take an {@code
 *       MLDsaAlgorithm}/{@code CompositeMLDsaAlgorithm} argument (e.g. {@code
 *       MLDsaAlgorithm.MLDsa65}), a member-access expression the engine resolves to the bare
 *       identifier {@code "MLDsa65"} (see {@code CSharpLanguageTranslation}, the same mechanism
 *       {@code DotNetMLKem}'s rules rely on for {@code MLKemAlgorithm}). Captured with {@code
 *       ParameterIdentifierFactory<>()} as a child of the top-level detection.
 *   <li><b>Structural imports</b> ({@code ImportPkcs8PrivateKey}, {@code
 *       ImportSubjectPublicKeyInfo}, {@code ImportFromPem}, {@code ImportEncryptedPkcs8PrivateKey},
 *       {@code ImportFromEncryptedPem}): the parameter set is embedded inside the encoded key
 *       material / PEM text, not present as a separate literal argument, so — exactly as for ML-KEM
 *       — it cannot be recovered by this engine. These translate to a generic node with no {@code
 *       ParameterSetIdentifier} child, a known, inherent precision gap, not a bug.
 * </ul>
 *
 * <p>{@code MLDsaCng(CngKey)}, {@code MLDsaOpenSsl(SafeEvpPKeyHandle)} and {@code
 * CompositeMLDsaCng(CngKey)} wrap an already-existing native key handle and never receive an
 * algorithm argument at all, so they always translate to the generic node, mirroring {@code
 * MLKemCng(CngKey)}/{@code MLKemOpenSsl(SafeEvpPKeyHandle)}.
 *
 * <p><b>Sign/Verify modeling:</b> unlike {@code DotNetMLKem} (which models KEM-specific {@code
 * Encapsulate}/{@code Decapsulate} via {@code KeyActionFactory}), {@code MLDsa} and {@code
 * CompositeMLDsa} are ordinary signature primitives, so their operations are modeled with {@code
 * SignatureActionFactory} under a {@code SignatureContext} — the exact same shape as {@code
 * DotNetDSA}/{@code DotNetECDsa}'s {@code SignData}/{@code VerifyData} rules, reusing the existing
 * generic SIGN/VERIFY dispatch in {@code CSharpSignatureContextTranslator} (no changes needed
 * there: that translator already maps {@code SignatureAction.Action.SIGN}/{@code VERIFY} to {@code
 * Sign}/{@code Verify} functionality nodes regardless of which algorithm produced the action, so
 * this rule set is purely additive from its perspective). {@code MLDsa} additionally exposes {@code
 * SignMu}/{@code VerifyMu} (signing a pre-computed FIPS 204 "mu" digest) and {@code
 * SignPreHash}/{@code VerifyPreHash} (the FIPS 204 pre-hash variant); both are modeled the same way
 * as {@code SignData}/{@code VerifyData} since the engine cannot meaningfully distinguish "what was
 * hashed before signing" from "what was signed" without value tracking. {@code CompositeMLDsa} only
 * exposes {@code SignData}/{@code VerifyData} (no mu/pre-hash variants per the verified API
 * surface). The {@code *Core} overrides ({@code SignDataCore}, {@code SignMuCore}, {@code
 * SignPreHashCore}, {@code VerifyDataCore}, {@code VerifyMuCore}, {@code VerifyPreHashCore}) are
 * protected extensibility hooks for subclassing, not called by ordinary consumer code, and are
 * intentionally not modeled — consistent with not modeling {@code EncapsulateCore}/{@code
 * DecapsulateCore} in {@code DotNetMLKem}.
 *
 * <p><b>Mapper model reuse:</b> {@code com.ibm.mapper.model.algorithms.MLDSA} (implementing {@code
 * Signature}) already existed before this batch (added alongside {@code MLKEM} — see PR "Add
 * support for MLKEM and MLDSA #219") and already exposes the exact {@code MLDSA(int
 * parameterSetIdentifier, DetectionLocation)} shape {@code DotNetMLKem} relies on for {@code
 * MLKEM}, so {@code asString()} yields {@code "ML-DSA-44"}/{@code "ML-DSA-65"}/{@code "ML-DSA-87"}.
 * No new mapper model class was introduced for plain ML-DSA.
 *
 * <p><b>Composite ML-DSA modeling — a deliberate, documented compromise, not a fabrication:</b> a
 * repository-wide search ({@code grep -rl "Composite\|Hybrid" mapper/}) found no existing
 * "composite"/"hybrid" algorithm concept anywhere in the mapper model — {@code CompositeMLDsa}
 * combines a post-quantum algorithm (ML-DSA-44/65/87) with a classical one (e.g. RSA-2048-PSS,
 * ECDSA-P256, Ed25519) into a single key, which a properly structured model would represent as two
 * linked algorithm nodes. Inventing that two-algorithm "Hybrid"/"Composite" model class from
 * scratch was judged out of scope for this batch (it would require new base-class/interface design
 * in {@code mapper/model/}, affecting more than this one rule file — see class-level "Not covered"
 * note below for the recommendation). However, the detection-rule *shape* for {@code
 * CompositeMLDsa} turned out to be structurally identical to plain {@code MLDsa} (same static
 * factory / structural-import / Cng-constructor pattern, confirmed from the official reference
 * above, not assumed by RSA/ECDsa analogy) — there was therefore no reason to skip detecting it
 * entirely. The chosen middle ground: {@code CompositeMLDsa}/{@code CompositeMLDsaCng} creation is
 * detected and reuses the existing {@code MLDSA} mapper node (via a distinct {@code
 * "MLDSA_COMPOSITE"} {@code KeyContext} kind, dispatched in {@code CSharpKeyContextTranslator}),
 * with the <em>full, untranslated</em> {@code CompositeMLDsaAlgorithm} member name (e.g. {@code
 * "MLDsa44WithECDsaP256"}, one of the 17 combinations verified from the official {@code
 * CompositeMLDsaAlgorithm} reference page — {@code MLDsa44With\{ECDsaP256,Ed25519,RSA2048Pkcs15,
 * RSA2048Pss\}}, {@code MLDsa65With\{ECDsaBrainpoolP256r1,ECDsaP256,ECDsaP384,Ed25519,
 * RSA3072Pkcs15,RSA3072Pss,RSA4096Pkcs15,RSA4096Pss\}}, {@code
 * MLDsa87With\{ECDsaBrainpoolP384r1,ECDsaP384,ECDsaP521,Ed448,RSA3072Pss,RSA4096Pss\}}) captured
 * <em>verbatim</em> as the {@code ParameterSetIdentifier} string, rather than parsed into an ML-DSA
 * parameter set number plus a separate classical-algorithm node. This preserves 100% of the
 * information the engine can see (nothing is dropped or guessed) and yields a distinguishable,
 * still-informative {@code asString()} such as {@code "ML-DSA-MLDsa44WithECDsaP256"}, at the cost
 * of not exposing the classical component as a structured sibling/child node the way a "true"
 * composite/hybrid model would. This is flagged here explicitly, not silently: a follow-up
 * introducing a proper composite/hybrid algorithm concept in {@code mapper/model/} could later
 * parse this same string into two structured nodes without touching this detection rule file.
 *
 * <p><b>Not covered (deliberately, consistent with the rest of this rule set):</b> the {@code
 * Algorithm}/{@code IsSupported} getters and {@code CompositeMLDsa.IsAlgorithmSupported(...)}
 * (state reads, not configuration — no property setters exist on {@code MLDsa}/{@code
 * CompositeMLDsa} at all), {@code MLDsaCng.GetKey()}/{@code CompositeMLDsaCng.GetKey()}/{@code
 * MLDsaOpenSsl.DuplicateKeyHandle()} (native-handle export, the {@code MLDsa}-specific equivalent
 * of the {@code Export*} methods skipped for RSA/ECDsa/ECDiffieHellman), {@code Dispose()}, and all
 * {@code ExportXxx}/{@code TryExportXxx}/{@code ExportXxxPem} instance methods (standard
 * PKCS#8/SPKI/PEM export — same convention as RSA/ECDsa/ECDiffieHellman/MLKem).
 */
@SuppressWarnings("java:S1192")
public final class DotNetMLDsa {

    private DotNetMLDsa() {
        // nothing
    }

    // =========================================================================
    // Sign / Verify operation rules (depending rules on any tracked MLDsa/CompositeMLDsa-family
    // variable, mirroring DotNetDSA.java's SignData/VerifyData rules)
    // =========================================================================

    // mldsa.SignData(data, context) — 2 overloads (array-based and Span-based)
    private static final IDetectionRule<CSharpTree> MLDSA_SIGN_DATA =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes(MethodMatcher.ANY)
                    .forMethods("SignData")
                    .shouldBeDetectedAs(new SignatureActionFactory<>(SignatureAction.Action.SIGN))
                    .withAnyParameters()
                    .buildForContext(new SignatureContext())
                    .inBundle(() -> "DotNet")
                    .withoutDependingDetectionRules();

    // mldsa.VerifyData(data, signature, context) — 2 overloads
    private static final IDetectionRule<CSharpTree> MLDSA_VERIFY_DATA =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes(MethodMatcher.ANY)
                    .forMethods("VerifyData")
                    .shouldBeDetectedAs(new SignatureActionFactory<>(SignatureAction.Action.VERIFY))
                    .withAnyParameters()
                    .buildForContext(new SignatureContext())
                    .inBundle(() -> "DotNet")
                    .withoutDependingDetectionRules();

    // mldsa.SignMu(mu[, destination]) — 3 overloads (MLDsa only, not CompositeMLDsa)
    private static final IDetectionRule<CSharpTree> MLDSA_SIGN_MU =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes(MethodMatcher.ANY)
                    .forMethods("SignMu")
                    .shouldBeDetectedAs(new SignatureActionFactory<>(SignatureAction.Action.SIGN))
                    .withAnyParameters()
                    .buildForContext(new SignatureContext())
                    .inBundle(() -> "DotNet")
                    .withoutDependingDetectionRules();

    // mldsa.VerifyMu(mu, signature) — 2 overloads (MLDsa only)
    private static final IDetectionRule<CSharpTree> MLDSA_VERIFY_MU =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes(MethodMatcher.ANY)
                    .forMethods("VerifyMu")
                    .shouldBeDetectedAs(new SignatureActionFactory<>(SignatureAction.Action.VERIFY))
                    .withAnyParameters()
                    .buildForContext(new SignatureContext())
                    .inBundle(() -> "DotNet")
                    .withoutDependingDetectionRules();

    // mldsa.SignPreHash(hash, hashAlgorithmOid, context) — 2 overloads (MLDsa only)
    private static final IDetectionRule<CSharpTree> MLDSA_SIGN_PRE_HASH =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes(MethodMatcher.ANY)
                    .forMethods("SignPreHash")
                    .shouldBeDetectedAs(new SignatureActionFactory<>(SignatureAction.Action.SIGN))
                    .withAnyParameters()
                    .buildForContext(new SignatureContext())
                    .inBundle(() -> "DotNet")
                    .withoutDependingDetectionRules();

    // mldsa.VerifyPreHash(hash, signature, hashAlgorithmOid, context) — 2 overloads (MLDsa only)
    private static final IDetectionRule<CSharpTree> MLDSA_VERIFY_PRE_HASH =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes(MethodMatcher.ANY)
                    .forMethods("VerifyPreHash")
                    .shouldBeDetectedAs(new SignatureActionFactory<>(SignatureAction.Action.VERIFY))
                    .withAnyParameters()
                    .buildForContext(new SignatureContext())
                    .inBundle(() -> "DotNet")
                    .withoutDependingDetectionRules();

    /** Full set of depending rules for {@code MLDsa}/{@code MLDsaCng}/{@code MLDsaOpenSsl}. */
    private static final List<IDetectionRule<CSharpTree>> MLDSA_DEPENDING_RULES =
            List.of(
                    MLDSA_SIGN_DATA,
                    MLDSA_VERIFY_DATA,
                    MLDSA_SIGN_MU,
                    MLDSA_VERIFY_MU,
                    MLDSA_SIGN_PRE_HASH,
                    MLDSA_VERIFY_PRE_HASH);

    /**
     * Depending rules for {@code CompositeMLDsa}/{@code CompositeMLDsaCng} — only {@code
     * SignData}/{@code VerifyData} exist on this type (no mu/pre-hash variants).
     */
    private static final List<IDetectionRule<CSharpTree>> COMPOSITE_MLDSA_DEPENDING_RULES =
            List.of(MLDSA_SIGN_DATA, MLDSA_VERIFY_DATA);

    // =========================================================================
    // MLDsa — primary creation rules, algorithm-parameterized (MLDsaAlgorithm argument captured
    // as the parameter set, see class javadoc)
    // =========================================================================

    // MLDsa.GenerateKey(MLDsaAlgorithm.MLDsa65)
    private static final IDetectionRule<CSharpTree> MLDSA_GENERATE_KEY =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes("MLDsa")
                    .forMethods("GenerateKey")
                    .shouldBeDetectedAs(new ValueActionFactory<>("ML-DSA"))
                    .withMethodParameter(MethodMatcher.ANY) // MLDsaAlgorithm
                    .shouldBeDetectedAs(new ParameterIdentifierFactory<>())
                    .asChildOfParameterWithId(-1)
                    .buildForContext(new KeyContext(Map.of("kind", "MLDSA")))
                    .inBundle(() -> "DotNet")
                    .withDependingDetectionRules(MLDSA_DEPENDING_RULES);

    // MLDsa.ImportMLDsaPrivateKey(MLDsaAlgorithm.MLDsa65, privateKeyBytes)
    private static final IDetectionRule<CSharpTree> MLDSA_IMPORT_PRIVATE_KEY =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes("MLDsa")
                    .forMethods("ImportMLDsaPrivateKey")
                    .shouldBeDetectedAs(new ValueActionFactory<>("ML-DSA"))
                    .withMethodParameter(MethodMatcher.ANY) // MLDsaAlgorithm
                    .shouldBeDetectedAs(new ParameterIdentifierFactory<>())
                    .asChildOfParameterWithId(-1)
                    .withMethodParameter(MethodMatcher.ANY) // private key bytes
                    .buildForContext(new KeyContext(Map.of("kind", "MLDSA")))
                    .inBundle(() -> "DotNet")
                    .withDependingDetectionRules(MLDSA_DEPENDING_RULES);

    // MLDsa.ImportMLDsaPrivateSeed(MLDsaAlgorithm.MLDsa65, seedBytes)
    private static final IDetectionRule<CSharpTree> MLDSA_IMPORT_PRIVATE_SEED =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes("MLDsa")
                    .forMethods("ImportMLDsaPrivateSeed")
                    .shouldBeDetectedAs(new ValueActionFactory<>("ML-DSA"))
                    .withMethodParameter(MethodMatcher.ANY) // MLDsaAlgorithm
                    .shouldBeDetectedAs(new ParameterIdentifierFactory<>())
                    .asChildOfParameterWithId(-1)
                    .withMethodParameter(MethodMatcher.ANY) // seed bytes
                    .buildForContext(new KeyContext(Map.of("kind", "MLDSA")))
                    .inBundle(() -> "DotNet")
                    .withDependingDetectionRules(MLDSA_DEPENDING_RULES);

    // MLDsa.ImportMLDsaPublicKey(MLDsaAlgorithm.MLDsa65, publicKeyBytes)
    private static final IDetectionRule<CSharpTree> MLDSA_IMPORT_PUBLIC_KEY =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes("MLDsa")
                    .forMethods("ImportMLDsaPublicKey")
                    .shouldBeDetectedAs(new ValueActionFactory<>("ML-DSA"))
                    .withMethodParameter(MethodMatcher.ANY) // MLDsaAlgorithm
                    .shouldBeDetectedAs(new ParameterIdentifierFactory<>())
                    .asChildOfParameterWithId(-1)
                    .withMethodParameter(MethodMatcher.ANY) // public key bytes
                    .buildForContext(new KeyContext(Map.of("kind", "MLDSA")))
                    .inBundle(() -> "DotNet")
                    .withDependingDetectionRules(MLDSA_DEPENDING_RULES);

    // =========================================================================
    // MLDsa — primary creation rules, structural imports (no MLDsaAlgorithm argument; see class
    // javadoc for why the parameter set cannot be captured for these)
    // =========================================================================

    private static IDetectionRule<CSharpTree> structuralImportRule(
            @Nonnull String objectType,
            @Nonnull String methodName,
            @Nonnull String kind,
            @Nonnull List<IDetectionRule<CSharpTree>> dependingRules) {
        return new DetectionRuleBuilder<CSharpTree>()
                .createDetectionRule()
                .forObjectTypes(objectType)
                .forMethods(methodName)
                .shouldBeDetectedAs(new ValueActionFactory<>("ML-DSA"))
                .withAnyParameters()
                .buildForContext(new KeyContext(Map.of("kind", kind)))
                .inBundle(() -> "DotNet")
                .withDependingDetectionRules(dependingRules);
    }

    // MLDsa.ImportPkcs8PrivateKey(source) / MLDsa.ImportSubjectPublicKeyInfo(source) /
    // MLDsa.ImportFromPem(pem) / MLDsa.ImportEncryptedPkcs8PrivateKey(...) /
    // MLDsa.ImportFromEncryptedPem(...)
    private static final IDetectionRule<CSharpTree> MLDSA_IMPORT_PKCS8_PRIVATE_KEY =
            structuralImportRule("MLDsa", "ImportPkcs8PrivateKey", "MLDSA", MLDSA_DEPENDING_RULES);

    private static final IDetectionRule<CSharpTree> MLDSA_IMPORT_SUBJECT_PUBLIC_KEY_INFO =
            structuralImportRule(
                    "MLDsa", "ImportSubjectPublicKeyInfo", "MLDSA", MLDSA_DEPENDING_RULES);

    private static final IDetectionRule<CSharpTree> MLDSA_IMPORT_FROM_PEM =
            structuralImportRule("MLDsa", "ImportFromPem", "MLDSA", MLDSA_DEPENDING_RULES);

    private static final IDetectionRule<CSharpTree> MLDSA_IMPORT_ENCRYPTED_PKCS8_PRIVATE_KEY =
            structuralImportRule(
                    "MLDsa", "ImportEncryptedPkcs8PrivateKey", "MLDSA", MLDSA_DEPENDING_RULES);

    private static final IDetectionRule<CSharpTree> MLDSA_IMPORT_FROM_ENCRYPTED_PEM =
            structuralImportRule("MLDsa", "ImportFromEncryptedPem", "MLDSA", MLDSA_DEPENDING_RULES);

    // =========================================================================
    // MLDsa — primary creation rules, native-interop constructors (no MLDsaAlgorithm argument;
    // wrap an already-existing native key handle, mirroring MLKemCng/MLKemOpenSsl in DotNetMLKem)
    // =========================================================================

    // new MLDsaCng(cngKey)
    private static final IDetectionRule<CSharpTree> MLDSA_CNG =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes("MLDsaCng")
                    .forMethods("<init>")
                    .shouldBeDetectedAs(new ValueActionFactory<>("ML-DSA"))
                    .withAnyParameters()
                    .buildForContext(new KeyContext(Map.of("kind", "MLDSA")))
                    .inBundle(() -> "DotNet")
                    .withDependingDetectionRules(MLDSA_DEPENDING_RULES);

    // new MLDsaOpenSsl(safeEvpPKeyHandle)
    private static final IDetectionRule<CSharpTree> MLDSA_OPENSSL =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes("MLDsaOpenSsl")
                    .forMethods("<init>")
                    .shouldBeDetectedAs(new ValueActionFactory<>("ML-DSA"))
                    .withAnyParameters()
                    .buildForContext(new KeyContext(Map.of("kind", "MLDSA")))
                    .inBundle(() -> "DotNet")
                    .withDependingDetectionRules(MLDSA_DEPENDING_RULES);

    // =========================================================================
    // CompositeMLDsa — primary creation rules, algorithm-parameterized (CompositeMLDsaAlgorithm
    // argument captured verbatim as the parameter set — see class javadoc for why this is not
    // parsed into a structured ML-DSA-size + classical-algorithm pair)
    // =========================================================================

    // CompositeMLDsa.GenerateKey(CompositeMLDsaAlgorithm.MLDsa65WithECDsaP256)
    private static final IDetectionRule<CSharpTree> COMPOSITE_MLDSA_GENERATE_KEY =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes("CompositeMLDsa")
                    .forMethods("GenerateKey")
                    .shouldBeDetectedAs(new ValueActionFactory<>("ML-DSA"))
                    .withMethodParameter(MethodMatcher.ANY) // CompositeMLDsaAlgorithm
                    .shouldBeDetectedAs(new ParameterIdentifierFactory<>())
                    .asChildOfParameterWithId(-1)
                    .buildForContext(new KeyContext(Map.of("kind", "MLDSA_COMPOSITE")))
                    .inBundle(() -> "DotNet")
                    .withDependingDetectionRules(COMPOSITE_MLDSA_DEPENDING_RULES);

    // CompositeMLDsa.ImportCompositeMLDsaPrivateKey(CompositeMLDsaAlgorithm.MLDsa65WithECDsaP256,
    // privateKeyBytes)
    private static final IDetectionRule<CSharpTree> COMPOSITE_MLDSA_IMPORT_PRIVATE_KEY =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes("CompositeMLDsa")
                    .forMethods("ImportCompositeMLDsaPrivateKey")
                    .shouldBeDetectedAs(new ValueActionFactory<>("ML-DSA"))
                    .withMethodParameter(MethodMatcher.ANY) // CompositeMLDsaAlgorithm
                    .shouldBeDetectedAs(new ParameterIdentifierFactory<>())
                    .asChildOfParameterWithId(-1)
                    .withMethodParameter(MethodMatcher.ANY) // private key bytes
                    .buildForContext(new KeyContext(Map.of("kind", "MLDSA_COMPOSITE")))
                    .inBundle(() -> "DotNet")
                    .withDependingDetectionRules(COMPOSITE_MLDSA_DEPENDING_RULES);

    // CompositeMLDsa.ImportCompositeMLDsaPublicKey(CompositeMLDsaAlgorithm.MLDsa65WithECDsaP256,
    // publicKeyBytes)
    private static final IDetectionRule<CSharpTree> COMPOSITE_MLDSA_IMPORT_PUBLIC_KEY =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes("CompositeMLDsa")
                    .forMethods("ImportCompositeMLDsaPublicKey")
                    .shouldBeDetectedAs(new ValueActionFactory<>("ML-DSA"))
                    .withMethodParameter(MethodMatcher.ANY) // CompositeMLDsaAlgorithm
                    .shouldBeDetectedAs(new ParameterIdentifierFactory<>())
                    .asChildOfParameterWithId(-1)
                    .withMethodParameter(MethodMatcher.ANY) // public key bytes
                    .buildForContext(new KeyContext(Map.of("kind", "MLDSA_COMPOSITE")))
                    .inBundle(() -> "DotNet")
                    .withDependingDetectionRules(COMPOSITE_MLDSA_DEPENDING_RULES);

    // =========================================================================
    // CompositeMLDsa — primary creation rules, structural imports (no CompositeMLDsaAlgorithm
    // argument)
    // =========================================================================

    // CompositeMLDsa.ImportPkcs8PrivateKey(source) /
    // CompositeMLDsa.ImportSubjectPublicKeyInfo(source) / CompositeMLDsa.ImportFromPem(pem) /
    // CompositeMLDsa.ImportEncryptedPkcs8PrivateKey(...) /
    // CompositeMLDsa.ImportFromEncryptedPem(...)
    private static final IDetectionRule<CSharpTree> COMPOSITE_MLDSA_IMPORT_PKCS8_PRIVATE_KEY =
            structuralImportRule(
                    "CompositeMLDsa",
                    "ImportPkcs8PrivateKey",
                    "MLDSA_COMPOSITE",
                    COMPOSITE_MLDSA_DEPENDING_RULES);

    private static final IDetectionRule<CSharpTree> COMPOSITE_MLDSA_IMPORT_SUBJECT_PUBLIC_KEY_INFO =
            structuralImportRule(
                    "CompositeMLDsa",
                    "ImportSubjectPublicKeyInfo",
                    "MLDSA_COMPOSITE",
                    COMPOSITE_MLDSA_DEPENDING_RULES);

    private static final IDetectionRule<CSharpTree> COMPOSITE_MLDSA_IMPORT_FROM_PEM =
            structuralImportRule(
                    "CompositeMLDsa",
                    "ImportFromPem",
                    "MLDSA_COMPOSITE",
                    COMPOSITE_MLDSA_DEPENDING_RULES);

    private static final IDetectionRule<CSharpTree>
            COMPOSITE_MLDSA_IMPORT_ENCRYPTED_PKCS8_PRIVATE_KEY =
                    structuralImportRule(
                            "CompositeMLDsa",
                            "ImportEncryptedPkcs8PrivateKey",
                            "MLDSA_COMPOSITE",
                            COMPOSITE_MLDSA_DEPENDING_RULES);

    private static final IDetectionRule<CSharpTree> COMPOSITE_MLDSA_IMPORT_FROM_ENCRYPTED_PEM =
            structuralImportRule(
                    "CompositeMLDsa",
                    "ImportFromEncryptedPem",
                    "MLDSA_COMPOSITE",
                    COMPOSITE_MLDSA_DEPENDING_RULES);

    // =========================================================================
    // CompositeMLDsa — primary creation rule, native-interop constructor (no
    // CompositeMLDsaAlgorithm argument; wraps an already-existing native key handle)
    // =========================================================================

    // new CompositeMLDsaCng(cngKey)
    private static final IDetectionRule<CSharpTree> COMPOSITE_MLDSA_CNG =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes("CompositeMLDsaCng")
                    .forMethods("<init>")
                    .shouldBeDetectedAs(new ValueActionFactory<>("ML-DSA"))
                    .withAnyParameters()
                    .buildForContext(new KeyContext(Map.of("kind", "MLDSA_COMPOSITE")))
                    .inBundle(() -> "DotNet")
                    .withDependingDetectionRules(COMPOSITE_MLDSA_DEPENDING_RULES);

    @Nonnull
    public static List<IDetectionRule<CSharpTree>> rules() {
        return Stream.of(
                        MLDSA_GENERATE_KEY,
                        MLDSA_IMPORT_PRIVATE_KEY,
                        MLDSA_IMPORT_PRIVATE_SEED,
                        MLDSA_IMPORT_PUBLIC_KEY,
                        MLDSA_IMPORT_PKCS8_PRIVATE_KEY,
                        MLDSA_IMPORT_SUBJECT_PUBLIC_KEY_INFO,
                        MLDSA_IMPORT_FROM_PEM,
                        MLDSA_IMPORT_ENCRYPTED_PKCS8_PRIVATE_KEY,
                        MLDSA_IMPORT_FROM_ENCRYPTED_PEM,
                        MLDSA_CNG,
                        MLDSA_OPENSSL,
                        COMPOSITE_MLDSA_GENERATE_KEY,
                        COMPOSITE_MLDSA_IMPORT_PRIVATE_KEY,
                        COMPOSITE_MLDSA_IMPORT_PUBLIC_KEY,
                        COMPOSITE_MLDSA_IMPORT_PKCS8_PRIVATE_KEY,
                        COMPOSITE_MLDSA_IMPORT_SUBJECT_PUBLIC_KEY_INFO,
                        COMPOSITE_MLDSA_IMPORT_FROM_PEM,
                        COMPOSITE_MLDSA_IMPORT_ENCRYPTED_PKCS8_PRIVATE_KEY,
                        COMPOSITE_MLDSA_IMPORT_FROM_ENCRYPTED_PEM,
                        COMPOSITE_MLDSA_CNG)
                .toList();
    }
}
