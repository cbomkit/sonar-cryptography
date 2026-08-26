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
import javax.annotation.Nonnull;

/**
 * Detection rules for SLH-DSA (Stateless Hash-Based Digital Signature Algorithm, FIPS 205, formerly
 * known as SPHINCS+) usage in {@code System.Security.Cryptography}.
 *
 * <p><b>API availability (verified against the official Microsoft Learn API reference, not
 * assumed):</b> {@code SlhDsa}, {@code SlhDsaCng}, {@code SlhDsaOpenSsl} and {@code
 * SlhDsaAlgorithm} are documented for the {@code net-10.0} and {@code net-11.0} monikers (the
 * {@code net-11.0} page redirects/renders identically to {@code net-10.0} content — {@code
 * defaultMoniker: net-10.0} — both listing "Assembly: System.Security.Cryptography.dll" as in-box,
 * plus "Assembly: Microsoft.Bcl.Cryptography.dll" — package {@code Microsoft.Bcl.Cryptography
 * v11.0.0-preview.7.26381.103} — as a back-compat NuGet shim for {@code SlhDsa}/{@code
 * SlhDsaCng}/{@code SlhDsaAlgorithm} on older TFMs; {@code SlhDsaOpenSsl} lists only the in-box
 * assembly, mirroring {@code MLKemOpenSsl}/{@code MLDsaOpenSsl}). Unlike plain {@code MLDsa}/{@code
 * MLKem}, the whole {@code SlhDsa} surface (base class, both derived classes, and {@code
 * SlhDsaAlgorithm}) carries a class-level {@code
 * [System.Diagnostics.CodeAnalysis.Experimental("SYSLIB5006")]} attribute — SLH-DSA is still a
 * preview API as of .NET 10/11, unlike the now-stable plain ML-DSA/ML-KEM surface.
 *
 * <p>Classes covered:
 *
 * <ul>
 *   <li>{@code SlhDsa} — abstract base. All of its members are {@code static} factory methods (the
 *       only listed constructor, {@code SlhDsa(SlhDsaAlgorithm)}, is for derived classes, not
 *       called by ordinary consumer code): {@code GenerateKey(SlhDsaAlgorithm)}, {@code
 *       ImportSlhDsaPrivateKey(SlhDsaAlgorithm, byte[]/ReadOnlySpan&lt;byte&gt;)}, {@code
 *       ImportSlhDsaPublicKey(SlhDsaAlgorithm, byte[]/ReadOnlySpan&lt;byte&gt;)}, {@code
 *       ImportPkcs8PrivateKey(...)}, {@code ImportSubjectPublicKeyInfo(...)}, {@code
 *       ImportFromPem(...)}, {@code ImportEncryptedPkcs8PrivateKey(...)}, {@code
 *       ImportFromEncryptedPem(...)}.
 *   <li>{@code SlhDsaCng} — CNG-backed implementation ({@code SlhDsaCng(CngKey)} constructor).
 *   <li>{@code SlhDsaOpenSsl} — OpenSSL-backed implementation ({@code
 *       SlhDsaOpenSsl(SafeEvpPKeyHandle)} constructor).
 * </ul>
 *
 * <p><b>Differences from ML-DSA, verified from the official reference rather than assumed by
 * analogy (SLH-DSA is a hash-based signature scheme per FIPS 205, structurally unrelated to the
 * lattice-based FIPS 204 ML-DSA, despite both exposing a similar C# surface):</b>
 *
 * <ul>
 *   <li><b>No private-seed import.</b> {@code SlhDsa} has no {@code ImportSlhDsaPrivateSeed}
 *       equivalent to {@code MLDsa.ImportMLDsaPrivateSeed} — confirmed absent from the verified
 *       method table. This makes sense: ML-DSA's seed-expansion key derivation is a
 *       lattice-specific construction, not part of the FIPS 205 SLH-DSA private key format.
 *   <li><b>No {@code SignMu}/{@code VerifyMu}.</b> ML-DSA's {@code SignMu}/{@code VerifyMu}
 *       (signing a pre-computed FIPS 204 "mu" digest) are absent from {@code SlhDsa} — confirmed
 *       absent from the verified method table. This is expected: "mu" is a
 *       ML-DSA/Dilithium-specific message-representative construction with no FIPS 205 equivalent.
 *   <li><b>{@code SignPreHash}/{@code VerifyPreHash} do exist</b> (the FIPS 205 pre-hash signing
 *       variant, {@code SignPreHash(byte[]/ReadOnlySpan&lt;byte&gt;, ..., string hashAlgorithmOid,
 *       ...)}) — confirmed present in the verified method table, with the exact same shape as
 *       ML-DSA's pre-hash methods.
 *   <li><b>No Composite variant.</b> Unlike {@code CompositeMLDsa}, no {@code CompositeSlhDsa}
 *       class exists in the official reference (the {@code SlhDsa} page's "Derived" list contains
 *       only {@code SlhDsaCng} and {@code SlhDsaOpenSsl}), so no composite/hybrid detection or
 *       modeling compromise is needed here.
 *   <li><b>Parameter set names are completely different.</b> {@code SlhDsaAlgorithm} exposes twelve
 *       static properties, verified from the official {@code SlhDsaAlgorithm} reference page:
 *       {@code SlhDsaSha2_128s}, {@code SlhDsaSha2_128f}, {@code SlhDsaSha2_192s}, {@code
 *       SlhDsaSha2_192f}, {@code SlhDsaSha2_256s}, {@code SlhDsaSha2_256f}, {@code
 *       SlhDsaShake128s}, {@code SlhDsaShake128f}, {@code SlhDsaShake192s}, {@code
 *       SlhDsaShake192f}, {@code SlhDsaShake256s}, {@code SlhDsaShake256f} — a hash-family
 *       (SHA2/SHAKE) x security-level (128/192/256) x speed-tradeoff (s=small signature/slower,
 *       f=fast/larger signature) matrix, nothing like ML-DSA's simple {@code MLDsa44}/{@code
 *       MLDsa65}/{@code MLDsa87} three-value set.
 * </ul>
 *
 * <p><b>Architecture — {@code Import*} as primary creation rules, not skipped:</b> exactly as
 * established for ML-KEM/ML-DSA (see {@code DotNetMLKem}'s javadoc for the full rationale), every
 * {@code Import*} method verified above on {@code SlhDsa} is a {@code static} factory that is the
 * only way (besides {@code GenerateKey} or the {@code Cng}/{@code OpenSsl} native-interop
 * constructors) to obtain an instance in the first place. They are therefore treated as primary
 * creation rules here.
 *
 * <p>Two creation-rule shapes result from this:
 *
 * <ul>
 *   <li><b>Algorithm-parameterized</b> ({@code GenerateKey}, {@code ImportSlhDsaPrivateKey}, {@code
 *       ImportSlhDsaPublicKey}): take an {@code SlhDsaAlgorithm} argument (e.g. {@code
 *       SlhDsaAlgorithm.SlhDsaSha2_128s}), a member-access expression the engine resolves to the
 *       bare identifier {@code "SlhDsaSha2_128s"} (see {@code CSharpLanguageTranslation}, the same
 *       mechanism {@code DotNetMLDsa}/{@code DotNetMLKem}'s rules rely on). Captured with {@code
 *       ParameterIdentifierFactory<>()} as a child of the top-level detection.
 *   <li><b>Structural imports</b> ({@code ImportPkcs8PrivateKey}, {@code
 *       ImportSubjectPublicKeyInfo}, {@code ImportFromPem}, {@code ImportEncryptedPkcs8PrivateKey},
 *       {@code ImportFromEncryptedPem}): the parameter set is embedded inside the encoded key
 *       material / PEM text, not present as a separate literal argument, so — exactly as for
 *       ML-KEM/ML-DSA — it cannot be recovered by this engine. These translate to a generic node
 *       with no {@code ParameterSetIdentifier} child, a known, inherent precision gap, not a bug.
 * </ul>
 *
 * <p>{@code SlhDsaCng(CngKey)} and {@code SlhDsaOpenSsl(SafeEvpPKeyHandle)} wrap an
 * already-existing native key handle and never receive an algorithm argument at all, so they always
 * translate to the generic node, mirroring {@code MLDsaCng(CngKey)}/{@code
 * MLDsaOpenSsl(SafeEvpPKeyHandle)}.
 *
 * <p><b>Sign/Verify modeling:</b> {@code SlhDsa} is an ordinary signature primitive, so its
 * operations are modeled with {@code SignatureActionFactory} under a {@code SignatureContext} — the
 * exact same shape as {@code DotNetDSA}/{@code DotNetECDsa}/{@code DotNetMLDsa}'s {@code
 * SignData}/{@code VerifyData} rules, reusing the existing generic SIGN/VERIFY dispatch in {@code
 * CSharpSignatureContextTranslator} (no changes needed there: it already maps {@code
 * SignatureAction.Action.SIGN}/{@code VERIFY} to {@code Sign}/{@code Verify} functionality nodes
 * regardless of which algorithm produced the action, so this rule set is purely additive from its
 * perspective). {@code SignPreHash}/{@code VerifyPreHash} (the FIPS 205 pre-hash variant) are
 * modeled the same way as {@code SignData}/{@code VerifyData}, since the engine cannot meaningfully
 * distinguish "what was hashed before signing" from "what was signed" without value tracking — no
 * {@code SignMu}/{@code VerifyMu} rules exist here, since (per the verified reference) {@code
 * SlhDsa} has no such methods. The {@code *Core} overrides ({@code SignDataCore}, {@code
 * SignPreHashCore}, {@code VerifyDataCore}, {@code VerifyPreHashCore}) are protected extensibility
 * hooks for subclassing, not called by ordinary consumer code, and are intentionally not modeled —
 * consistent with not modeling {@code SignMuCore}/{@code VerifyMuCore} in {@code DotNetMLDsa}.
 *
 * <p><b>Mapper model reuse — no new model class needed:</b> a repository-wide search ({@code grep
 * -rl "SlhDsa\|SLHDSA\|SLH-DSA\|SPHINCS" mapper/}) found that {@code
 * com.ibm.mapper.model.algorithms.SPHINCSPlus} (implementing {@code Signature}, {@code NAME =
 * "SLH-DSA"}, documented as "Other Names and Related Standards: SPHINCS+") already existed before
 * this batch — used by the BouncyCastle {@code SPHINCSPlusSigner} translation ({@code
 * BcMessageSignerMapper}) — but its {@code asString()} only appended a {@code MessageDigest} child
 * (never actually exercised — {@code SPHINCSPlusSigner} maps to a bare {@code new
 * SPHINCSPlus(detectionLocation)} with no children, confirmed by grep — no existing test asserts
 * {@code asString()} behavior with a child attached, so extending it is safe). This batch adds one
 * new, purely additive {@code SPHINCSPlus(String parameterSetIdentifier, DetectionLocation)}
 * constructor and extends {@code asString()} to also check for a {@code ParameterSetIdentifier}
 * child (prepended with "-", independent of and before the pre-existing {@code MessageDigest}
 * check, whose no-args/no-children call path is completely unchanged), so {@code asString()} now
 * yields e.g. {@code "SLH-DSA-SHA2-128s"} — matching the exact FIPS 205 parameter set naming
 * convention (hash family + security level + speed tradeoff) referenced by the class's own
 * "cyclonedx.org/schema/cryptography-defs.json (algorithmName: SLH-DSA)" specification link. No new
 * mapper model class was introduced for SLH-DSA — an existing, if previously underused, class was
 * completed instead.
 *
 * <p><b>Not covered (deliberately, consistent with the rest of this rule set):</b> the {@code
 * Algorithm}/{@code IsSupported} getters (state reads, not configuration — no property setters
 * exist on {@code SlhDsa} at all), {@code SlhDsaCng.GetKey()}/{@code
 * SlhDsaOpenSsl.DuplicateKeyHandle()} (native-handle export, the {@code SlhDsa}-specific equivalent
 * of the {@code Export*} methods skipped for RSA/ECDsa/ECDiffieHellman/MLDsa), {@code Dispose()},
 * and all {@code ExportXxx}/{@code TryExportXxx}/{@code ExportXxxPem} instance methods (standard
 * PKCS#8/SPKI/PEM export — same convention as RSA/ECDsa/ECDiffieHellman/MLKem/MLDsa).
 */
@SuppressWarnings("java:S1192")
public final class DotNetSlhDsa {

    private DotNetSlhDsa() {
        // nothing
    }

    // =========================================================================
    // Sign / Verify operation rules (depending rules on any tracked SlhDsa-family variable,
    // mirroring DotNetMLDsa.java's SignData/VerifyData/SignPreHash/VerifyPreHash rules; no
    // SignMu/VerifyMu — confirmed absent from the official SlhDsa reference, see class javadoc)
    // =========================================================================

    // slhDsa.SignData(data, context) — 2 overloads (array-based and Span-based)
    private static final IDetectionRule<CSharpTree> SLHDSA_SIGN_DATA =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes(MethodMatcher.ANY)
                    .forMethods("SignData")
                    .shouldBeDetectedAs(new SignatureActionFactory<>(SignatureAction.Action.SIGN))
                    .withAnyParameters()
                    .buildForContext(new SignatureContext())
                    .inBundle(() -> "DotNet")
                    .withoutDependingDetectionRules();

    // slhDsa.VerifyData(data, signature, context) — 2 overloads
    private static final IDetectionRule<CSharpTree> SLHDSA_VERIFY_DATA =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes(MethodMatcher.ANY)
                    .forMethods("VerifyData")
                    .shouldBeDetectedAs(new SignatureActionFactory<>(SignatureAction.Action.VERIFY))
                    .withAnyParameters()
                    .buildForContext(new SignatureContext())
                    .inBundle(() -> "DotNet")
                    .withoutDependingDetectionRules();

    // slhDsa.SignPreHash(hash, hashAlgorithmOid, context) — 2 overloads
    private static final IDetectionRule<CSharpTree> SLHDSA_SIGN_PRE_HASH =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes(MethodMatcher.ANY)
                    .forMethods("SignPreHash")
                    .shouldBeDetectedAs(new SignatureActionFactory<>(SignatureAction.Action.SIGN))
                    .withAnyParameters()
                    .buildForContext(new SignatureContext())
                    .inBundle(() -> "DotNet")
                    .withoutDependingDetectionRules();

    // slhDsa.VerifyPreHash(hash, signature, hashAlgorithmOid, context) — 2 overloads
    private static final IDetectionRule<CSharpTree> SLHDSA_VERIFY_PRE_HASH =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes(MethodMatcher.ANY)
                    .forMethods("VerifyPreHash")
                    .shouldBeDetectedAs(new SignatureActionFactory<>(SignatureAction.Action.VERIFY))
                    .withAnyParameters()
                    .buildForContext(new SignatureContext())
                    .inBundle(() -> "DotNet")
                    .withoutDependingDetectionRules();

    /** Full set of depending rules for {@code SlhDsa}/{@code SlhDsaCng}/{@code SlhDsaOpenSsl}. */
    private static final List<IDetectionRule<CSharpTree>> SLHDSA_DEPENDING_RULES =
            List.of(
                    SLHDSA_SIGN_DATA,
                    SLHDSA_VERIFY_DATA,
                    SLHDSA_SIGN_PRE_HASH,
                    SLHDSA_VERIFY_PRE_HASH);

    // =========================================================================
    // SlhDsa — primary creation rules, algorithm-parameterized (SlhDsaAlgorithm argument captured
    // as the parameter set, see class javadoc)
    // =========================================================================

    // SlhDsa.GenerateKey(SlhDsaAlgorithm.SlhDsaSha2_128s)
    private static final IDetectionRule<CSharpTree> SLHDSA_GENERATE_KEY =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes("SlhDsa")
                    .forMethods("GenerateKey")
                    .shouldBeDetectedAs(new ValueActionFactory<>("SLH-DSA"))
                    .withMethodParameter(MethodMatcher.ANY) // SlhDsaAlgorithm
                    .shouldBeDetectedAs(new ParameterIdentifierFactory<>())
                    .asChildOfParameterWithId(-1)
                    .buildForContext(new KeyContext(Map.of("kind", "SLHDSA")))
                    .inBundle(() -> "DotNet")
                    .withDependingDetectionRules(SLHDSA_DEPENDING_RULES);

    // SlhDsa.ImportSlhDsaPrivateKey(SlhDsaAlgorithm.SlhDsaSha2_128s, privateKeyBytes)
    private static final IDetectionRule<CSharpTree> SLHDSA_IMPORT_PRIVATE_KEY =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes("SlhDsa")
                    .forMethods("ImportSlhDsaPrivateKey")
                    .shouldBeDetectedAs(new ValueActionFactory<>("SLH-DSA"))
                    .withMethodParameter(MethodMatcher.ANY) // SlhDsaAlgorithm
                    .shouldBeDetectedAs(new ParameterIdentifierFactory<>())
                    .asChildOfParameterWithId(-1)
                    .withMethodParameter(MethodMatcher.ANY) // private key bytes
                    .buildForContext(new KeyContext(Map.of("kind", "SLHDSA")))
                    .inBundle(() -> "DotNet")
                    .withDependingDetectionRules(SLHDSA_DEPENDING_RULES);

    // SlhDsa.ImportSlhDsaPublicKey(SlhDsaAlgorithm.SlhDsaSha2_128s, publicKeyBytes)
    private static final IDetectionRule<CSharpTree> SLHDSA_IMPORT_PUBLIC_KEY =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes("SlhDsa")
                    .forMethods("ImportSlhDsaPublicKey")
                    .shouldBeDetectedAs(new ValueActionFactory<>("SLH-DSA"))
                    .withMethodParameter(MethodMatcher.ANY) // SlhDsaAlgorithm
                    .shouldBeDetectedAs(new ParameterIdentifierFactory<>())
                    .asChildOfParameterWithId(-1)
                    .withMethodParameter(MethodMatcher.ANY) // public key bytes
                    .buildForContext(new KeyContext(Map.of("kind", "SLHDSA")))
                    .inBundle(() -> "DotNet")
                    .withDependingDetectionRules(SLHDSA_DEPENDING_RULES);

    // =========================================================================
    // SlhDsa — primary creation rules, structural imports (no SlhDsaAlgorithm argument; see class
    // javadoc for why the parameter set cannot be captured for these)
    // =========================================================================

    private static IDetectionRule<CSharpTree> structuralImportRule(@Nonnull String methodName) {
        return new DetectionRuleBuilder<CSharpTree>()
                .createDetectionRule()
                .forObjectTypes("SlhDsa")
                .forMethods(methodName)
                .shouldBeDetectedAs(new ValueActionFactory<>("SLH-DSA"))
                .withAnyParameters()
                .buildForContext(new KeyContext(Map.of("kind", "SLHDSA")))
                .inBundle(() -> "DotNet")
                .withDependingDetectionRules(SLHDSA_DEPENDING_RULES);
    }

    // SlhDsa.ImportPkcs8PrivateKey(source) / SlhDsa.ImportSubjectPublicKeyInfo(source) /
    // SlhDsa.ImportFromPem(pem) / SlhDsa.ImportEncryptedPkcs8PrivateKey(...) /
    // SlhDsa.ImportFromEncryptedPem(...)
    private static final IDetectionRule<CSharpTree> SLHDSA_IMPORT_PKCS8_PRIVATE_KEY =
            structuralImportRule("ImportPkcs8PrivateKey");

    private static final IDetectionRule<CSharpTree> SLHDSA_IMPORT_SUBJECT_PUBLIC_KEY_INFO =
            structuralImportRule("ImportSubjectPublicKeyInfo");

    private static final IDetectionRule<CSharpTree> SLHDSA_IMPORT_FROM_PEM =
            structuralImportRule("ImportFromPem");

    private static final IDetectionRule<CSharpTree> SLHDSA_IMPORT_ENCRYPTED_PKCS8_PRIVATE_KEY =
            structuralImportRule("ImportEncryptedPkcs8PrivateKey");

    private static final IDetectionRule<CSharpTree> SLHDSA_IMPORT_FROM_ENCRYPTED_PEM =
            structuralImportRule("ImportFromEncryptedPem");

    // =========================================================================
    // SlhDsa — primary creation rules, native-interop constructors (no SlhDsaAlgorithm argument;
    // wrap an already-existing native key handle, mirroring MLDsaCng/MLDsaOpenSsl in DotNetMLDsa)
    // =========================================================================

    // new SlhDsaCng(cngKey)
    private static final IDetectionRule<CSharpTree> SLHDSA_CNG =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes("SlhDsaCng")
                    .forMethods("<init>")
                    .shouldBeDetectedAs(new ValueActionFactory<>("SLH-DSA"))
                    .withAnyParameters()
                    .buildForContext(new KeyContext(Map.of("kind", "SLHDSA")))
                    .inBundle(() -> "DotNet")
                    .withDependingDetectionRules(SLHDSA_DEPENDING_RULES);

    // new SlhDsaOpenSsl(safeEvpPKeyHandle)
    private static final IDetectionRule<CSharpTree> SLHDSA_OPENSSL =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes("SlhDsaOpenSsl")
                    .forMethods("<init>")
                    .shouldBeDetectedAs(new ValueActionFactory<>("SLH-DSA"))
                    .withAnyParameters()
                    .buildForContext(new KeyContext(Map.of("kind", "SLHDSA")))
                    .inBundle(() -> "DotNet")
                    .withDependingDetectionRules(SLHDSA_DEPENDING_RULES);

    @Nonnull
    public static List<IDetectionRule<CSharpTree>> rules() {
        return List.of(
                SLHDSA_GENERATE_KEY,
                SLHDSA_IMPORT_PRIVATE_KEY,
                SLHDSA_IMPORT_PUBLIC_KEY,
                SLHDSA_IMPORT_PKCS8_PRIVATE_KEY,
                SLHDSA_IMPORT_SUBJECT_PUBLIC_KEY_INFO,
                SLHDSA_IMPORT_FROM_PEM,
                SLHDSA_IMPORT_ENCRYPTED_PKCS8_PRIVATE_KEY,
                SLHDSA_IMPORT_FROM_ENCRYPTED_PEM,
                SLHDSA_CNG,
                SLHDSA_OPENSSL);
    }
}
