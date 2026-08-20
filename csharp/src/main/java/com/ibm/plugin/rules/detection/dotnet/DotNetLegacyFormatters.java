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
import com.ibm.engine.model.CipherAction;
import com.ibm.engine.model.SignatureAction;
import com.ibm.engine.model.context.CipherContext;
import com.ibm.engine.model.context.DigestContext;
import com.ibm.engine.model.context.KeyContext;
import com.ibm.engine.model.context.SignatureContext;
import com.ibm.engine.model.factory.AlgorithmFactory;
import com.ibm.engine.model.factory.CipherActionFactory;
import com.ibm.engine.model.factory.PaddingFactory;
import com.ibm.engine.model.factory.SignatureActionFactory;
import com.ibm.engine.model.factory.ValueActionFactory;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import java.util.List;
import java.util.Map;
import javax.annotation.Nonnull;

/**
 * Detection rules for the legacy Formatter/Deformatter and mask-generation classes in {@code
 * System.Security.Cryptography}.
 *
 * <p>Classes covered (all nine, all still present through net-11.0 per the official API reference —
 * none were removed in modern .NET):
 *
 * <ul>
 *   <li>{@code DSASignatureFormatter} / {@code DSASignatureDeformatter} — create/verify a DSA
 *       signature from a caller-supplied hash
 *   <li>{@code RSAPKCS1SignatureFormatter} / {@code RSAPKCS1SignatureDeformatter} — create/verify
 *       an RSA PKCS #1 v1.5 signature from a caller-supplied hash
 *   <li>{@code RSAOAEPKeyExchangeFormatter} / {@code RSAOAEPKeyExchangeDeformatter} —
 *       encrypt/decrypt a symmetric key using RSA-OAEP ("key exchange")
 *   <li>{@code RSAPKCS1KeyExchangeFormatter} / {@code RSAPKCS1KeyExchangeDeformatter} —
 *       encrypt/decrypt a symmetric key using RSA PKCS #1 v1.5 ("key exchange")
 *   <li>{@code PKCS1MaskGenerationMethod} — the PKCS #1 (MGF1) mask generation function used
 *       internally by OAEP implementations
 * </ul>
 *
 * <p>Architecture: each Formatter/Deformatter constructor is modeled exactly like the primary
 * creation rules in {@link DotNetDSA} / {@link DotNetRSA} — a top-level {@link ValueActionFactory}
 * of {@code "DSA"} or {@code "RSA"} under {@link KeyContext}{@code (kind=DSA/RSA)}, which is
 * already translated by the existing {@code CSharpKeyContextTranslator} switch (no translator
 * changes needed for those two). The class's two constructors ({@code ()} and {@code
 * (AsymmetricAlgorithm)}) are collapsed into a single {@code withAnyParameters()} rule, mirroring
 * {@code DSA_CNG}/{@code RSA_CNG} in the referenced files.
 *
 * <p><b>{@code CreateSignature}/{@code VerifySignature}</b> are modeled as depending rules using
 * {@link SignatureActionFactory} ({@code SIGN}/{@code VERIFY}) under {@link SignatureContext}, with
 * {@code withAnyParameters()} — deliberately not attempting to also capture the PKCS #1 v1.5
 * padding implied by the RSA classes' names, mirroring {@link DotNetRSA}'s own {@code
 * RSA_SIGN_DATA}/{@code RSA_VERIFY_DATA} rules, which likewise never capture the {@code
 * RSASignaturePadding} parameter of the modern {@code RSA.SignData}/{@code VerifyData} API. There
 * is also no existing precedent anywhere in this codebase (Java or C#) for attaching a {@code
 * Padding} value under a {@code SignatureContext} detection, so doing so here would require
 * inventing new translation code for a single, low-priority call site.
 *
 * <p><b>{@code SetHashAlgorithm(string)}</b> (on all four Signature Formatter/Deformatter classes)
 * takes a literal hash-algorithm name (e.g. {@code "SHA1"}, {@code "SHA256"}) — unlike most
 * parameters elsewhere in this module, this one is directly readable by the ANTLR4-based engine
 * (see {@code CSharpTreeConverter}, which resolves string literals). It is captured with the
 * existing {@link AlgorithmFactory} under {@link DigestContext}, reusing the {@code Algorithm<?>}
 * branch already present in {@code CSharpDigestContextTranslator} (no translator changes needed).
 *
 * <p><b>{@code CreateKeyExchange}/{@code DecryptKeyExchange}</b> (on the four KeyExchange
 * Formatter/Deformatter classes) are modeled as {@link CipherActionFactory} ({@code
 * CipherAction.Action.ENCRYPT}/{@code DECRYPT}) under {@link CipherContext}, with a constant {@link
 * PaddingFactory} ({@code "OAEP"} or {@code "PKCS1Padding"}) attached to the first parameter —
 * exactly the same "constant value keyed off which rule/method matched" pattern {@link DotNetAES}
 * uses for {@code ModeFactory<>("CBC")} on {@code EncryptCbc}/{@code DecryptCbc}. Both padding
 * strings are already understood by the existing {@code JcaPaddingMapper} reused via {@code
 * CSharpCipherContextTranslator}'s {@code Padding<?>} branch ({@code "OAEP"} routes to {@code
 * JcaOAEPPaddingMapper}, {@code "PKCS1Padding"} matches its {@code PKCS1} case exactly), so no
 * translator changes were needed for this either. Unlike the signature padding case above, this is
 * not blocked by the "no parameter value resolution" engine limitation at all: the padding scheme
 * here is a compile-time fact of which concrete class was instantiated (its class name), not a
 * runtime argument that would need to be resolved.
 *
 * <p><b>Open design question — {@code CipherAction.Action.WRAP} vs. {@code ENCRYPT}/{@code DECRYPT}
 * for key exchange:</b> the engine's {@code CipherAction.Action} enum already defines {@code WRAP},
 * used by {@code JcaCipherWrap} (Java, {@code Cipher.WRAP_MODE}) and {@code PycaWrapping} (Python).
 * However, its translation is <em>not</em> consistent between those two: {@code
 * JavaCipherContextTranslator} maps {@code WRAP} to the generic {@code Encapsulate} functionality,
 * while {@code PycaCipherContextTranslator} maps it to a {@code KeyWrap}-typed algorithm variant
 * instead of an operation node at all. {@code CSharpCipherContextTranslator} does not handle {@code
 * WRAP} at present (falls through to {@code default -> Optional.empty()}). Given this pre-existing
 * inconsistency, this file deliberately uses the already-wired {@code ENCRYPT}/{@code DECRYPT}
 * actions instead — which also matches the fact that both {@code RSAOAEPKeyExchangeFormatter} and
 * {@code RSAPKCS1KeyExchangeFormatter}'s reference-source implementations literally delegate to
 * {@code RSA.Encrypt}/{@code RSA.Decrypt} internally, the exact same operation {@link DotNetRSA}'s
 * own {@code RSA_ENCRYPT}/{@code RSA_DECRYPT} rules already model with {@code ENCRYPT}/{@code
 * DECRYPT}. Should a unified cross-language "key wrap" CBOM concept ever be settled on, these four
 * rules (the {@code CREATE_KEY_EXCHANGE_*}/{@code DECRYPT_KEY_EXCHANGE_*} constants below) are the
 * ones to revisit.
 *
 * <p><b>{@code PKCS1MaskGenerationMethod}</b> reuses the existing MGF1 concept already present in
 * the mapper model ({@code mapper/model/algorithms/MGF1.java}, implementing {@code
 * MaskGenerationFunction} — already used by {@code JcaMGFMapper}/{@code JcaOAEPPaddingMapper} for
 * JCA's OAEP padding translation), rather than inventing a new one. Its sole constructor is
 * captured as {@code ValueActionFactory<>("MGF1")} under {@code KeyContext(kind=MGF1)} — reusing
 * {@link KeyContext} as the generic "identify which standalone algorithm was just constructed"
 * context already used in this module for RSA/DSA/ECDSA/ECDH/X25519/ML-KEM/ML-DSA/SLH-DSA/KDF
 * variants (see {@code CSharpKeyContextTranslator}), not because MGF1 is a "key" algorithm in the
 * strict sense. This required one small <em>additive</em> case in {@code
 * CSharpKeyContextTranslator}'s existing kind switch: {@code case "MGF1" -> Optional.of(new
 * MGF1(detectionLocation))}. Its {@code HashName} property (compiles to a synthetic {@code
 * set_HashName(string)} call, see {@code CSharpTreeConverter}) is captured with the same {@link
 * AlgorithmFactory}/{@link DigestContext} pattern as {@code SetHashAlgorithm} above, producing a
 * digest child of the MGF1 node. Per the official reference, "This class is only used by
 * implementations of key exchange algorithms for mask generation. Application code does not use
 * this class directly" — so {@code GenerateMask(byte[], int)} is intentionally <em>not</em> modeled
 * as a depending rule: like {@code DotNetSHA}'s {@code ComputeHash} (see that class's own javadoc),
 * invoking it adds no cryptographic information beyond what the constructor already captured (the
 * mask-generation algorithm is always MGF1; only the hash feeding it, already captured via {@code
 * HashName}, varies).
 *
 * <p><b>Known gap — {@code SetKey(AsymmetricAlgorithm)}:</b> present on all eight
 * Formatter/Deformatter classes, this method is typically called with a variable holding a
 * previously created {@code DSA}/{@code RSA} instance (e.g. {@code formatter.SetKey(dsa)} where
 * {@code dsa} came from {@code DSA.Create()} in an earlier statement). Per the engine's documented
 * limitations ({@code CSharpSymbol} — "Full symbol tracking across scopes is not supported"; {@code
 * CSharpLanguageTranslation} — no parameter type resolution), the concrete key instance behind such
 * a variable cannot be resolved and linked to this call. This is a known, unavoidable gap: {@code
 * SetKey} is therefore intentionally <em>not</em> modeled as a detection rule here (no rule would
 * ever usefully fire), rather than faking a value. The Formatter/Deformatter class itself is still
 * fully detected in isolation via its constructor (which already identifies the algorithm family —
 * DSA or RSA — from the class name alone, independent of {@code SetKey}). The same reasoning
 * applies to the non-crypto-identity-bearing {@code Rng}/{@code Parameter}/{@code Parameters}
 * properties on the KeyExchange formatters ({@code Rng} in particular would need to resolve a
 * {@code new SomeRng()} expression assigned via a property setter, which {@code
 * CSharpTreeConverter}'s {@code convertPrimaryExpressionStart} does not handle for object-creation
 * right-hand sides — only literals and bare identifiers), so they are likewise left undetected.
 */
@SuppressWarnings("java:S1192")
public final class DotNetLegacyFormatters {

    private DotNetLegacyFormatters() {
        // nothing
    }

    // =========================================================================
    // Shared depending rules: signature operations (DSA + RSA PKCS#1 formatters)
    // =========================================================================

    // formatter.CreateSignature(hash) — byte[] override or inherited HashAlgorithm override,
    // indistinguishable to this engine (see class javadoc: no padding capture, mirrors DotNetRSA).
    private static final IDetectionRule<CSharpTree> CREATE_SIGNATURE =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes(MethodMatcher.ANY)
                    .forMethods("CreateSignature")
                    .shouldBeDetectedAs(new SignatureActionFactory<>(SignatureAction.Action.SIGN))
                    .withAnyParameters()
                    .buildForContext(new SignatureContext())
                    .inBundle(() -> "DotNet")
                    .withoutDependingDetectionRules();

    // deformatter.VerifySignature(hash, signature) — byte[] or inherited HashAlgorithm override.
    private static final IDetectionRule<CSharpTree> VERIFY_SIGNATURE =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes(MethodMatcher.ANY)
                    .forMethods("VerifySignature")
                    .shouldBeDetectedAs(new SignatureActionFactory<>(SignatureAction.Action.VERIFY))
                    .withAnyParameters()
                    .buildForContext(new SignatureContext())
                    .inBundle(() -> "DotNet")
                    .withoutDependingDetectionRules();

    // (de)formatter.SetHashAlgorithm("SHA256") — literal string, shared across all four
    // Signature Formatter/Deformatter classes (same method name and semantics on each).
    private static final IDetectionRule<CSharpTree> SET_HASH_ALGORITHM =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes(MethodMatcher.ANY)
                    .forMethods("SetHashAlgorithm")
                    .withMethodParameter(MethodMatcher.ANY)
                    .shouldBeDetectedAs(new AlgorithmFactory<>())
                    .buildForContext(new DigestContext())
                    .inBundle(() -> "DotNet")
                    .withoutDependingDetectionRules();

    private static final List<IDetectionRule<CSharpTree>> SIGN_DEPENDING_RULES =
            List.of(CREATE_SIGNATURE, SET_HASH_ALGORITHM);

    private static final List<IDetectionRule<CSharpTree>> VERIFY_DEPENDING_RULES =
            List.of(VERIFY_SIGNATURE, SET_HASH_ALGORITHM);

    // =========================================================================
    // Depending rules: RSA key exchange operations (OAEP and PKCS#1 formatters)
    // Constant padding value attached from which rule/arity matched (class name), not from a
    // resolved parameter value — see class javadoc.
    // =========================================================================

    // oaepFormatter.CreateKeyExchange(rgbData)
    private static final IDetectionRule<CSharpTree> CREATE_KEY_EXCHANGE_OAEP_1 =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes(MethodMatcher.ANY)
                    .forMethods("CreateKeyExchange")
                    .shouldBeDetectedAs(new CipherActionFactory<>(CipherAction.Action.ENCRYPT))
                    .withMethodParameter(MethodMatcher.ANY) // rgbData (symmetric key material)
                    .shouldBeDetectedAs(new PaddingFactory<>("OAEP"))
                    .buildForContext(new CipherContext())
                    .inBundle(() -> "DotNet")
                    .withoutDependingDetectionRules();

    // oaepFormatter.CreateKeyExchange(rgbData, symAlgType)
    private static final IDetectionRule<CSharpTree> CREATE_KEY_EXCHANGE_OAEP_2 =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes(MethodMatcher.ANY)
                    .forMethods("CreateKeyExchange")
                    .shouldBeDetectedAs(new CipherActionFactory<>(CipherAction.Action.ENCRYPT))
                    .withMethodParameter(MethodMatcher.ANY) // rgbData
                    .shouldBeDetectedAs(new PaddingFactory<>("OAEP"))
                    .withMethodParameter(MethodMatcher.ANY) // symAlgType
                    .buildForContext(new CipherContext())
                    .inBundle(() -> "DotNet")
                    .withoutDependingDetectionRules();

    // oaepDeformatter.DecryptKeyExchange(rgbData) — single overload per the official reference.
    private static final IDetectionRule<CSharpTree> DECRYPT_KEY_EXCHANGE_OAEP =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes(MethodMatcher.ANY)
                    .forMethods("DecryptKeyExchange")
                    .shouldBeDetectedAs(new CipherActionFactory<>(CipherAction.Action.DECRYPT))
                    .withMethodParameter(MethodMatcher.ANY) // rgbIn
                    .shouldBeDetectedAs(new PaddingFactory<>("OAEP"))
                    .buildForContext(new CipherContext())
                    .inBundle(() -> "DotNet")
                    .withoutDependingDetectionRules();

    // pkcs1Formatter.CreateKeyExchange(rgbData)
    private static final IDetectionRule<CSharpTree> CREATE_KEY_EXCHANGE_PKCS1_1 =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes(MethodMatcher.ANY)
                    .forMethods("CreateKeyExchange")
                    .shouldBeDetectedAs(new CipherActionFactory<>(CipherAction.Action.ENCRYPT))
                    .withMethodParameter(MethodMatcher.ANY) // rgbData
                    .shouldBeDetectedAs(new PaddingFactory<>("PKCS1Padding"))
                    .buildForContext(new CipherContext())
                    .inBundle(() -> "DotNet")
                    .withoutDependingDetectionRules();

    // pkcs1Formatter.CreateKeyExchange(rgbData, symAlgType)
    private static final IDetectionRule<CSharpTree> CREATE_KEY_EXCHANGE_PKCS1_2 =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes(MethodMatcher.ANY)
                    .forMethods("CreateKeyExchange")
                    .shouldBeDetectedAs(new CipherActionFactory<>(CipherAction.Action.ENCRYPT))
                    .withMethodParameter(MethodMatcher.ANY) // rgbData
                    .shouldBeDetectedAs(new PaddingFactory<>("PKCS1Padding"))
                    .withMethodParameter(MethodMatcher.ANY) // symAlgType
                    .buildForContext(new CipherContext())
                    .inBundle(() -> "DotNet")
                    .withoutDependingDetectionRules();

    // pkcs1Deformatter.DecryptKeyExchange(rgbIn) — single overload.
    private static final IDetectionRule<CSharpTree> DECRYPT_KEY_EXCHANGE_PKCS1 =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes(MethodMatcher.ANY)
                    .forMethods("DecryptKeyExchange")
                    .shouldBeDetectedAs(new CipherActionFactory<>(CipherAction.Action.DECRYPT))
                    .withMethodParameter(MethodMatcher.ANY) // rgbIn
                    .shouldBeDetectedAs(new PaddingFactory<>("PKCS1Padding"))
                    .buildForContext(new CipherContext())
                    .inBundle(() -> "DotNet")
                    .withoutDependingDetectionRules();

    private static final List<IDetectionRule<CSharpTree>> OAEP_FORMATTER_DEPENDING_RULES =
            List.of(CREATE_KEY_EXCHANGE_OAEP_1, CREATE_KEY_EXCHANGE_OAEP_2);

    private static final List<IDetectionRule<CSharpTree>> OAEP_DEFORMATTER_DEPENDING_RULES =
            List.of(DECRYPT_KEY_EXCHANGE_OAEP);

    private static final List<IDetectionRule<CSharpTree>> PKCS1_KX_FORMATTER_DEPENDING_RULES =
            List.of(CREATE_KEY_EXCHANGE_PKCS1_1, CREATE_KEY_EXCHANGE_PKCS1_2);

    private static final List<IDetectionRule<CSharpTree>> PKCS1_KX_DEFORMATTER_DEPENDING_RULES =
            List.of(DECRYPT_KEY_EXCHANGE_PKCS1);

    // =========================================================================
    // Depending rule: PKCS1MaskGenerationMethod.HashName property setter
    // =========================================================================

    // mgf.HashName = "SHA256"  →  synthetic set_HashName("SHA256")
    private static final IDetectionRule<CSharpTree> MGF1_SET_HASH_NAME =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes(MethodMatcher.ANY)
                    .forMethods("set_HashName")
                    .withMethodParameter(MethodMatcher.ANY)
                    .shouldBeDetectedAs(new AlgorithmFactory<>())
                    .buildForContext(new DigestContext())
                    .inBundle(() -> "DotNet")
                    .withoutDependingDetectionRules();

    // =========================================================================
    // Primary creation rules
    // =========================================================================

    // new DSASignatureFormatter() / new DSASignatureFormatter(AsymmetricAlgorithm)
    private static final IDetectionRule<CSharpTree> DSA_SIGNATURE_FORMATTER =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes("DSASignatureFormatter")
                    .forMethods("<init>")
                    .shouldBeDetectedAs(new ValueActionFactory<>("DSA"))
                    .withAnyParameters()
                    .buildForContext(new KeyContext(Map.of("kind", "DSA")))
                    .inBundle(() -> "DotNet")
                    .withDependingDetectionRules(SIGN_DEPENDING_RULES);

    // new DSASignatureDeformatter() / new DSASignatureDeformatter(AsymmetricAlgorithm)
    private static final IDetectionRule<CSharpTree> DSA_SIGNATURE_DEFORMATTER =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes("DSASignatureDeformatter")
                    .forMethods("<init>")
                    .shouldBeDetectedAs(new ValueActionFactory<>("DSA"))
                    .withAnyParameters()
                    .buildForContext(new KeyContext(Map.of("kind", "DSA")))
                    .inBundle(() -> "DotNet")
                    .withDependingDetectionRules(VERIFY_DEPENDING_RULES);

    // new RSAPKCS1SignatureFormatter() / new RSAPKCS1SignatureFormatter(AsymmetricAlgorithm)
    private static final IDetectionRule<CSharpTree> RSA_PKCS1_SIGNATURE_FORMATTER =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes("RSAPKCS1SignatureFormatter")
                    .forMethods("<init>")
                    .shouldBeDetectedAs(new ValueActionFactory<>("RSA"))
                    .withAnyParameters()
                    .buildForContext(new KeyContext(Map.of("kind", "RSA")))
                    .inBundle(() -> "DotNet")
                    .withDependingDetectionRules(SIGN_DEPENDING_RULES);

    // new RSAPKCS1SignatureDeformatter() / new RSAPKCS1SignatureDeformatter(AsymmetricAlgorithm)
    private static final IDetectionRule<CSharpTree> RSA_PKCS1_SIGNATURE_DEFORMATTER =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes("RSAPKCS1SignatureDeformatter")
                    .forMethods("<init>")
                    .shouldBeDetectedAs(new ValueActionFactory<>("RSA"))
                    .withAnyParameters()
                    .buildForContext(new KeyContext(Map.of("kind", "RSA")))
                    .inBundle(() -> "DotNet")
                    .withDependingDetectionRules(VERIFY_DEPENDING_RULES);

    // new RSAOAEPKeyExchangeFormatter() / new RSAOAEPKeyExchangeFormatter(AsymmetricAlgorithm)
    private static final IDetectionRule<CSharpTree> RSA_OAEP_KEY_EXCHANGE_FORMATTER =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes("RSAOAEPKeyExchangeFormatter")
                    .forMethods("<init>")
                    .shouldBeDetectedAs(new ValueActionFactory<>("RSA"))
                    .withAnyParameters()
                    .buildForContext(new KeyContext(Map.of("kind", "RSA")))
                    .inBundle(() -> "DotNet")
                    .withDependingDetectionRules(OAEP_FORMATTER_DEPENDING_RULES);

    // new RSAOAEPKeyExchangeDeformatter() / new RSAOAEPKeyExchangeDeformatter(AsymmetricAlgorithm)
    private static final IDetectionRule<CSharpTree> RSA_OAEP_KEY_EXCHANGE_DEFORMATTER =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes("RSAOAEPKeyExchangeDeformatter")
                    .forMethods("<init>")
                    .shouldBeDetectedAs(new ValueActionFactory<>("RSA"))
                    .withAnyParameters()
                    .buildForContext(new KeyContext(Map.of("kind", "RSA")))
                    .inBundle(() -> "DotNet")
                    .withDependingDetectionRules(OAEP_DEFORMATTER_DEPENDING_RULES);

    // new RSAPKCS1KeyExchangeFormatter() / new RSAPKCS1KeyExchangeFormatter(AsymmetricAlgorithm)
    private static final IDetectionRule<CSharpTree> RSA_PKCS1_KEY_EXCHANGE_FORMATTER =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes("RSAPKCS1KeyExchangeFormatter")
                    .forMethods("<init>")
                    .shouldBeDetectedAs(new ValueActionFactory<>("RSA"))
                    .withAnyParameters()
                    .buildForContext(new KeyContext(Map.of("kind", "RSA")))
                    .inBundle(() -> "DotNet")
                    .withDependingDetectionRules(PKCS1_KX_FORMATTER_DEPENDING_RULES);

    // new RSAPKCS1KeyExchangeDeformatter() / new
    // RSAPKCS1KeyExchangeDeformatter(AsymmetricAlgorithm)
    private static final IDetectionRule<CSharpTree> RSA_PKCS1_KEY_EXCHANGE_DEFORMATTER =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes("RSAPKCS1KeyExchangeDeformatter")
                    .forMethods("<init>")
                    .shouldBeDetectedAs(new ValueActionFactory<>("RSA"))
                    .withAnyParameters()
                    .buildForContext(new KeyContext(Map.of("kind", "RSA")))
                    .inBundle(() -> "DotNet")
                    .withDependingDetectionRules(PKCS1_KX_DEFORMATTER_DEPENDING_RULES);

    // new PKCS1MaskGenerationMethod() — single, parameterless constructor.
    private static final IDetectionRule<CSharpTree> PKCS1_MASK_GENERATION_METHOD =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes("PKCS1MaskGenerationMethod")
                    .forMethods("<init>")
                    .shouldBeDetectedAs(new ValueActionFactory<>("MGF1"))
                    .withoutParameters()
                    .buildForContext(new KeyContext(Map.of("kind", "MGF1")))
                    .inBundle(() -> "DotNet")
                    .withDependingDetectionRules(List.of(MGF1_SET_HASH_NAME));

    @Nonnull
    public static List<IDetectionRule<CSharpTree>> rules() {
        return List.of(
                DSA_SIGNATURE_FORMATTER,
                DSA_SIGNATURE_DEFORMATTER,
                RSA_PKCS1_SIGNATURE_FORMATTER,
                RSA_PKCS1_SIGNATURE_DEFORMATTER,
                RSA_OAEP_KEY_EXCHANGE_FORMATTER,
                RSA_OAEP_KEY_EXCHANGE_DEFORMATTER,
                RSA_PKCS1_KEY_EXCHANGE_FORMATTER,
                RSA_PKCS1_KEY_EXCHANGE_DEFORMATTER,
                PKCS1_MASK_GENERATION_METHOD);
    }
}
