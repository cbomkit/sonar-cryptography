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
import com.ibm.engine.model.KeyAction;
import com.ibm.engine.model.context.KeyContext;
import com.ibm.engine.model.factory.KeyActionFactory;
import com.ibm.engine.model.factory.ParameterIdentifierFactory;
import com.ibm.engine.model.factory.ValueActionFactory;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import java.util.List;
import java.util.Map;
import javax.annotation.Nonnull;

/**
 * Detection rules for ML-KEM (Module-Lattice-Based Key-Encapsulation Mechanism, FIPS 203) usage in
 * {@code System.Security.Cryptography}.
 *
 * <p><b>API availability (verified against the official Microsoft Learn API reference, not
 * assumed):</b> {@code MLKem}, {@code MLKemCng}, {@code MLKemOpenSsl} and {@code MLKemAlgorithm}
 * are documented for the {@code net-10.0} and {@code net-11.0} monikers (both listed the "Assembly:
 * System.Security.Cryptography.dll" as in-box, plus "Assembly: Microsoft.Bcl.Cryptography.dll" —
 * package {@code Microsoft.Bcl.Cryptography v11.0.0-preview.7.26381.103} — as a back-compat NuGet
 * shim for {@code MLKem}/{@code MLKemCng}/{@code MLKemAlgorithm} on older TFMs; {@code
 * MLKemOpenSsl} lists only the in-box assembly, since its OpenSSL interop has no back-compat shim).
 * {@code ImportPkcs8PrivateKey} carries a {@code
 * [System.Diagnostics.CodeAnalysis.Experimental("SYSLIB5006")]} attribute on (at least) one of its
 * documented overload snapshots, confirming this whole surface is still an actively evolving
 * preview API as of .NET 10/11 — not a settled, stable API.
 *
 * <p>Classes covered:
 *
 * <ul>
 *   <li>{@code MLKem} — abstract base. All of its members are {@code static} factory methods (no
 *       public constructor exists — the only listed constructor, {@code MLKem(MLKemAlgorithm)}, is
 *       for derived classes): {@code GenerateKey(MLKemAlgorithm)}, {@code
 *       ImportDecapsulationKey(MLKemAlgorithm, byte[])}, {@code
 *       ImportEncapsulationKey(MLKemAlgorithm, byte[])}, {@code ImportPrivateSeed(MLKemAlgorithm,
 *       byte[])}, {@code ImportPkcs8PrivateKey(byte[])}, {@code
 *       ImportSubjectPublicKeyInfo(byte[])}, {@code ImportFromPem(string)}, {@code
 *       ImportEncryptedPkcs8PrivateKey(...)}, {@code ImportFromEncryptedPem(...)}.
 *   <li>{@code MLKemCng} — CNG-backed implementation ({@code MLKemCng(CngKey)} constructor).
 *   <li>{@code MLKemOpenSsl} — OpenSSL-backed implementation ({@code
 *       MLKemOpenSsl(SafeEvpPKeyHandle)} constructor).
 * </ul>
 *
 * <p><b>Architecture — a "fundamental difference" from RSA/ECDsa/ECDiffieHellman justifies covering
 * the {@code Import*} methods here:</b> for RSA/ECDsa/ECDiffieHellman (see {@code DotNetRSA},
 * {@code DotNetECDsa}, {@code DotNetECDiffieHellman}), the {@code Import*}/{@code Export*} members
 * inherited from {@code AsymmetricAlgorithm} are <em>instance</em> methods that mutate/read an
 * already-constructed key object, and are intentionally not modeled (pure key-material plumbing,
 * consistent with not tracking raw byte buffers per the engine's documented limitations). For
 * {@code MLKem}, by contrast, every {@code Import*} method verified above is a {@code static}
 * factory that <em>is</em> the only way (besides {@code GenerateKey} or the {@code MLKemCng}/{@code
 * MLKemOpenSsl} native-interop constructors) to obtain an {@code MLKem} instance in the first place
 * — structurally the same role as {@code RSA.Create(RSAParameters)}, which RSA's rule set does
 * cover. They are therefore treated as primary creation rules here, not skipped.
 *
 * <p>Two creation-rule shapes result from this:
 *
 * <ul>
 *   <li><b>Algorithm-parameterized</b> ({@code GenerateKey}, {@code ImportDecapsulationKey}, {@code
 *       ImportEncapsulationKey}, {@code ImportPrivateSeed}): all take an {@code MLKemAlgorithm}
 *       argument (e.g. {@code MLKemAlgorithm.MLKem768}), a member-access expression the engine
 *       resolves to the bare identifier {@code "MLKem768"} (see {@code
 *       CSharpLanguageTranslation#resolveIdentifierAsString} / {@code getEnumIdentifierName}, the
 *       same mechanism {@code DotNetAES}'s {@code AES_SET_MODE} rule relies on for {@code
 *       CipherMode.CBC}). This is captured with {@code ParameterIdentifierFactory<>()} as a child
 *       of the top-level detection, then mapped in {@code CSharpKeyContextTranslator} from {@code
 *       "MLKem512"/"MLKem768"/"MLKem1024"} to a {@code ParameterSetIdentifier} of {@code
 *       "512"/"768"/"1024"} — reproducing the exact {@code MLKEM(int, DetectionLocation)} shape
 *       already used by {@code JcaKemMapper}/{@code GoCryptoKEMMapper}, so {@code asString()}
 *       yields {@code "ML-KEM-768"} etc., consistent across all three language modules.
 *   <li><b>Structural imports</b> ({@code ImportPkcs8PrivateKey}, {@code
 *       ImportSubjectPublicKeyInfo}, {@code ImportFromPem}, {@code ImportEncryptedPkcs8PrivateKey},
 *       {@code ImportFromEncryptedPem}): the parameter set is embedded inside the encoded key
 *       material / PEM text, not present as a separate literal argument, so it cannot be recovered
 *       by this engine (no byte-content parsing). These translate to a generic {@code MLKEM} node
 *       with no {@code ParameterSetIdentifier} child (mirrors {@code MLKEM(DetectionLocation)}, the
 *       no-argument constructor) — a known, inherent precision gap, not a bug.
 * </ul>
 *
 * <p>{@code MLKemCng(CngKey)} and {@code MLKemOpenSsl(SafeEvpPKeyHandle)} wrap an already-existing
 * native key handle and never receive an {@code MLKemAlgorithm} argument at all, so they always
 * translate to the generic {@code MLKEM} node, mirroring how {@code RSACng(CngKey)} in {@code
 * DotNetRSA} captures no key size either.
 *
 * <p><b>Encapsulate / Decapsulate modeling — no missing {@code CipherAction.Action}/{@code
 * SignatureAction.Action} enum value needed:</b> unlike the concern raised for {@code
 * ECDiffieHellman}'s derive operations (see {@code DotNetECDiffieHellman}'s javadoc), KEM
 * encapsulate/decapsulate turned out to already have first-class support in the engine model:
 * {@code KeyAction.Action} (in {@code com.ibm.engine.model.KeyAction}, used via {@code
 * KeyActionFactory}) already defines {@code ENCAPSULATION} and {@code DECAPSULATION} members, and
 * the mapper model already defines {@code com.ibm.mapper.model.functionality.Encapsulate}/{@code
 * Decapsulate} functionality nodes. This exact combination is already used by the very recently
 * added Go {@code crypto/mlkem} support ({@code GoCryptoMLKEM.java} / {@code
 * GoKeyContextTranslator.java}), which this rule set mirrors: {@code MLKem.Encapsulate(...)} /
 * {@code MLKem.Decapsulate(...)} (both instance methods, confirmed from the official
 * method-reference pages, each with two overloads differing only by array-vs-{@code Span} /
 * out-vs-return parameter shape, collapsed with a single {@code withAnyParameters()} rule per
 * method name — {@code EncapsulateCore}/{@code DecapsulateCore} are protected extensibility hooks
 * for subclassing {@code MLKem} itself, not called by ordinary consumer code, and are intentionally
 * not modeled, consistent with not modeling other protected virtual hooks elsewhere in this rule
 * set) are captured with {@code KeyActionFactory<>(KeyAction .Action.ENCAPSULATION /
 * .DECAPSULATION)} under a {@code KeyContext} of {@code kind = "KEM"}, dispatched in {@code
 * CSharpKeyContextTranslator} exactly like the Go translator does. No detection rule had to fake or
 * omit an action type.
 *
 * <p><b>Mapper model reuse:</b> {@code com.ibm.mapper.model.algorithms.MLKEM} (implementing {@code
 * KeyEncapsulationMechanism}) already existed before this batch — it is used by the JCA,
 * BouncyCastle and Go {@code crypto/mlkem} translations. No new mapper model class was introduced
 * for ML-KEM itself; this rule set is purely additive (new detection rules plus new {@code "KEM"}
 * dispatch branches in {@code CSharpKeyContextTranslator}).
 *
 * <p><b>Not covered (deliberately, consistent with the rest of this rule set):</b> the {@code
 * Algorithm}/{@code IsSupported} getters (state reads, not configuration — no property setters
 * exist on {@code MLKem} at all), {@code MLKemCng.GetKey()} / {@code
 * MLKemOpenSsl.DuplicateKeyHandle()} (native-handle export, the {@code MLKem}-specific equivalent
 * of the {@code Export*} methods skipped for RSA/ECDsa/ECDiffieHellman), {@code Dispose()}, and all
 * {@code ExportXxx}/{@code TryExportXxx}/{@code ExportXxxPem} instance methods (standard
 * PKCS#8/SPKI/PEM export — same convention as RSA/ECDsa/ECDiffieHellman).
 */
@SuppressWarnings("java:S1192")
public final class DotNetMLKem {

    private DotNetMLKem() {
        // nothing
    }

    // =========================================================================
    // Encapsulate / Decapsulate operation rules (depending rules on any tracked MLKem-family
    // variable, mirroring GoCryptoMLKEM.java's ENCAPSULATE_768/DECAPSULATE_768 rules)
    // =========================================================================

    // mlkem.Encapsulate(out ciphertext, out sharedSecret) / mlkem.Encapsulate(ciphertext,
    // sharedSecret)
    private static final IDetectionRule<CSharpTree> MLKEM_ENCAPSULATE =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes(MethodMatcher.ANY)
                    .forMethods("Encapsulate")
                    .shouldBeDetectedAs(new KeyActionFactory<>(KeyAction.Action.ENCAPSULATION))
                    .withAnyParameters()
                    .buildForContext(new KeyContext(Map.of("kind", "KEM")))
                    .inBundle(() -> "DotNet")
                    .withoutDependingDetectionRules();

    // mlkem.Decapsulate(ciphertext) / mlkem.Decapsulate(ciphertext, sharedSecret)
    private static final IDetectionRule<CSharpTree> MLKEM_DECAPSULATE =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes(MethodMatcher.ANY)
                    .forMethods("Decapsulate")
                    .shouldBeDetectedAs(new KeyActionFactory<>(KeyAction.Action.DECAPSULATION))
                    .withAnyParameters()
                    .buildForContext(new KeyContext(Map.of("kind", "KEM")))
                    .inBundle(() -> "DotNet")
                    .withoutDependingDetectionRules();

    private static final List<IDetectionRule<CSharpTree>> MLKEM_DEPENDING_RULES =
            List.of(MLKEM_ENCAPSULATE, MLKEM_DECAPSULATE);

    // =========================================================================
    // Primary creation rules — algorithm-parameterized (MLKemAlgorithm argument captured as the
    // parameter set, see class javadoc)
    // =========================================================================

    // MLKem.GenerateKey(MLKemAlgorithm.MLKem768)
    private static final IDetectionRule<CSharpTree> MLKEM_GENERATE_KEY =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes("MLKem")
                    .forMethods("GenerateKey")
                    .shouldBeDetectedAs(new ValueActionFactory<>("ML-KEM"))
                    .withMethodParameter(MethodMatcher.ANY) // MLKemAlgorithm
                    .shouldBeDetectedAs(new ParameterIdentifierFactory<>())
                    .asChildOfParameterWithId(-1)
                    .buildForContext(new KeyContext(Map.of("kind", "KEM")))
                    .inBundle(() -> "DotNet")
                    .withDependingDetectionRules(MLKEM_DEPENDING_RULES);

    // MLKem.ImportDecapsulationKey(MLKemAlgorithm.MLKem768, decapsulationKeyBytes)
    private static final IDetectionRule<CSharpTree> MLKEM_IMPORT_DECAPSULATION_KEY =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes("MLKem")
                    .forMethods("ImportDecapsulationKey")
                    .shouldBeDetectedAs(new ValueActionFactory<>("ML-KEM"))
                    .withMethodParameter(MethodMatcher.ANY) // MLKemAlgorithm
                    .shouldBeDetectedAs(new ParameterIdentifierFactory<>())
                    .asChildOfParameterWithId(-1)
                    .withMethodParameter(MethodMatcher.ANY) // decapsulation key bytes
                    .buildForContext(new KeyContext(Map.of("kind", "KEM")))
                    .inBundle(() -> "DotNet")
                    .withDependingDetectionRules(MLKEM_DEPENDING_RULES);

    // MLKem.ImportEncapsulationKey(MLKemAlgorithm.MLKem768, encapsulationKeyBytes)
    private static final IDetectionRule<CSharpTree> MLKEM_IMPORT_ENCAPSULATION_KEY =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes("MLKem")
                    .forMethods("ImportEncapsulationKey")
                    .shouldBeDetectedAs(new ValueActionFactory<>("ML-KEM"))
                    .withMethodParameter(MethodMatcher.ANY) // MLKemAlgorithm
                    .shouldBeDetectedAs(new ParameterIdentifierFactory<>())
                    .asChildOfParameterWithId(-1)
                    .withMethodParameter(MethodMatcher.ANY) // encapsulation key bytes
                    .buildForContext(new KeyContext(Map.of("kind", "KEM")))
                    .inBundle(() -> "DotNet")
                    .withDependingDetectionRules(MLKEM_DEPENDING_RULES);

    // MLKem.ImportPrivateSeed(MLKemAlgorithm.MLKem768, seedBytes)
    private static final IDetectionRule<CSharpTree> MLKEM_IMPORT_PRIVATE_SEED =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes("MLKem")
                    .forMethods("ImportPrivateSeed")
                    .shouldBeDetectedAs(new ValueActionFactory<>("ML-KEM"))
                    .withMethodParameter(MethodMatcher.ANY) // MLKemAlgorithm
                    .shouldBeDetectedAs(new ParameterIdentifierFactory<>())
                    .asChildOfParameterWithId(-1)
                    .withMethodParameter(MethodMatcher.ANY) // seed bytes
                    .buildForContext(new KeyContext(Map.of("kind", "KEM")))
                    .inBundle(() -> "DotNet")
                    .withDependingDetectionRules(MLKEM_DEPENDING_RULES);

    // =========================================================================
    // Primary creation rules — structural imports (no MLKemAlgorithm argument; see class javadoc
    // for why the parameter set cannot be captured for these)
    // =========================================================================

    // MLKem.ImportPkcs8PrivateKey(source) / MLKem.ImportSubjectPublicKeyInfo(source) /
    // MLKem.ImportFromPem(pem) / MLKem.ImportEncryptedPkcs8PrivateKey(...) /
    // MLKem.ImportFromEncryptedPem(...)
    private static IDetectionRule<CSharpTree> structuralImportRule(@Nonnull String methodName) {
        return new DetectionRuleBuilder<CSharpTree>()
                .createDetectionRule()
                .forObjectTypes("MLKem")
                .forMethods(methodName)
                .shouldBeDetectedAs(new ValueActionFactory<>("ML-KEM"))
                .withAnyParameters()
                .buildForContext(new KeyContext(Map.of("kind", "KEM")))
                .inBundle(() -> "DotNet")
                .withDependingDetectionRules(MLKEM_DEPENDING_RULES);
    }

    private static final IDetectionRule<CSharpTree> MLKEM_IMPORT_PKCS8_PRIVATE_KEY =
            structuralImportRule("ImportPkcs8PrivateKey");

    private static final IDetectionRule<CSharpTree> MLKEM_IMPORT_SUBJECT_PUBLIC_KEY_INFO =
            structuralImportRule("ImportSubjectPublicKeyInfo");

    private static final IDetectionRule<CSharpTree> MLKEM_IMPORT_FROM_PEM =
            structuralImportRule("ImportFromPem");

    private static final IDetectionRule<CSharpTree> MLKEM_IMPORT_ENCRYPTED_PKCS8_PRIVATE_KEY =
            structuralImportRule("ImportEncryptedPkcs8PrivateKey");

    private static final IDetectionRule<CSharpTree> MLKEM_IMPORT_FROM_ENCRYPTED_PEM =
            structuralImportRule("ImportFromEncryptedPem");

    // =========================================================================
    // Primary creation rules — native-interop constructors (no MLKemAlgorithm argument; wrap an
    // already-existing native key handle, mirroring RSACng(CngKey)/RSAOpenSsl(SafeEvpPKeyHandle) in
    // DotNetRSA)
    // =========================================================================

    // new MLKemCng(cngKey)
    private static final IDetectionRule<CSharpTree> MLKEM_CNG =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes("MLKemCng")
                    .forMethods("<init>")
                    .shouldBeDetectedAs(new ValueActionFactory<>("ML-KEM"))
                    .withAnyParameters()
                    .buildForContext(new KeyContext(Map.of("kind", "KEM")))
                    .inBundle(() -> "DotNet")
                    .withDependingDetectionRules(MLKEM_DEPENDING_RULES);

    // new MLKemOpenSsl(safeEvpPKeyHandle)
    private static final IDetectionRule<CSharpTree> MLKEM_OPENSSL =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes("MLKemOpenSsl")
                    .forMethods("<init>")
                    .shouldBeDetectedAs(new ValueActionFactory<>("ML-KEM"))
                    .withAnyParameters()
                    .buildForContext(new KeyContext(Map.of("kind", "KEM")))
                    .inBundle(() -> "DotNet")
                    .withDependingDetectionRules(MLKEM_DEPENDING_RULES);

    @Nonnull
    public static List<IDetectionRule<CSharpTree>> rules() {
        return List.of(
                MLKEM_GENERATE_KEY,
                MLKEM_IMPORT_DECAPSULATION_KEY,
                MLKEM_IMPORT_ENCAPSULATION_KEY,
                MLKEM_IMPORT_PRIVATE_SEED,
                MLKEM_IMPORT_PKCS8_PRIVATE_KEY,
                MLKEM_IMPORT_SUBJECT_PUBLIC_KEY_INFO,
                MLKEM_IMPORT_FROM_PEM,
                MLKEM_IMPORT_ENCRYPTED_PKCS8_PRIVATE_KEY,
                MLKEM_IMPORT_FROM_ENCRYPTED_PEM,
                MLKEM_CNG,
                MLKEM_OPENSSL);
    }
}
