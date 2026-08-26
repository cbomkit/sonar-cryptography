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
import com.ibm.engine.model.Size;
import com.ibm.engine.model.context.CipherContext;
import com.ibm.engine.model.context.DigestContext;
import com.ibm.engine.model.context.KeyContext;
import com.ibm.engine.model.context.MacContext;
import com.ibm.engine.model.factory.AlgorithmFactory;
import com.ibm.engine.model.factory.BlockSizeFactory;
import com.ibm.engine.model.factory.CipherActionFactory;
import com.ibm.engine.model.factory.KeySizeFactory;
import com.ibm.engine.model.factory.ModeFactory;
import com.ibm.engine.model.factory.PaddingFactory;
import com.ibm.engine.model.factory.ValueActionFactory;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import java.util.List;
import java.util.stream.Stream;
import javax.annotation.Nonnull;

/**
 * Detection rules for the generic, string-based factory methods declared directly on the
 * <b>abstract base classes</b> of {@code System.Security.Cryptography} — as opposed to the
 * per-algorithm {@code Create()}/{@code Create(string)} overloads already covered on concrete
 * algorithm classes ({@code RC2.Create(string)} in {@link DotNetRC2}, {@code
 * RandomNumberGenerator.Create(string)} in {@link DotNetRandomNumberGenerator}, etc.), where the
 * class name itself already fixes the algorithm identity and the string parameter only selects an
 * implementation/provider.
 *
 * <p>Here, the base class carries <em>no</em> algorithm identity of its own — the algorithm is
 * chosen entirely at runtime by the string argument:
 *
 * <ul>
 *   <li>{@code SymmetricAlgorithm.Create(string algName)} — e.g. {@code
 *       SymmetricAlgorithm.Create("RC2")}
 *   <li>{@code HashAlgorithm.Create(string hashName)} — e.g. {@code HashAlgorithm.Create("SHA256")}
 *   <li>{@code KeyedHashAlgorithm.Create(string algName)} — e.g. {@code
 *       KeyedHashAlgorithm.Create("HMACSHA256")}
 *   <li>{@code HMAC.Create(string algorithmName)} — e.g. {@code HMAC.Create("HMACSHA256")}
 *   <li>{@code AsymmetricAlgorithm.Create(string algName)} — e.g. {@code
 *       AsymmetricAlgorithm.Create("RSA")}
 * </ul>
 *
 * <p>All five overloads are marked {@code Obsolete} (diagnostic {@code SYSLIB0045}) starting with
 * .NET 7, in favor of the parameterless, strongly-typed {@code Create()} factory on each concrete
 * algorithm type. They remain valid, detectable legacy source across every earlier and current
 * .NET/.NET Framework version — the same "obsolete but in scope" precedent already established for
 * {@code PasswordDeriveBytes} (see {@link DotNetKeyDerivation}) and {@code
 * RandomNumberGenerator.Create(string)}/{@code RNGCryptoServiceProvider} (see {@link
 * DotNetRandomNumberGenerator}).
 *
 * <p><b>Architecture — reusing the engine's existing string-value-to-algorithm resolution mechanism
 * ({@code AlgorithmFactory}):</b> {@code AlgorithmFactory} ({@code
 * com.ibm.engine.model.factory.AlgorithmFactory}) is a generic, language-agnostic engine class
 * (parametrized over {@code <T>}, operating purely on {@code ResolvedValue}) already used
 * identically by the Java module for the structurally identical problem — a call on an abstract
 * base class whose method resolves an algorithm from a runtime string, e.g. {@code
 * MessageDigest.getInstance(String)} ({@code JcaMessageDigestGetInstance}) or {@code
 * Cipher.getInstance(String)} ({@code JcaCipherGetInstance}). No engine change was required: the
 * same {@code .withMethodParameter(type).shouldBeDetectedAs(new AlgorithmFactory<>())} idiom used
 * there is reused here verbatim.
 *
 * <p>Two things confirm this works for C# without any engine modification:
 *
 * <ul>
 *   <li>{@code CSharpTreeConverter} already converts {@code ClassName.Method(args)} call shapes
 *       (its own javadoc cites {@code Aes.Create()}, {@code RSA.Create(2048)} as the pattern it
 *       handles) — {@code SymmetricAlgorithm.Create("RC2")} is exactly this same shape, already
 *       exercised for a literal argument by {@code RSA.Create(2048)} (an {@code int} literal
 *       captured via {@code KeySizeFactory} in {@link DotNetRSA}) and for a string argument (with
 *       no value capture) by {@code RandomNumberGenerator.Create(string)} in {@link
 *       DotNetRandomNumberGenerator}.
 *   <li>{@code CSharpDetectionEngine.resolveValues} resolves a {@code CSharpLiteralTree} (which is
 *       exactly what a string-literal argument becomes, per {@code
 *       CSharpTreeConverter#convertLiteral}) to its raw string value regardless of what class the
 *       enclosing call is invoked on — value resolution is driven purely by the argument
 *       expression, not by the receiver. There is no code path in the C# engine that special-cases
 *       "abstract base class" vs. "concrete class" as a call receiver: {@code
 *       getInvokedObjectTypeString} just compares the receiver text against whatever string {@code
 *       forObjectTypes(...)} was given.
 * </ul>
 *
 * <p><b>Depending rules — deliberately asymmetric across the five factories:</b>
 *
 * <ul>
 *   <li>{@code SymmetricAlgorithm.Create(string)} <em>does</em> attach a depending-rule set ({@code
 *       SYMMETRIC_ALGORITHM_DEPENDING_RULES} below) for post-creation cipher operations ({@code
 *       CreateEncryptor}/{@code CreateDecryptor}, {@code EncryptCbc}/{@code Ecb}/{@code Cfb},
 *       {@code DecryptCbc}/{@code Ecb}/{@code Cfb}, the {@code Try*} variants, {@code
 *       GenerateKey}/{@code GenerateIV}, and the {@code Mode}/{@code KeySize}/{@code Padding}/
 *       {@code FeedbackSize} property setters). Every one of these rules is declared with {@code
 *       forObjectTypes(MethodMatcher.ANY)} — i.e. it fires on method name alone, never on a
 *       concrete receiver class — so it applies unconditionally no matter which concrete algorithm
 *       (AES/DES/RC2/TripleDES) the runtime string actually resolves to at a given call site; there
 *       is no "arbitrary pick" being made. This is a literal, line-for-line duplicate of the
 *       identical {@code PROPERTY_SETTER_RULES}/{@code CIPHER_OP_RULES} pair already defined in
 *       {@link DotNetAES}/{@link DotNetRC2}/{@link DotNetTripleDES}/{@link DotNetDES} (those fields
 *       are private to their own files, and this module's established convention is to duplicate
 *       such per-algorithm depending-rule lists per file rather than centrally share them — see
 *       e.g. {@code DotNetAES}'s own class javadoc), so this follows the same pattern rather than
 *       inventing a new shared abstraction.
 *   <li>{@code HashAlgorithm.Create(string)}, {@code KeyedHashAlgorithm.Create(string)} and {@code
 *       HMAC.Create(string)} intentionally attach <em>no</em> depending rules, consistent with
 *       {@link DotNetSHA}/{@link DotNetHMAC}: a hash/MAC algorithm's cryptographically relevant
 *       information is already fully captured by the algorithm-identity value alone, and operations
 *       such as {@code ComputeHash}/{@code TransformBlock} add nothing to the CBOM model (unlike
 *       Encrypt vs. Decrypt for ciphers). Attaching operation rules here would be inconsistent with
 *       that established, deliberate precedent.
 *   <li>{@code AsymmetricAlgorithm.Create(string)} intentionally attaches <em>no</em> depending
 *       rules either, but for a different, structural reason: verified against the official API
 *       reference
 *       (learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.asymmetricalgorithm),
 *       the {@code AsymmetricAlgorithm} base class itself declares no {@code Sign}/{@code Verify}/
 *       {@code SignData}/{@code VerifyData}/{@code SignHash}/{@code VerifyHash} methods at all —
 *       its "Methods" table only lists key import/export members ({@code ExportPkcs8PrivateKey},
 *       {@code ImportFromPem}, etc.) plus {@code Clear}/{@code Dispose}. Signing/verification is
 *       declared only on the concrete subclasses ({@code RSA}, {@code DSA}, {@code ECDsa} — see
 *       {@link DotNetRSA}/{@link DotNetDSA}/{@link DotNetECDsa} for their own {@code
 *       SignatureActionFactory}-based depending rules), which a rule keyed on the abstract base
 *       class has no way to reach. Unlike the {@code SymmetricAlgorithm} case above, there is no
 *       generic, algorithm-independent operation set to duplicate here.
 * </ul>
 *
 * <p><b>String tables — verified against the official API reference (learn.microsoft.com), not
 * guessed:</b>
 *
 * <ul>
 *   <li>{@code HashAlgorithm.Create(string)}, {@code KeyedHashAlgorithm.Create(string)} and {@code
 *       HMAC.Create(string)} each document an explicit table of accepted {@code hashName}/{@code
 *       algName}/{@code algorithmName} values (including fully-qualified {@code
 *       System.Security.Cryptography.*} forms) — reproduced exactly in {@code
 *       CSharpDigestContextTranslator} and {@code CSharpMacContextTranslator}.
 *   <li>{@code AsymmetricAlgorithm.Create(string)} documents an explicit table covering {@code
 *       RSA}, {@code DSA}, {@code ECDsa}/{@code ECDsaCng}, and {@code ECDH}/{@code
 *       ECDiffieHellman}/{@code ECDiffieHellmanCng} — reproduced in {@code
 *       CSharpKeyContextTranslator}.
 *   <li>{@code SymmetricAlgorithm.Create(string)} is the one exception: unlike its four siblings,
 *       its API reference page does <em>not</em> publish an explicit value table (the underlying
 *       .NET Core implementation only special-cases a handful of names before falling through to
 *       reflection-based {@code CryptoConfig} lookup). {@code CSharpCipherContextTranslator}'s new
 *       branch therefore reuses the same well-known names already accepted elsewhere in that
 *       translator for this codebase's .NET support (AES, DES, 3DES/TripleDES, RC2) rather than
 *       inventing an unverifiable table.
 * </ul>
 */
public final class DotNetAlgorithmFactory {

    private DotNetAlgorithmFactory() {
        // nothing
    }

    // =========================================================================
    // SymmetricAlgorithm.Create(string) depending rules
    //
    // A SymmetricAlgorithm.Create("...") call site is tracked exactly like any other
    // SymmetricAlgorithm-derived variable (Aes/RC2/TripleDES/DES): every method inherited from
    // SymmetricAlgorithm itself (CreateEncryptor/CreateDecryptor, EncryptCbc/Ecb/Cfb,
    // DecryptCbc/Ecb/Cfb, the Try* variants, GenerateKey/GenerateIV, and the Mode/KeySize/
    // Padding/FeedbackSize property setters) is algorithm-independent — it only depends on the
    // method name, never on a concrete class name (forObjectTypes(MethodMatcher.ANY)) — so it
    // applies unconditionally regardless of which concrete algorithm the runtime string resolves
    // to. This is a deliberate, literal duplicate of the identical rule set already defined in
    // DotNetAES/DotNetRC2/DotNetTripleDES/DotNetDES (see their PROPERTY_SETTER_RULES/
    // CIPHER_OP_RULES): those fields are private to their own files, and every existing
    // per-algorithm depending-rule list in this module is duplicated per file rather than
    // centrally shared, so this follows the same established convention instead of inventing a
    // new shared abstraction.
    // =========================================================================

    // alg.Mode = CipherMode.CBC  →  synthetic set_Mode(CipherMode.CBC)
    private static final IDetectionRule<CSharpTree> SYMMETRIC_ALGORITHM_SET_MODE =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes(MethodMatcher.ANY)
                    .forMethods("set_Mode")
                    .withMethodParameter(MethodMatcher.ANY)
                    .shouldBeDetectedAs(new ModeFactory<>())
                    .buildForContext(new CipherContext())
                    .inBundle(() -> "DotNet")
                    .withoutDependingDetectionRules();

    // alg.KeySize = 256  →  synthetic set_KeySize(256)
    private static final IDetectionRule<CSharpTree> SYMMETRIC_ALGORITHM_SET_KEY_SIZE =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes(MethodMatcher.ANY)
                    .forMethods("set_KeySize")
                    .withMethodParameter(MethodMatcher.ANY)
                    .shouldBeDetectedAs(new KeySizeFactory<>(Size.UnitType.BIT))
                    .buildForContext(new CipherContext())
                    .inBundle(() -> "DotNet")
                    .withoutDependingDetectionRules();

    // alg.Padding = PaddingMode.PKCS7  →  synthetic set_Padding(PaddingMode.PKCS7)
    private static final IDetectionRule<CSharpTree> SYMMETRIC_ALGORITHM_SET_PADDING =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes(MethodMatcher.ANY)
                    .forMethods("set_Padding")
                    .withMethodParameter(MethodMatcher.ANY)
                    .shouldBeDetectedAs(new PaddingFactory<>())
                    .buildForContext(new CipherContext())
                    .inBundle(() -> "DotNet")
                    .withoutDependingDetectionRules();

    // alg.FeedbackSize = 128  →  synthetic set_FeedbackSize(128)
    private static final IDetectionRule<CSharpTree> SYMMETRIC_ALGORITHM_SET_FEEDBACK_SIZE =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes(MethodMatcher.ANY)
                    .forMethods("set_FeedbackSize")
                    .withMethodParameter(MethodMatcher.ANY)
                    .shouldBeDetectedAs(new BlockSizeFactory<>(Size.UnitType.BIT))
                    .buildForContext(new CipherContext())
                    .inBundle(() -> "DotNet")
                    .withoutDependingDetectionRules();

    private static final List<IDetectionRule<CSharpTree>>
            SYMMETRIC_ALGORITHM_PROPERTY_SETTER_RULES =
                    List.of(
                            SYMMETRIC_ALGORITHM_SET_MODE,
                            SYMMETRIC_ALGORITHM_SET_KEY_SIZE,
                            SYMMETRIC_ALGORITHM_SET_PADDING,
                            SYMMETRIC_ALGORITHM_SET_FEEDBACK_SIZE);

    // alg.CreateEncryptor()
    private static final IDetectionRule<CSharpTree> SYMMETRIC_ALGORITHM_CREATE_ENCRYPTOR =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes(MethodMatcher.ANY)
                    .forMethods("CreateEncryptor")
                    .shouldBeDetectedAs(new CipherActionFactory<>(CipherAction.Action.ENCRYPT))
                    .withoutParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> "DotNet")
                    .withoutDependingDetectionRules();

    // alg.CreateEncryptor(byte[] key, byte[] iv)
    private static final IDetectionRule<CSharpTree> SYMMETRIC_ALGORITHM_CREATE_ENCRYPTOR_WITH_KEY =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes(MethodMatcher.ANY)
                    .forMethods("CreateEncryptor")
                    .shouldBeDetectedAs(new CipherActionFactory<>(CipherAction.Action.ENCRYPT))
                    .withMethodParameter(MethodMatcher.ANY) // key bytes
                    .withMethodParameter(MethodMatcher.ANY) // iv bytes
                    .buildForContext(new CipherContext())
                    .inBundle(() -> "DotNet")
                    .withoutDependingDetectionRules();

    // alg.CreateDecryptor()
    private static final IDetectionRule<CSharpTree> SYMMETRIC_ALGORITHM_CREATE_DECRYPTOR =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes(MethodMatcher.ANY)
                    .forMethods("CreateDecryptor")
                    .shouldBeDetectedAs(new CipherActionFactory<>(CipherAction.Action.DECRYPT))
                    .withoutParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> "DotNet")
                    .withoutDependingDetectionRules();

    // alg.CreateDecryptor(byte[] key, byte[] iv)
    private static final IDetectionRule<CSharpTree> SYMMETRIC_ALGORITHM_CREATE_DECRYPTOR_WITH_KEY =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes(MethodMatcher.ANY)
                    .forMethods("CreateDecryptor")
                    .shouldBeDetectedAs(new CipherActionFactory<>(CipherAction.Action.DECRYPT))
                    .withMethodParameter(MethodMatcher.ANY) // key bytes
                    .withMethodParameter(MethodMatcher.ANY) // iv bytes
                    .buildForContext(new CipherContext())
                    .inBundle(() -> "DotNet")
                    .withoutDependingDetectionRules();

    // EncryptCbc(plaintext, iv, padding)
    private static final IDetectionRule<CSharpTree> SYMMETRIC_ALGORITHM_ENCRYPT_CBC_3 =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes(MethodMatcher.ANY)
                    .forMethods("EncryptCbc")
                    .withMethodParameter(MethodMatcher.ANY) // plaintext
                    .withMethodParameter(MethodMatcher.ANY) // iv
                    .shouldBeDetectedAs(new ModeFactory<>("CBC"))
                    .withMethodParameter(MethodMatcher.ANY) // padding
                    .shouldBeDetectedAs(new PaddingFactory<>())
                    .buildForContext(new CipherContext())
                    .inBundle(() -> "DotNet")
                    .withoutDependingDetectionRules();

    // EncryptCbc(plaintext, iv, destination, padding)  [output-buffer overload]
    private static final IDetectionRule<CSharpTree> SYMMETRIC_ALGORITHM_ENCRYPT_CBC_4 =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes(MethodMatcher.ANY)
                    .forMethods("EncryptCbc")
                    .withMethodParameter(MethodMatcher.ANY) // plaintext
                    .withMethodParameter(MethodMatcher.ANY) // iv
                    .shouldBeDetectedAs(new ModeFactory<>("CBC"))
                    .withMethodParameter(MethodMatcher.ANY) // destination buffer
                    .withMethodParameter(MethodMatcher.ANY) // padding
                    .shouldBeDetectedAs(new PaddingFactory<>())
                    .buildForContext(new CipherContext())
                    .inBundle(() -> "DotNet")
                    .withoutDependingDetectionRules();

    // DecryptCbc(ciphertext, iv, padding)
    private static final IDetectionRule<CSharpTree> SYMMETRIC_ALGORITHM_DECRYPT_CBC_3 =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes(MethodMatcher.ANY)
                    .forMethods("DecryptCbc")
                    .withMethodParameter(MethodMatcher.ANY) // ciphertext
                    .withMethodParameter(MethodMatcher.ANY) // iv
                    .shouldBeDetectedAs(new ModeFactory<>("CBC"))
                    .withMethodParameter(MethodMatcher.ANY) // padding
                    .shouldBeDetectedAs(new PaddingFactory<>())
                    .buildForContext(new CipherContext())
                    .inBundle(() -> "DotNet")
                    .withoutDependingDetectionRules();

    // DecryptCbc(ciphertext, iv, destination, padding)
    private static final IDetectionRule<CSharpTree> SYMMETRIC_ALGORITHM_DECRYPT_CBC_4 =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes(MethodMatcher.ANY)
                    .forMethods("DecryptCbc")
                    .withMethodParameter(MethodMatcher.ANY) // ciphertext
                    .withMethodParameter(MethodMatcher.ANY) // iv
                    .shouldBeDetectedAs(new ModeFactory<>("CBC"))
                    .withMethodParameter(MethodMatcher.ANY) // destination buffer
                    .withMethodParameter(MethodMatcher.ANY) // padding
                    .shouldBeDetectedAs(new PaddingFactory<>())
                    .buildForContext(new CipherContext())
                    .inBundle(() -> "DotNet")
                    .withoutDependingDetectionRules();

    // EncryptEcb(plaintext, padding)
    private static final IDetectionRule<CSharpTree> SYMMETRIC_ALGORITHM_ENCRYPT_ECB_2 =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes(MethodMatcher.ANY)
                    .forMethods("EncryptEcb")
                    .withMethodParameter(MethodMatcher.ANY) // plaintext
                    .shouldBeDetectedAs(new ModeFactory<>("ECB"))
                    .withMethodParameter(MethodMatcher.ANY) // padding
                    .shouldBeDetectedAs(new PaddingFactory<>())
                    .buildForContext(new CipherContext())
                    .inBundle(() -> "DotNet")
                    .withoutDependingDetectionRules();

    // EncryptEcb(plaintext, destination, padding)
    private static final IDetectionRule<CSharpTree> SYMMETRIC_ALGORITHM_ENCRYPT_ECB_3 =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes(MethodMatcher.ANY)
                    .forMethods("EncryptEcb")
                    .withMethodParameter(MethodMatcher.ANY) // plaintext
                    .shouldBeDetectedAs(new ModeFactory<>("ECB"))
                    .withMethodParameter(MethodMatcher.ANY) // destination buffer
                    .withMethodParameter(MethodMatcher.ANY) // padding
                    .shouldBeDetectedAs(new PaddingFactory<>())
                    .buildForContext(new CipherContext())
                    .inBundle(() -> "DotNet")
                    .withoutDependingDetectionRules();

    // DecryptEcb(ciphertext, padding)
    private static final IDetectionRule<CSharpTree> SYMMETRIC_ALGORITHM_DECRYPT_ECB_2 =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes(MethodMatcher.ANY)
                    .forMethods("DecryptEcb")
                    .withMethodParameter(MethodMatcher.ANY) // ciphertext
                    .shouldBeDetectedAs(new ModeFactory<>("ECB"))
                    .withMethodParameter(MethodMatcher.ANY) // padding
                    .shouldBeDetectedAs(new PaddingFactory<>())
                    .buildForContext(new CipherContext())
                    .inBundle(() -> "DotNet")
                    .withoutDependingDetectionRules();

    // DecryptEcb(ciphertext, destination, padding)
    private static final IDetectionRule<CSharpTree> SYMMETRIC_ALGORITHM_DECRYPT_ECB_3 =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes(MethodMatcher.ANY)
                    .forMethods("DecryptEcb")
                    .withMethodParameter(MethodMatcher.ANY) // ciphertext
                    .shouldBeDetectedAs(new ModeFactory<>("ECB"))
                    .withMethodParameter(MethodMatcher.ANY) // destination buffer
                    .withMethodParameter(MethodMatcher.ANY) // padding
                    .shouldBeDetectedAs(new PaddingFactory<>())
                    .buildForContext(new CipherContext())
                    .inBundle(() -> "DotNet")
                    .withoutDependingDetectionRules();

    // EncryptCfb(plaintext, iv, padding, feedbackSize)
    private static final IDetectionRule<CSharpTree> SYMMETRIC_ALGORITHM_ENCRYPT_CFB_4 =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes(MethodMatcher.ANY)
                    .forMethods("EncryptCfb")
                    .withMethodParameter(MethodMatcher.ANY) // plaintext
                    .withMethodParameter(MethodMatcher.ANY) // iv
                    .shouldBeDetectedAs(new ModeFactory<>("CFB"))
                    .withMethodParameter(MethodMatcher.ANY) // padding
                    .shouldBeDetectedAs(new PaddingFactory<>())
                    .withMethodParameter(MethodMatcher.ANY) // feedbackSize (int)
                    .buildForContext(new CipherContext())
                    .inBundle(() -> "DotNet")
                    .withoutDependingDetectionRules();

    // EncryptCfb(plaintext, iv, destination, padding, feedbackSize)
    private static final IDetectionRule<CSharpTree> SYMMETRIC_ALGORITHM_ENCRYPT_CFB_5 =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes(MethodMatcher.ANY)
                    .forMethods("EncryptCfb")
                    .withMethodParameter(MethodMatcher.ANY) // plaintext
                    .withMethodParameter(MethodMatcher.ANY) // iv
                    .shouldBeDetectedAs(new ModeFactory<>("CFB"))
                    .withMethodParameter(MethodMatcher.ANY) // destination buffer
                    .withMethodParameter(MethodMatcher.ANY) // padding
                    .shouldBeDetectedAs(new PaddingFactory<>())
                    .withMethodParameter(MethodMatcher.ANY) // feedbackSize (int)
                    .buildForContext(new CipherContext())
                    .inBundle(() -> "DotNet")
                    .withoutDependingDetectionRules();

    // DecryptCfb(ciphertext, iv, padding, feedbackSize)
    private static final IDetectionRule<CSharpTree> SYMMETRIC_ALGORITHM_DECRYPT_CFB_4 =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes(MethodMatcher.ANY)
                    .forMethods("DecryptCfb")
                    .withMethodParameter(MethodMatcher.ANY) // ciphertext
                    .withMethodParameter(MethodMatcher.ANY) // iv
                    .shouldBeDetectedAs(new ModeFactory<>("CFB"))
                    .withMethodParameter(MethodMatcher.ANY) // padding
                    .shouldBeDetectedAs(new PaddingFactory<>())
                    .withMethodParameter(MethodMatcher.ANY) // feedbackSize (int)
                    .buildForContext(new CipherContext())
                    .inBundle(() -> "DotNet")
                    .withoutDependingDetectionRules();

    // DecryptCfb(ciphertext, iv, destination, padding, feedbackSize)
    private static final IDetectionRule<CSharpTree> SYMMETRIC_ALGORITHM_DECRYPT_CFB_5 =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes(MethodMatcher.ANY)
                    .forMethods("DecryptCfb")
                    .withMethodParameter(MethodMatcher.ANY) // ciphertext
                    .withMethodParameter(MethodMatcher.ANY) // iv
                    .shouldBeDetectedAs(new ModeFactory<>("CFB"))
                    .withMethodParameter(MethodMatcher.ANY) // destination buffer
                    .withMethodParameter(MethodMatcher.ANY) // padding
                    .shouldBeDetectedAs(new PaddingFactory<>())
                    .withMethodParameter(MethodMatcher.ANY) // feedbackSize (int)
                    .buildForContext(new CipherContext())
                    .inBundle(() -> "DotNet")
                    .withoutDependingDetectionRules();

    // TryEncryptCbc(plaintext, iv, destination, out bytesWritten, padding)
    private static final IDetectionRule<CSharpTree> SYMMETRIC_ALGORITHM_TRY_ENCRYPT_CBC =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes(MethodMatcher.ANY)
                    .forMethods("TryEncryptCbc")
                    .withMethodParameter(MethodMatcher.ANY) // plaintext
                    .withMethodParameter(MethodMatcher.ANY) // iv
                    .shouldBeDetectedAs(new ModeFactory<>("CBC"))
                    .withMethodParameter(MethodMatcher.ANY) // destination
                    .withMethodParameter(MethodMatcher.ANY) // out bytesWritten
                    .withMethodParameter(MethodMatcher.ANY) // padding
                    .shouldBeDetectedAs(new PaddingFactory<>())
                    .buildForContext(new CipherContext())
                    .inBundle(() -> "DotNet")
                    .withoutDependingDetectionRules();

    // TryDecryptCbc(ciphertext, iv, destination, out bytesWritten, padding)
    private static final IDetectionRule<CSharpTree> SYMMETRIC_ALGORITHM_TRY_DECRYPT_CBC =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes(MethodMatcher.ANY)
                    .forMethods("TryDecryptCbc")
                    .withMethodParameter(MethodMatcher.ANY) // ciphertext
                    .withMethodParameter(MethodMatcher.ANY) // iv
                    .shouldBeDetectedAs(new ModeFactory<>("CBC"))
                    .withMethodParameter(MethodMatcher.ANY) // destination
                    .withMethodParameter(MethodMatcher.ANY) // out bytesWritten
                    .withMethodParameter(MethodMatcher.ANY) // padding
                    .shouldBeDetectedAs(new PaddingFactory<>())
                    .buildForContext(new CipherContext())
                    .inBundle(() -> "DotNet")
                    .withoutDependingDetectionRules();

    // TryEncryptEcb(plaintext, destination, padding, out bytesWritten)
    private static final IDetectionRule<CSharpTree> SYMMETRIC_ALGORITHM_TRY_ENCRYPT_ECB =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes(MethodMatcher.ANY)
                    .forMethods("TryEncryptEcb")
                    .withMethodParameter(MethodMatcher.ANY) // plaintext
                    .shouldBeDetectedAs(new ModeFactory<>("ECB"))
                    .withMethodParameter(MethodMatcher.ANY) // destination
                    .withMethodParameter(MethodMatcher.ANY) // padding
                    .shouldBeDetectedAs(new PaddingFactory<>())
                    .withMethodParameter(MethodMatcher.ANY) // out bytesWritten
                    .buildForContext(new CipherContext())
                    .inBundle(() -> "DotNet")
                    .withoutDependingDetectionRules();

    // TryDecryptEcb(ciphertext, destination, padding, out bytesWritten)
    private static final IDetectionRule<CSharpTree> SYMMETRIC_ALGORITHM_TRY_DECRYPT_ECB =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes(MethodMatcher.ANY)
                    .forMethods("TryDecryptEcb")
                    .withMethodParameter(MethodMatcher.ANY) // ciphertext
                    .shouldBeDetectedAs(new ModeFactory<>("ECB"))
                    .withMethodParameter(MethodMatcher.ANY) // destination
                    .withMethodParameter(MethodMatcher.ANY) // padding
                    .shouldBeDetectedAs(new PaddingFactory<>())
                    .withMethodParameter(MethodMatcher.ANY) // out bytesWritten
                    .buildForContext(new CipherContext())
                    .inBundle(() -> "DotNet")
                    .withoutDependingDetectionRules();

    // TryEncryptCfb(plaintext, iv, destination, out bytesWritten, padding, feedbackSize)
    private static final IDetectionRule<CSharpTree> SYMMETRIC_ALGORITHM_TRY_ENCRYPT_CFB =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes(MethodMatcher.ANY)
                    .forMethods("TryEncryptCfb")
                    .withMethodParameter(MethodMatcher.ANY) // plaintext
                    .withMethodParameter(MethodMatcher.ANY) // iv
                    .shouldBeDetectedAs(new ModeFactory<>("CFB"))
                    .withMethodParameter(MethodMatcher.ANY) // destination
                    .withMethodParameter(MethodMatcher.ANY) // out bytesWritten
                    .withMethodParameter(MethodMatcher.ANY) // padding
                    .shouldBeDetectedAs(new PaddingFactory<>())
                    .withMethodParameter(MethodMatcher.ANY) // feedbackSize
                    .buildForContext(new CipherContext())
                    .inBundle(() -> "DotNet")
                    .withoutDependingDetectionRules();

    // TryDecryptCfb(ciphertext, iv, destination, out bytesWritten, padding, feedbackSize)
    private static final IDetectionRule<CSharpTree> SYMMETRIC_ALGORITHM_TRY_DECRYPT_CFB =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes(MethodMatcher.ANY)
                    .forMethods("TryDecryptCfb")
                    .withMethodParameter(MethodMatcher.ANY) // ciphertext
                    .withMethodParameter(MethodMatcher.ANY) // iv
                    .shouldBeDetectedAs(new ModeFactory<>("CFB"))
                    .withMethodParameter(MethodMatcher.ANY) // destination
                    .withMethodParameter(MethodMatcher.ANY) // out bytesWritten
                    .withMethodParameter(MethodMatcher.ANY) // padding
                    .shouldBeDetectedAs(new PaddingFactory<>())
                    .withMethodParameter(MethodMatcher.ANY) // feedbackSize
                    .buildForContext(new CipherContext())
                    .inBundle(() -> "DotNet")
                    .withoutDependingDetectionRules();

    // alg.GenerateKey() — generates a new random key (size determined by KeySize property)
    private static final IDetectionRule<CSharpTree> SYMMETRIC_ALGORITHM_GENERATE_KEY =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes(MethodMatcher.ANY)
                    .forMethods("GenerateKey")
                    .shouldBeDetectedAs(new ValueActionFactory<>("GenerateKey"))
                    .withoutParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> "DotNet")
                    .withoutDependingDetectionRules();

    // alg.GenerateIV() — generates a new random initialization vector
    private static final IDetectionRule<CSharpTree> SYMMETRIC_ALGORITHM_GENERATE_IV =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes(MethodMatcher.ANY)
                    .forMethods("GenerateIV")
                    .shouldBeDetectedAs(new ValueActionFactory<>("GenerateIV"))
                    .withoutParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> "DotNet")
                    .withoutDependingDetectionRules();

    /**
     * All cipher operation rules that fire on a tracked SymmetricAlgorithm-family variable.
     * Includes CreateEncryptor/CreateDecryptor, direct mode-specific Encrypt/Decrypt methods, Try*
     * variants, and key/IV generation. Literal duplicate of the identical list in
     * DotNetAES/DotNetRC2/DotNetTripleDES/DotNetDES (see class javadoc above).
     */
    private static final List<IDetectionRule<CSharpTree>> SYMMETRIC_ALGORITHM_CIPHER_OP_RULES =
            List.of(
                    SYMMETRIC_ALGORITHM_CREATE_ENCRYPTOR,
                    SYMMETRIC_ALGORITHM_CREATE_ENCRYPTOR_WITH_KEY,
                    SYMMETRIC_ALGORITHM_CREATE_DECRYPTOR,
                    SYMMETRIC_ALGORITHM_CREATE_DECRYPTOR_WITH_KEY,
                    SYMMETRIC_ALGORITHM_ENCRYPT_CBC_3,
                    SYMMETRIC_ALGORITHM_ENCRYPT_CBC_4,
                    SYMMETRIC_ALGORITHM_DECRYPT_CBC_3,
                    SYMMETRIC_ALGORITHM_DECRYPT_CBC_4,
                    SYMMETRIC_ALGORITHM_ENCRYPT_ECB_2,
                    SYMMETRIC_ALGORITHM_ENCRYPT_ECB_3,
                    SYMMETRIC_ALGORITHM_DECRYPT_ECB_2,
                    SYMMETRIC_ALGORITHM_DECRYPT_ECB_3,
                    SYMMETRIC_ALGORITHM_ENCRYPT_CFB_4,
                    SYMMETRIC_ALGORITHM_ENCRYPT_CFB_5,
                    SYMMETRIC_ALGORITHM_DECRYPT_CFB_4,
                    SYMMETRIC_ALGORITHM_DECRYPT_CFB_5,
                    SYMMETRIC_ALGORITHM_TRY_ENCRYPT_CBC,
                    SYMMETRIC_ALGORITHM_TRY_DECRYPT_CBC,
                    SYMMETRIC_ALGORITHM_TRY_ENCRYPT_ECB,
                    SYMMETRIC_ALGORITHM_TRY_DECRYPT_ECB,
                    SYMMETRIC_ALGORITHM_TRY_ENCRYPT_CFB,
                    SYMMETRIC_ALGORITHM_TRY_DECRYPT_CFB,
                    SYMMETRIC_ALGORITHM_GENERATE_KEY,
                    SYMMETRIC_ALGORITHM_GENERATE_IV);

    /** Full set of depending rules for the SymmetricAlgorithm.Create(string) factory. */
    private static final List<IDetectionRule<CSharpTree>> SYMMETRIC_ALGORITHM_DEPENDING_RULES =
            Stream.concat(
                            SYMMETRIC_ALGORITHM_PROPERTY_SETTER_RULES.stream(),
                            SYMMETRIC_ALGORITHM_CIPHER_OP_RULES.stream())
                    .toList();

    // SymmetricAlgorithm.Create(string algName) — e.g. SymmetricAlgorithm.Create("RC2")
    private static final IDetectionRule<CSharpTree> SYMMETRIC_ALGORITHM_CREATE =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes("SymmetricAlgorithm")
                    .forMethods("Create")
                    .withMethodParameter(MethodMatcher.ANY)
                    .shouldBeDetectedAs(new AlgorithmFactory<>())
                    .buildForContext(new CipherContext())
                    .inBundle(() -> "DotNet")
                    .withDependingDetectionRules(SYMMETRIC_ALGORITHM_DEPENDING_RULES);

    // HashAlgorithm.Create(string hashName) — e.g. HashAlgorithm.Create("SHA256")
    private static final IDetectionRule<CSharpTree> HASH_ALGORITHM_CREATE =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes("HashAlgorithm")
                    .forMethods("Create")
                    .withMethodParameter(MethodMatcher.ANY)
                    .shouldBeDetectedAs(new AlgorithmFactory<>())
                    .buildForContext(new DigestContext())
                    .inBundle(() -> "DotNet")
                    .withoutDependingDetectionRules();

    // KeyedHashAlgorithm.Create(string algName) — e.g. KeyedHashAlgorithm.Create("HMACSHA256")
    private static final IDetectionRule<CSharpTree> KEYED_HASH_ALGORITHM_CREATE =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes("KeyedHashAlgorithm")
                    .forMethods("Create")
                    .withMethodParameter(MethodMatcher.ANY)
                    .shouldBeDetectedAs(new AlgorithmFactory<>())
                    .buildForContext(new MacContext())
                    .inBundle(() -> "DotNet")
                    .withoutDependingDetectionRules();

    // HMAC.Create(string algorithmName) — e.g. HMAC.Create("HMACSHA256")
    private static final IDetectionRule<CSharpTree> HMAC_CREATE =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes("HMAC")
                    .forMethods("Create")
                    .withMethodParameter(MethodMatcher.ANY)
                    .shouldBeDetectedAs(new AlgorithmFactory<>())
                    .buildForContext(new MacContext())
                    .inBundle(() -> "DotNet")
                    .withoutDependingDetectionRules();

    // AsymmetricAlgorithm.Create(string algName) — e.g. AsymmetricAlgorithm.Create("RSA")
    // No fixed "kind" property: CSharpKeyContextTranslator's new Algorithm-typed branch resolves
    // the concrete algorithm (RSA/DSA/ECDSA/ECDH) purely from the captured string value.
    private static final IDetectionRule<CSharpTree> ASYMMETRIC_ALGORITHM_CREATE =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes("AsymmetricAlgorithm")
                    .forMethods("Create")
                    .withMethodParameter(MethodMatcher.ANY)
                    .shouldBeDetectedAs(new AlgorithmFactory<>())
                    .buildForContext(new KeyContext())
                    .inBundle(() -> "DotNet")
                    .withoutDependingDetectionRules();

    @Nonnull
    public static List<IDetectionRule<CSharpTree>> rules() {
        return List.of(
                SYMMETRIC_ALGORITHM_CREATE,
                HASH_ALGORITHM_CREATE,
                KEYED_HASH_ALGORITHM_CREATE,
                HMAC_CREATE,
                ASYMMETRIC_ALGORITHM_CREATE);
    }
}
