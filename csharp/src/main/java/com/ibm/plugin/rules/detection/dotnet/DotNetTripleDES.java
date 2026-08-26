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
 * Detection rules for the Triple DES (3DES) family in System.Security.Cryptography.
 *
 * <p>Classes covered:
 *
 * <ul>
 *   <li>{@code TripleDES} — abstract base ({@code TripleDES.Create()}, {@code
 *       TripleDES.Create(string)})
 *   <li>{@code TripleDESCryptoServiceProvider} — legacy CAPI implementation
 *   <li>{@code TripleDESCng} — CNG-backed implementation (ephemeral and persisted-key constructors)
 * </ul>
 *
 * <p>Architecture: all methods inherited from {@code SymmetricAlgorithm} (EncryptCbc, DecryptCbc,
 * CreateEncryptor, property setters, etc.) are expressed as <em>depending rules</em> attached to
 * each primary creation rule. The detection engine tracks the variable and fires these rules on
 * every matching method call, regardless of the concrete TripleDES subclass. Like {@code Aes},
 * {@code TripleDES} has a CNG-backed subclass ({@code TripleDESCng}), but unlike {@code Aes} it has
 * no AEAD variant, so depending-rule coverage mirrors {@code DotNetDES} and {@code DotNetRC2}
 * exactly (no TripleDES-specific properties exist beyond those inherited from {@code
 * SymmetricAlgorithm}).
 */
@SuppressWarnings("java:S1192")
public final class DotNetTripleDES {

    private DotNetTripleDES() {
        // nothing
    }

    // =========================================================================
    // Property setter rules (synthetic set_X method invocations)
    // =========================================================================

    // tdes.Mode = CipherMode.CBC  →  synthetic set_Mode(CipherMode.CBC)
    private static final IDetectionRule<CSharpTree> TRIPLE_DES_SET_MODE =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes(MethodMatcher.ANY)
                    .forMethods("set_Mode")
                    .withMethodParameter(MethodMatcher.ANY)
                    .shouldBeDetectedAs(new ModeFactory<>())
                    .buildForContext(new CipherContext())
                    .inBundle(() -> "DotNet")
                    .withoutDependingDetectionRules();

    // tdes.KeySize = 192  →  synthetic set_KeySize(192)
    private static final IDetectionRule<CSharpTree> TRIPLE_DES_SET_KEY_SIZE =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes(MethodMatcher.ANY)
                    .forMethods("set_KeySize")
                    .withMethodParameter(MethodMatcher.ANY)
                    .shouldBeDetectedAs(new KeySizeFactory<>(Size.UnitType.BIT))
                    .buildForContext(new CipherContext())
                    .inBundle(() -> "DotNet")
                    .withoutDependingDetectionRules();

    // tdes.Padding = PaddingMode.PKCS7  →  synthetic set_Padding(PaddingMode.PKCS7)
    private static final IDetectionRule<CSharpTree> TRIPLE_DES_SET_PADDING =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes(MethodMatcher.ANY)
                    .forMethods("set_Padding")
                    .withMethodParameter(MethodMatcher.ANY)
                    .shouldBeDetectedAs(new PaddingFactory<>())
                    .buildForContext(new CipherContext())
                    .inBundle(() -> "DotNet")
                    .withoutDependingDetectionRules();

    // tdes.FeedbackSize = 8  →  synthetic set_FeedbackSize(8)
    private static final IDetectionRule<CSharpTree> TRIPLE_DES_SET_FEEDBACK_SIZE =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes(MethodMatcher.ANY)
                    .forMethods("set_FeedbackSize")
                    .withMethodParameter(MethodMatcher.ANY)
                    .shouldBeDetectedAs(new BlockSizeFactory<>(Size.UnitType.BIT))
                    .buildForContext(new CipherContext())
                    .inBundle(() -> "DotNet")
                    .withoutDependingDetectionRules();

    private static final List<IDetectionRule<CSharpTree>> PROPERTY_SETTER_RULES =
            List.of(
                    TRIPLE_DES_SET_MODE,
                    TRIPLE_DES_SET_KEY_SIZE,
                    TRIPLE_DES_SET_PADDING,
                    TRIPLE_DES_SET_FEEDBACK_SIZE);

    // =========================================================================
    // CreateEncryptor / CreateDecryptor rules
    // =========================================================================

    // tdes.CreateEncryptor()
    private static final IDetectionRule<CSharpTree> TRIPLE_DES_CREATE_ENCRYPTOR =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes(MethodMatcher.ANY)
                    .forMethods("CreateEncryptor")
                    .shouldBeDetectedAs(new CipherActionFactory<>(CipherAction.Action.ENCRYPT))
                    .withoutParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> "DotNet")
                    .withoutDependingDetectionRules();

    // tdes.CreateEncryptor(byte[] key, byte[] iv)
    private static final IDetectionRule<CSharpTree> TRIPLE_DES_CREATE_ENCRYPTOR_WITH_KEY =
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

    // tdes.CreateDecryptor()
    private static final IDetectionRule<CSharpTree> TRIPLE_DES_CREATE_DECRYPTOR =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes(MethodMatcher.ANY)
                    .forMethods("CreateDecryptor")
                    .shouldBeDetectedAs(new CipherActionFactory<>(CipherAction.Action.DECRYPT))
                    .withoutParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> "DotNet")
                    .withoutDependingDetectionRules();

    // tdes.CreateDecryptor(byte[] key, byte[] iv)
    private static final IDetectionRule<CSharpTree> TRIPLE_DES_CREATE_DECRYPTOR_WITH_KEY =
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

    // =========================================================================
    // EncryptCbc / DecryptCbc rules
    // Mode is constant "CBC" (from method name); padding is detected from last param.
    // Two overloads: 3-param and 4-param (with output buffer).
    // =========================================================================

    // EncryptCbc(plaintext, iv, padding)
    private static final IDetectionRule<CSharpTree> TRIPLE_DES_ENCRYPT_CBC_3 =
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
    private static final IDetectionRule<CSharpTree> TRIPLE_DES_ENCRYPT_CBC_4 =
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
    private static final IDetectionRule<CSharpTree> TRIPLE_DES_DECRYPT_CBC_3 =
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
    private static final IDetectionRule<CSharpTree> TRIPLE_DES_DECRYPT_CBC_4 =
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

    // =========================================================================
    // EncryptEcb / DecryptEcb rules
    // Mode is constant "ECB" (from method name); no IV parameter.
    // Two overloads: 2-param and 3-param (with output buffer).
    // =========================================================================

    // EncryptEcb(plaintext, padding)
    private static final IDetectionRule<CSharpTree> TRIPLE_DES_ENCRYPT_ECB_2 =
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
    private static final IDetectionRule<CSharpTree> TRIPLE_DES_ENCRYPT_ECB_3 =
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
    private static final IDetectionRule<CSharpTree> TRIPLE_DES_DECRYPT_ECB_2 =
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
    private static final IDetectionRule<CSharpTree> TRIPLE_DES_DECRYPT_ECB_3 =
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

    // =========================================================================
    // EncryptCfb / DecryptCfb rules
    // Mode is constant "CFB"; padding detected from 3rd param; feedbackSize ignored.
    // Two overloads: 4-param and 5-param (with output buffer).
    // =========================================================================

    // EncryptCfb(plaintext, iv, padding, feedbackSize)
    private static final IDetectionRule<CSharpTree> TRIPLE_DES_ENCRYPT_CFB_4 =
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
    private static final IDetectionRule<CSharpTree> TRIPLE_DES_ENCRYPT_CFB_5 =
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
    private static final IDetectionRule<CSharpTree> TRIPLE_DES_DECRYPT_CFB_4 =
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
    private static final IDetectionRule<CSharpTree> TRIPLE_DES_DECRYPT_CFB_5 =
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

    // =========================================================================
    // TryEncrypt* / TryDecrypt* rules
    // Signatures:
    //   TryEncryptCbc(plaintext, iv, destination, out bytesWritten, padding)       — 5 params
    //   TryDecryptCbc(ciphertext, iv, destination, out bytesWritten, padding)      — 5 params
    //   TryEncryptEcb(plaintext, destination, padding, out bytesWritten)           — 4 params
    //   TryDecryptEcb(ciphertext, destination, padding, out bytesWritten)          — 4 params
    //   TryEncryptCfb(plaintext, iv, destination, out bytesWritten, padding, fs)   — 6 params
    //   TryDecryptCfb(ciphertext, iv, destination, out bytesWritten, padding, fs)  — 6 params
    // =========================================================================

    // TryEncryptCbc(plaintext, iv, destination, out bytesWritten, padding)
    private static final IDetectionRule<CSharpTree> TRIPLE_DES_TRY_ENCRYPT_CBC =
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
    private static final IDetectionRule<CSharpTree> TRIPLE_DES_TRY_DECRYPT_CBC =
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
    private static final IDetectionRule<CSharpTree> TRIPLE_DES_TRY_ENCRYPT_ECB =
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
    private static final IDetectionRule<CSharpTree> TRIPLE_DES_TRY_DECRYPT_ECB =
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
    private static final IDetectionRule<CSharpTree> TRIPLE_DES_TRY_ENCRYPT_CFB =
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
    private static final IDetectionRule<CSharpTree> TRIPLE_DES_TRY_DECRYPT_CFB =
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

    // =========================================================================
    // Key / IV generation rules
    // =========================================================================

    // tdes.GenerateKey() — generates a new random key (size determined by KeySize property)
    private static final IDetectionRule<CSharpTree> TRIPLE_DES_GENERATE_KEY =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes(MethodMatcher.ANY)
                    .forMethods("GenerateKey")
                    .shouldBeDetectedAs(new ValueActionFactory<>("GenerateKey"))
                    .withoutParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> "DotNet")
                    .withoutDependingDetectionRules();

    // tdes.GenerateIV() — generates a new random initialization vector
    private static final IDetectionRule<CSharpTree> TRIPLE_DES_GENERATE_IV =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes(MethodMatcher.ANY)
                    .forMethods("GenerateIV")
                    .shouldBeDetectedAs(new ValueActionFactory<>("GenerateIV"))
                    .withoutParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> "DotNet")
                    .withoutDependingDetectionRules();

    // =========================================================================
    // Aggregated depending-rule lists
    // =========================================================================

    /**
     * All cipher operation rules that fire on a tracked TripleDES-family variable. Includes
     * CreateEncryptor/CreateDecryptor, direct mode-specific Encrypt/Decrypt methods, Try* variants,
     * and key/IV generation.
     */
    private static final List<IDetectionRule<CSharpTree>> CIPHER_OP_RULES =
            List.of(
                    TRIPLE_DES_CREATE_ENCRYPTOR,
                    TRIPLE_DES_CREATE_ENCRYPTOR_WITH_KEY,
                    TRIPLE_DES_CREATE_DECRYPTOR,
                    TRIPLE_DES_CREATE_DECRYPTOR_WITH_KEY,
                    TRIPLE_DES_ENCRYPT_CBC_3,
                    TRIPLE_DES_ENCRYPT_CBC_4,
                    TRIPLE_DES_DECRYPT_CBC_3,
                    TRIPLE_DES_DECRYPT_CBC_4,
                    TRIPLE_DES_ENCRYPT_ECB_2,
                    TRIPLE_DES_ENCRYPT_ECB_3,
                    TRIPLE_DES_DECRYPT_ECB_2,
                    TRIPLE_DES_DECRYPT_ECB_3,
                    TRIPLE_DES_ENCRYPT_CFB_4,
                    TRIPLE_DES_ENCRYPT_CFB_5,
                    TRIPLE_DES_DECRYPT_CFB_4,
                    TRIPLE_DES_DECRYPT_CFB_5,
                    TRIPLE_DES_TRY_ENCRYPT_CBC,
                    TRIPLE_DES_TRY_DECRYPT_CBC,
                    TRIPLE_DES_TRY_ENCRYPT_ECB,
                    TRIPLE_DES_TRY_DECRYPT_ECB,
                    TRIPLE_DES_TRY_ENCRYPT_CFB,
                    TRIPLE_DES_TRY_DECRYPT_CFB,
                    TRIPLE_DES_GENERATE_KEY,
                    TRIPLE_DES_GENERATE_IV);

    /** Full set of depending rules for all TripleDES-derived classes. */
    private static final List<IDetectionRule<CSharpTree>> TRIPLE_DES_DEPENDING_RULES =
            Stream.concat(PROPERTY_SETTER_RULES.stream(), CIPHER_OP_RULES.stream()).toList();

    // =========================================================================
    // Primary creation rules
    // =========================================================================

    // TripleDES.Create() — abstract factory, no parameters
    private static final IDetectionRule<CSharpTree> TRIPLE_DES_CREATE =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes("TripleDES")
                    .forMethods("Create")
                    .shouldBeDetectedAs(new ValueActionFactory<>("TRIPLEDES"))
                    .withoutParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> "DotNet")
                    .withDependingDetectionRules(TRIPLE_DES_DEPENDING_RULES);

    // TripleDES.Create("TripleDES") — named factory (obsolete in .NET 7+, still detectable)
    private static final IDetectionRule<CSharpTree> TRIPLE_DES_CREATE_NAMED =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes("TripleDES")
                    .forMethods("Create")
                    .shouldBeDetectedAs(new ValueActionFactory<>("TRIPLEDES"))
                    .withMethodParameter(MethodMatcher.ANY) // algorithm name string
                    .buildForContext(new CipherContext())
                    .inBundle(() -> "DotNet")
                    .withDependingDetectionRules(TRIPLE_DES_DEPENDING_RULES);

    // new TripleDESCryptoServiceProvider() — legacy CAPI implementation
    private static final IDetectionRule<CSharpTree> TRIPLE_DES_CSP =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes("TripleDESCryptoServiceProvider")
                    .forMethods("<init>")
                    .shouldBeDetectedAs(new ValueActionFactory<>("TRIPLEDES"))
                    .withoutParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> "DotNet")
                    .withDependingDetectionRules(TRIPLE_DES_DEPENDING_RULES);

    // new TripleDESCng() / new TripleDESCng("keyName") / new TripleDESCng("keyName", provider) /
    // ...
    // Matches all TripleDESCng constructors (ephemeral 0-param and persisted 1-3 params).
    // Uses withAnyParameters() to avoid double-detection that would occur if a separate
    // withoutParameters() rule were added alongside this one.
    private static final IDetectionRule<CSharpTree> TRIPLE_DES_CNG =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes("TripleDESCng")
                    .forMethods("<init>")
                    .shouldBeDetectedAs(new ValueActionFactory<>("TRIPLEDES"))
                    .withAnyParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> "DotNet")
                    .withDependingDetectionRules(TRIPLE_DES_DEPENDING_RULES);

    @Nonnull
    public static List<IDetectionRule<CSharpTree>> rules() {
        return List.of(TRIPLE_DES_CREATE, TRIPLE_DES_CREATE_NAMED, TRIPLE_DES_CSP, TRIPLE_DES_CNG);
    }
}
