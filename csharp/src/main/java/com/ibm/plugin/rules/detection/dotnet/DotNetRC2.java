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
 * Detection rules for RC2 usage in System.Security.Cryptography.
 *
 * <p>Classes covered:
 *
 * <ul>
 *   <li>{@code RC2} — abstract base ({@code RC2.Create()}, {@code RC2.Create(string)})
 *   <li>{@code RC2CryptoServiceProvider} — legacy CAPI implementation
 * </ul>
 *
 * <p>Architecture: all methods inherited from {@code SymmetricAlgorithm} (EncryptCbc, DecryptCbc,
 * CreateEncryptor, property setters, etc.) are expressed as <em>depending rules</em> attached to
 * each primary creation rule. The detection engine tracks the variable and fires these rules on
 * every matching method call, regardless of the concrete RC2 subclass. Like {@code DES}, {@code
 * RC2} has no CNG-backed subclass and no AEAD variant, so it mirrors {@code DotNetDES}'s
 * depending-rule coverage, with one addition: RC2's own {@code EffectiveKeySize} property.
 *
 * <p>Known gap: {@code RC2CryptoServiceProvider.UseSalt} (a CAPI-only boolean flag controlling
 * whether an 11-byte zero-value salt is appended when deriving a key) has no corresponding concept
 * in the detection model (no boolean/flag value factory exists, and it does not map to a CBOM
 * property such as mode, padding or key/block size). It is therefore intentionally left undetected.
 * // TODO: RC2CryptoServiceProvider.UseSalt is not detected as a known gap.
 */
@SuppressWarnings("java:S1192")
public final class DotNetRC2 {

    private DotNetRC2() {
        // nothing
    }

    // =========================================================================
    // Property setter rules (synthetic set_X method invocations)
    // =========================================================================

    // rc2.Mode = CipherMode.CBC  →  synthetic set_Mode(CipherMode.CBC)
    private static final IDetectionRule<CSharpTree> RC2_SET_MODE =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes(MethodMatcher.ANY)
                    .forMethods("set_Mode")
                    .withMethodParameter(MethodMatcher.ANY)
                    .shouldBeDetectedAs(new ModeFactory<>())
                    .buildForContext(new CipherContext())
                    .inBundle(() -> "DotNet")
                    .withoutDependingDetectionRules();

    // rc2.KeySize = 128  →  synthetic set_KeySize(128)
    private static final IDetectionRule<CSharpTree> RC2_SET_KEY_SIZE =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes(MethodMatcher.ANY)
                    .forMethods("set_KeySize")
                    .withMethodParameter(MethodMatcher.ANY)
                    .shouldBeDetectedAs(new KeySizeFactory<>(Size.UnitType.BIT))
                    .buildForContext(new CipherContext())
                    .inBundle(() -> "DotNet")
                    .withoutDependingDetectionRules();

    // rc2.EffectiveKeySize = 64  →  synthetic set_EffectiveKeySize(64)
    // RC2-specific property (not present on SymmetricAlgorithm nor on Aes/DES). Semantically it
    // constrains the effective cryptographic strength of the key in bits, so it is reused as a
    // KeySize detection (same as set_KeySize above) rather than introducing a dedicated factory.
    private static final IDetectionRule<CSharpTree> RC2_SET_EFFECTIVE_KEY_SIZE =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes(MethodMatcher.ANY)
                    .forMethods("set_EffectiveKeySize")
                    .withMethodParameter(MethodMatcher.ANY)
                    .shouldBeDetectedAs(new KeySizeFactory<>(Size.UnitType.BIT))
                    .buildForContext(new CipherContext())
                    .inBundle(() -> "DotNet")
                    .withoutDependingDetectionRules();

    // rc2.Padding = PaddingMode.PKCS7  →  synthetic set_Padding(PaddingMode.PKCS7)
    private static final IDetectionRule<CSharpTree> RC2_SET_PADDING =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes(MethodMatcher.ANY)
                    .forMethods("set_Padding")
                    .withMethodParameter(MethodMatcher.ANY)
                    .shouldBeDetectedAs(new PaddingFactory<>())
                    .buildForContext(new CipherContext())
                    .inBundle(() -> "DotNet")
                    .withoutDependingDetectionRules();

    // rc2.FeedbackSize = 8  →  synthetic set_FeedbackSize(8)
    private static final IDetectionRule<CSharpTree> RC2_SET_FEEDBACK_SIZE =
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
                    RC2_SET_MODE,
                    RC2_SET_KEY_SIZE,
                    RC2_SET_EFFECTIVE_KEY_SIZE,
                    RC2_SET_PADDING,
                    RC2_SET_FEEDBACK_SIZE);

    // =========================================================================
    // CreateEncryptor / CreateDecryptor rules
    // =========================================================================

    // rc2.CreateEncryptor()
    private static final IDetectionRule<CSharpTree> RC2_CREATE_ENCRYPTOR =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes(MethodMatcher.ANY)
                    .forMethods("CreateEncryptor")
                    .shouldBeDetectedAs(new CipherActionFactory<>(CipherAction.Action.ENCRYPT))
                    .withoutParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> "DotNet")
                    .withoutDependingDetectionRules();

    // rc2.CreateEncryptor(byte[] key, byte[] iv)
    private static final IDetectionRule<CSharpTree> RC2_CREATE_ENCRYPTOR_WITH_KEY =
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

    // rc2.CreateDecryptor()
    private static final IDetectionRule<CSharpTree> RC2_CREATE_DECRYPTOR =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes(MethodMatcher.ANY)
                    .forMethods("CreateDecryptor")
                    .shouldBeDetectedAs(new CipherActionFactory<>(CipherAction.Action.DECRYPT))
                    .withoutParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> "DotNet")
                    .withoutDependingDetectionRules();

    // rc2.CreateDecryptor(byte[] key, byte[] iv)
    private static final IDetectionRule<CSharpTree> RC2_CREATE_DECRYPTOR_WITH_KEY =
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
    private static final IDetectionRule<CSharpTree> RC2_ENCRYPT_CBC_3 =
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
    private static final IDetectionRule<CSharpTree> RC2_ENCRYPT_CBC_4 =
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
    private static final IDetectionRule<CSharpTree> RC2_DECRYPT_CBC_3 =
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
    private static final IDetectionRule<CSharpTree> RC2_DECRYPT_CBC_4 =
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
    private static final IDetectionRule<CSharpTree> RC2_ENCRYPT_ECB_2 =
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
    private static final IDetectionRule<CSharpTree> RC2_ENCRYPT_ECB_3 =
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
    private static final IDetectionRule<CSharpTree> RC2_DECRYPT_ECB_2 =
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
    private static final IDetectionRule<CSharpTree> RC2_DECRYPT_ECB_3 =
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
    private static final IDetectionRule<CSharpTree> RC2_ENCRYPT_CFB_4 =
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
    private static final IDetectionRule<CSharpTree> RC2_ENCRYPT_CFB_5 =
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
    private static final IDetectionRule<CSharpTree> RC2_DECRYPT_CFB_4 =
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
    private static final IDetectionRule<CSharpTree> RC2_DECRYPT_CFB_5 =
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
    private static final IDetectionRule<CSharpTree> RC2_TRY_ENCRYPT_CBC =
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
    private static final IDetectionRule<CSharpTree> RC2_TRY_DECRYPT_CBC =
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
    private static final IDetectionRule<CSharpTree> RC2_TRY_ENCRYPT_ECB =
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
    private static final IDetectionRule<CSharpTree> RC2_TRY_DECRYPT_ECB =
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
    private static final IDetectionRule<CSharpTree> RC2_TRY_ENCRYPT_CFB =
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
    private static final IDetectionRule<CSharpTree> RC2_TRY_DECRYPT_CFB =
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

    // rc2.GenerateKey() — generates a new random key (size determined by KeySize property)
    private static final IDetectionRule<CSharpTree> RC2_GENERATE_KEY =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes(MethodMatcher.ANY)
                    .forMethods("GenerateKey")
                    .shouldBeDetectedAs(new ValueActionFactory<>("GenerateKey"))
                    .withoutParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> "DotNet")
                    .withoutDependingDetectionRules();

    // rc2.GenerateIV() — generates a new random initialization vector
    private static final IDetectionRule<CSharpTree> RC2_GENERATE_IV =
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
     * All cipher operation rules that fire on a tracked RC2-family variable. Includes
     * CreateEncryptor/CreateDecryptor, direct mode-specific Encrypt/Decrypt methods, Try* variants,
     * and key/IV generation.
     */
    private static final List<IDetectionRule<CSharpTree>> CIPHER_OP_RULES =
            List.of(
                    RC2_CREATE_ENCRYPTOR,
                    RC2_CREATE_ENCRYPTOR_WITH_KEY,
                    RC2_CREATE_DECRYPTOR,
                    RC2_CREATE_DECRYPTOR_WITH_KEY,
                    RC2_ENCRYPT_CBC_3,
                    RC2_ENCRYPT_CBC_4,
                    RC2_DECRYPT_CBC_3,
                    RC2_DECRYPT_CBC_4,
                    RC2_ENCRYPT_ECB_2,
                    RC2_ENCRYPT_ECB_3,
                    RC2_DECRYPT_ECB_2,
                    RC2_DECRYPT_ECB_3,
                    RC2_ENCRYPT_CFB_4,
                    RC2_ENCRYPT_CFB_5,
                    RC2_DECRYPT_CFB_4,
                    RC2_DECRYPT_CFB_5,
                    RC2_TRY_ENCRYPT_CBC,
                    RC2_TRY_DECRYPT_CBC,
                    RC2_TRY_ENCRYPT_ECB,
                    RC2_TRY_DECRYPT_ECB,
                    RC2_TRY_ENCRYPT_CFB,
                    RC2_TRY_DECRYPT_CFB,
                    RC2_GENERATE_KEY,
                    RC2_GENERATE_IV);

    /** Full set of depending rules for all RC2-derived classes. */
    private static final List<IDetectionRule<CSharpTree>> RC2_DEPENDING_RULES =
            Stream.concat(PROPERTY_SETTER_RULES.stream(), CIPHER_OP_RULES.stream()).toList();

    // =========================================================================
    // Primary creation rules
    // =========================================================================

    // RC2.Create() — abstract factory, no parameters
    private static final IDetectionRule<CSharpTree> RC2_CREATE =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes("RC2")
                    .forMethods("Create")
                    .shouldBeDetectedAs(new ValueActionFactory<>("RC2"))
                    .withoutParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> "DotNet")
                    .withDependingDetectionRules(RC2_DEPENDING_RULES);

    // RC2.Create("RC2") — named factory (obsolete, still detectable)
    private static final IDetectionRule<CSharpTree> RC2_CREATE_NAMED =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes("RC2")
                    .forMethods("Create")
                    .shouldBeDetectedAs(new ValueActionFactory<>("RC2"))
                    .withMethodParameter(MethodMatcher.ANY) // algorithm name string
                    .buildForContext(new CipherContext())
                    .inBundle(() -> "DotNet")
                    .withDependingDetectionRules(RC2_DEPENDING_RULES);

    // new RC2CryptoServiceProvider() — legacy CAPI implementation
    private static final IDetectionRule<CSharpTree> RC2_CSP =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes("RC2CryptoServiceProvider")
                    .forMethods("<init>")
                    .shouldBeDetectedAs(new ValueActionFactory<>("RC2"))
                    .withoutParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> "DotNet")
                    .withDependingDetectionRules(RC2_DEPENDING_RULES);

    @Nonnull
    public static List<IDetectionRule<CSharpTree>> rules() {
        return List.of(RC2_CREATE, RC2_CREATE_NAMED, RC2_CSP);
    }
}
