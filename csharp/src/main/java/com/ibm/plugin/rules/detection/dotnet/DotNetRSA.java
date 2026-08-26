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
import com.ibm.engine.model.Size;
import com.ibm.engine.model.context.CipherContext;
import com.ibm.engine.model.context.KeyContext;
import com.ibm.engine.model.context.SignatureContext;
import com.ibm.engine.model.factory.CipherActionFactory;
import com.ibm.engine.model.factory.KeySizeFactory;
import com.ibm.engine.model.factory.SignatureActionFactory;
import com.ibm.engine.model.factory.ValueActionFactory;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;
import javax.annotation.Nonnull;

/**
 * Detection rules for RSA usage in System.Security.Cryptography.
 *
 * <p>Classes covered:
 *
 * <ul>
 *   <li>{@code RSA} — abstract base ({@code RSA.Create()}, {@code RSA.Create(int)}, {@code
 *       RSA.Create(RSAParameters)}, {@code RSA.Create(string)})
 *   <li>{@code RSACryptoServiceProvider} — legacy CAPI implementation
 *   <li>{@code RSACng} — CNG-backed implementation, Windows-only (ephemeral and persisted-key
 *       constructors)
 *   <li>{@code RSAOpenSsl} — OpenSSL-backed implementation, non-Windows only
 * </ul>
 *
 * <p>Architecture: all members inherited from {@code RSA} / {@code AsymmetricAlgorithm} (the {@code
 * KeySize} property, {@code Encrypt}/{@code Decrypt}, {@code SignData}/{@code VerifyData}, {@code
 * SignHash}/{@code VerifyHash}, and their {@code Try*} variants) are expressed as <em>depending
 * rules</em> attached to each primary creation rule. The detection engine tracks the variable and
 * fires these rules on every matching method call, regardless of the concrete RSA subclass. Method
 * overloads that only differ by array-vs-{@code Span}, offset/length, or output-buffer parameters
 * are intentionally collapsed into a single {@code withAnyParameters()} rule per method name: the
 * ANTLR4-based C# engine cannot resolve parameter types (see {@code CSharpLanguageTranslation}), so
 * distinguishing overloads by parameter type is not possible, and none of the extra parameters
 * carry additional cryptographic information worth extracting.
 */
@SuppressWarnings("java:S1192")
public final class DotNetRSA {

    private DotNetRSA() {
        // nothing
    }

    // =========================================================================
    // Property setter rules (synthetic set_X method invocations)
    // =========================================================================

    // rsa.KeySize = 2048  →  synthetic set_KeySize(2048)
    private static final IDetectionRule<CSharpTree> RSA_SET_KEY_SIZE =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes(MethodMatcher.ANY)
                    .forMethods("set_KeySize")
                    .withMethodParameter(MethodMatcher.ANY)
                    .shouldBeDetectedAs(new KeySizeFactory<>(Size.UnitType.BIT))
                    .buildForContext(new KeyContext(Map.of("kind", "RSA")))
                    .inBundle(() -> "DotNet")
                    .withoutDependingDetectionRules();

    // =========================================================================
    // Encryption / decryption operation rules (RSA used as a public-key cipher)
    // Each rule covers every overload of the given method name (arities vary only
    // by array-vs-Span / output-buffer parameters, which are not individually
    // tracked), mirroring the AES direct Encrypt/Decrypt rules.
    // =========================================================================

    // rsa.Encrypt(data, padding) / rsa.Encrypt(data, destination, padding)
    private static final IDetectionRule<CSharpTree> RSA_ENCRYPT =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes(MethodMatcher.ANY)
                    .forMethods("Encrypt")
                    .shouldBeDetectedAs(new CipherActionFactory<>(CipherAction.Action.ENCRYPT))
                    .withAnyParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> "DotNet")
                    .withoutDependingDetectionRules();

    // rsa.Decrypt(data, padding) / rsa.Decrypt(data, destination, padding)
    private static final IDetectionRule<CSharpTree> RSA_DECRYPT =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes(MethodMatcher.ANY)
                    .forMethods("Decrypt")
                    .shouldBeDetectedAs(new CipherActionFactory<>(CipherAction.Action.DECRYPT))
                    .withAnyParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> "DotNet")
                    .withoutDependingDetectionRules();

    // rsa.TryEncrypt(data, destination, padding, out bytesWritten)
    private static final IDetectionRule<CSharpTree> RSA_TRY_ENCRYPT =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes(MethodMatcher.ANY)
                    .forMethods("TryEncrypt")
                    .shouldBeDetectedAs(new CipherActionFactory<>(CipherAction.Action.ENCRYPT))
                    .withAnyParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> "DotNet")
                    .withoutDependingDetectionRules();

    // rsa.TryDecrypt(data, destination, padding, out bytesWritten)
    private static final IDetectionRule<CSharpTree> RSA_TRY_DECRYPT =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes(MethodMatcher.ANY)
                    .forMethods("TryDecrypt")
                    .shouldBeDetectedAs(new CipherActionFactory<>(CipherAction.Action.DECRYPT))
                    .withAnyParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> "DotNet")
                    .withoutDependingDetectionRules();

    private static final List<IDetectionRule<CSharpTree>> CIPHER_OP_RULES =
            List.of(RSA_ENCRYPT, RSA_DECRYPT, RSA_TRY_ENCRYPT, RSA_TRY_DECRYPT);

    // =========================================================================
    // Signing / verification operation rules
    // Each rule covers every overload of the given method name (arities vary only
    // by hash-algorithm / signature-padding / offset-length / output-buffer
    // parameters, which are not individually tracked), mirroring the DSA
    // SignData()/VerifyData() rules. Note that RSA has no TryVerifyData/
    // TryVerifyHash methods (verification returns a bool directly, so there is no
    // output buffer to size).
    // =========================================================================

    // rsa.SignData(data, hashAlgorithm, padding) [+ offset/length or Stream overloads]
    private static final IDetectionRule<CSharpTree> RSA_SIGN_DATA =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes(MethodMatcher.ANY)
                    .forMethods("SignData")
                    .shouldBeDetectedAs(new SignatureActionFactory<>(SignatureAction.Action.SIGN))
                    .withAnyParameters()
                    .buildForContext(new SignatureContext())
                    .inBundle(() -> "DotNet")
                    .withoutDependingDetectionRules();

    // rsa.TrySignData(data, destination, hashAlgorithm, padding, out bytesWritten)
    private static final IDetectionRule<CSharpTree> RSA_TRY_SIGN_DATA =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes(MethodMatcher.ANY)
                    .forMethods("TrySignData")
                    .shouldBeDetectedAs(new SignatureActionFactory<>(SignatureAction.Action.SIGN))
                    .withAnyParameters()
                    .buildForContext(new SignatureContext())
                    .inBundle(() -> "DotNet")
                    .withoutDependingDetectionRules();

    // rsa.SignHash(hash, hashAlgorithm, padding)
    private static final IDetectionRule<CSharpTree> RSA_SIGN_HASH =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes(MethodMatcher.ANY)
                    .forMethods("SignHash")
                    .shouldBeDetectedAs(new SignatureActionFactory<>(SignatureAction.Action.SIGN))
                    .withAnyParameters()
                    .buildForContext(new SignatureContext())
                    .inBundle(() -> "DotNet")
                    .withoutDependingDetectionRules();

    // rsa.TrySignHash(hash, destination, hashAlgorithm, padding, out bytesWritten)
    private static final IDetectionRule<CSharpTree> RSA_TRY_SIGN_HASH =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes(MethodMatcher.ANY)
                    .forMethods("TrySignHash")
                    .shouldBeDetectedAs(new SignatureActionFactory<>(SignatureAction.Action.SIGN))
                    .withAnyParameters()
                    .buildForContext(new SignatureContext())
                    .inBundle(() -> "DotNet")
                    .withoutDependingDetectionRules();

    // rsa.VerifyData(data, signature, hashAlgorithm, padding) [+ offset/length or Stream overloads]
    private static final IDetectionRule<CSharpTree> RSA_VERIFY_DATA =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes(MethodMatcher.ANY)
                    .forMethods("VerifyData")
                    .shouldBeDetectedAs(new SignatureActionFactory<>(SignatureAction.Action.VERIFY))
                    .withAnyParameters()
                    .buildForContext(new SignatureContext())
                    .inBundle(() -> "DotNet")
                    .withoutDependingDetectionRules();

    // rsa.VerifyHash(hash, signature, hashAlgorithm, padding)
    private static final IDetectionRule<CSharpTree> RSA_VERIFY_HASH =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes(MethodMatcher.ANY)
                    .forMethods("VerifyHash")
                    .shouldBeDetectedAs(new SignatureActionFactory<>(SignatureAction.Action.VERIFY))
                    .withAnyParameters()
                    .buildForContext(new SignatureContext())
                    .inBundle(() -> "DotNet")
                    .withoutDependingDetectionRules();

    private static final List<IDetectionRule<CSharpTree>> SIGNATURE_OP_RULES =
            List.of(
                    RSA_SIGN_DATA,
                    RSA_TRY_SIGN_DATA,
                    RSA_SIGN_HASH,
                    RSA_TRY_SIGN_HASH,
                    RSA_VERIFY_DATA,
                    RSA_VERIFY_HASH);

    // =========================================================================
    // Aggregated depending-rule list
    // =========================================================================

    /** Full set of depending rules for all RSA-derived classes. */
    private static final List<IDetectionRule<CSharpTree>> RSA_DEPENDING_RULES =
            Stream.of(
                            Stream.of(RSA_SET_KEY_SIZE),
                            CIPHER_OP_RULES.stream(),
                            SIGNATURE_OP_RULES.stream())
                    .flatMap(i -> i)
                    .toList();

    // =========================================================================
    // Primary creation rules
    // =========================================================================

    // RSA.Create() / RSA.Create(int) / RSA.Create(RSAParameters) / RSA.Create(string)
    private static final IDetectionRule<CSharpTree> RSA_CREATE =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes("RSA")
                    .forMethods("Create")
                    .shouldBeDetectedAs(new ValueActionFactory<>("RSA"))
                    .withAnyParameters()
                    .buildForContext(new KeyContext(Map.of("kind", "RSA")))
                    .inBundle(() -> "DotNet")
                    .withDependingDetectionRules(RSA_DEPENDING_RULES);

    // new RSACryptoServiceProvider() / (int) / (CspParameters) / (int, CspParameters)
    private static final IDetectionRule<CSharpTree> RSA_CRYPTO_SERVICE_PROVIDER =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes("RSACryptoServiceProvider")
                    .forMethods("<init>")
                    .shouldBeDetectedAs(new ValueActionFactory<>("RSA"))
                    .withAnyParameters()
                    .buildForContext(new KeyContext(Map.of("kind", "RSA")))
                    .inBundle(() -> "DotNet")
                    .withDependingDetectionRules(RSA_DEPENDING_RULES);

    // new RSACng() / new RSACng(CngKey) / new RSACng(int) — CNG-backed implementation.
    // Uses withAnyParameters() to avoid double-detection that would occur if a separate
    // withoutParameters() rule were added alongside this one (see AES_CNG_NAMED).
    private static final IDetectionRule<CSharpTree> RSA_CNG =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes("RSACng")
                    .forMethods("<init>")
                    .shouldBeDetectedAs(new ValueActionFactory<>("RSA"))
                    .withAnyParameters()
                    .buildForContext(new KeyContext(Map.of("kind", "RSA")))
                    .inBundle(() -> "DotNet")
                    .withDependingDetectionRules(RSA_DEPENDING_RULES);

    // new RSAOpenSsl() / (int) / (IntPtr) / (RSAParameters) / (SafeEvpPKeyHandle)
    private static final IDetectionRule<CSharpTree> RSA_OPENSSL =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes("RSAOpenSsl")
                    .forMethods("<init>")
                    .shouldBeDetectedAs(new ValueActionFactory<>("RSA"))
                    .withAnyParameters()
                    .buildForContext(new KeyContext(Map.of("kind", "RSA")))
                    .inBundle(() -> "DotNet")
                    .withDependingDetectionRules(RSA_DEPENDING_RULES);

    @Nonnull
    public static List<IDetectionRule<CSharpTree>> rules() {
        return List.of(RSA_CREATE, RSA_CRYPTO_SERVICE_PROVIDER, RSA_CNG, RSA_OPENSSL);
    }
}
