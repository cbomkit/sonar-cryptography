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
import com.ibm.engine.model.Size;
import com.ibm.engine.model.context.KeyContext;
import com.ibm.engine.model.context.SignatureContext;
import com.ibm.engine.model.factory.KeySizeFactory;
import com.ibm.engine.model.factory.SignatureActionFactory;
import com.ibm.engine.model.factory.ValueActionFactory;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import java.util.List;
import java.util.Map;
import javax.annotation.Nonnull;

/**
 * Detection rules for the DSA family in System.Security.Cryptography.
 *
 * <p>Classes covered:
 *
 * <ul>
 *   <li>{@code DSA} — abstract base ({@code DSA.Create()}, {@code DSA.Create(DSAParameters)},
 *       {@code DSA.Create(int)}, {@code DSA.Create(string)})
 *   <li>{@code DSACng} — CNG-backed implementation (ephemeral and persisted-key constructors)
 *   <li>{@code DSACryptoServiceProvider} — legacy CAPI implementation
 *   <li>{@code DSAOpenSsl} — OpenSSL-backed implementation
 * </ul>
 *
 * <p>Architecture: all methods inherited from {@code AsymmetricAlgorithm} / {@code DSA} (KeySize
 * property, CreateSignature, VerifySignature, SignData, VerifyData, Try* variants, etc.), as well
 * as the legacy {@code SignHash}/{@code VerifyHash} methods that exist only on {@code
 * DSACryptoServiceProvider} (not on the abstract {@code DSA} base class; {@code DSA} has no {@code
 * TrySignHash}), are expressed as <em>depending rules</em> attached to each primary creation rule.
 * The detection engine tracks the variable and fires these rules on every matching method call,
 * regardless of the concrete DSA subclass.
 */
@SuppressWarnings("java:S1192")
public final class DotNetDSA {

    private DotNetDSA() {
        // nothing
    }

    // =========================================================================
    // Property setter rules (synthetic set_X method invocations)
    // =========================================================================

    // dsa.KeySize = 2048  →  synthetic set_KeySize(2048)
    private static final IDetectionRule<CSharpTree> DSA_SET_KEY_SIZE =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes(MethodMatcher.ANY)
                    .forMethods("set_KeySize")
                    .withMethodParameter(MethodMatcher.ANY)
                    .shouldBeDetectedAs(new KeySizeFactory<>(Size.UnitType.BIT))
                    .buildForContext(new KeyContext(Map.of("kind", "DSA")))
                    .inBundle(() -> "DotNet")
                    .withoutDependingDetectionRules();

    // =========================================================================
    // Signing / verification operation rules
    // Each covers every overload of the given method name (arities vary only by
    // hash-algorithm / signature-format / offset-length parameters, which are not
    // individually tracked), mirroring the JCA Signature.sign()/verify() rules.
    // =========================================================================

    // dsa.CreateSignature(hash) / dsa.CreateSignature(hash, format)
    private static final IDetectionRule<CSharpTree> DSA_CREATE_SIGNATURE =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes(MethodMatcher.ANY)
                    .forMethods("CreateSignature")
                    .shouldBeDetectedAs(new SignatureActionFactory<>(SignatureAction.Action.SIGN))
                    .withAnyParameters()
                    .buildForContext(new SignatureContext())
                    .inBundle(() -> "DotNet")
                    .withoutDependingDetectionRules();

    // dsa.TryCreateSignature(hash, destination, ...)
    private static final IDetectionRule<CSharpTree> DSA_TRY_CREATE_SIGNATURE =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes(MethodMatcher.ANY)
                    .forMethods("TryCreateSignature")
                    .shouldBeDetectedAs(new SignatureActionFactory<>(SignatureAction.Action.SIGN))
                    .withAnyParameters()
                    .buildForContext(new SignatureContext())
                    .inBundle(() -> "DotNet")
                    .withoutDependingDetectionRules();

    // dsa.SignData(data, hashAlgorithm[, format])
    private static final IDetectionRule<CSharpTree> DSA_SIGN_DATA =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes(MethodMatcher.ANY)
                    .forMethods("SignData")
                    .shouldBeDetectedAs(new SignatureActionFactory<>(SignatureAction.Action.SIGN))
                    .withAnyParameters()
                    .buildForContext(new SignatureContext())
                    .inBundle(() -> "DotNet")
                    .withoutDependingDetectionRules();

    // dsa.TrySignData(data, destination, hashAlgorithm, ...)
    private static final IDetectionRule<CSharpTree> DSA_TRY_SIGN_DATA =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes(MethodMatcher.ANY)
                    .forMethods("TrySignData")
                    .shouldBeDetectedAs(new SignatureActionFactory<>(SignatureAction.Action.SIGN))
                    .withAnyParameters()
                    .buildForContext(new SignatureContext())
                    .inBundle(() -> "DotNet")
                    .withoutDependingDetectionRules();

    // dsa.VerifySignature(hash, signature[, format])
    private static final IDetectionRule<CSharpTree> DSA_VERIFY_SIGNATURE =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes(MethodMatcher.ANY)
                    .forMethods("VerifySignature")
                    .shouldBeDetectedAs(new SignatureActionFactory<>(SignatureAction.Action.VERIFY))
                    .withAnyParameters()
                    .buildForContext(new SignatureContext())
                    .inBundle(() -> "DotNet")
                    .withoutDependingDetectionRules();

    // dsa.VerifyData(data, signature, hashAlgorithm[, format])
    private static final IDetectionRule<CSharpTree> DSA_VERIFY_DATA =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes(MethodMatcher.ANY)
                    .forMethods("VerifyData")
                    .shouldBeDetectedAs(new SignatureActionFactory<>(SignatureAction.Action.VERIFY))
                    .withAnyParameters()
                    .buildForContext(new SignatureContext())
                    .inBundle(() -> "DotNet")
                    .withoutDependingDetectionRules();

    // dsa.SignHash(hash, hashAlgorithmName) — legacy CSP-era method, only real on
    // DSACryptoServiceProvider (not present on the abstract DSA base class), mirroring
    // RSA_SIGN_HASH in DotNetRSA.java. Note that unlike RSA, DSA has no TrySignHash.
    private static final IDetectionRule<CSharpTree> DSA_SIGN_HASH =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes(MethodMatcher.ANY)
                    .forMethods("SignHash")
                    .shouldBeDetectedAs(new SignatureActionFactory<>(SignatureAction.Action.SIGN))
                    .withAnyParameters()
                    .buildForContext(new SignatureContext())
                    .inBundle(() -> "DotNet")
                    .withoutDependingDetectionRules();

    // dsa.VerifyHash(hash, hashAlgorithmName, signature) — legacy CSP-era method, only real
    // on DSACryptoServiceProvider (not present on the abstract DSA base class), mirroring
    // RSA_VERIFY_HASH in DotNetRSA.java.
    private static final IDetectionRule<CSharpTree> DSA_VERIFY_HASH =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes(MethodMatcher.ANY)
                    .forMethods("VerifyHash")
                    .shouldBeDetectedAs(new SignatureActionFactory<>(SignatureAction.Action.VERIFY))
                    .withAnyParameters()
                    .buildForContext(new SignatureContext())
                    .inBundle(() -> "DotNet")
                    .withoutDependingDetectionRules();

    // =========================================================================
    // Aggregated depending-rule list
    // =========================================================================

    /** Full set of depending rules for all DSA-derived classes. */
    private static final List<IDetectionRule<CSharpTree>> DSA_DEPENDING_RULES =
            List.of(
                    DSA_SET_KEY_SIZE,
                    DSA_CREATE_SIGNATURE,
                    DSA_TRY_CREATE_SIGNATURE,
                    DSA_SIGN_DATA,
                    DSA_TRY_SIGN_DATA,
                    DSA_VERIFY_SIGNATURE,
                    DSA_VERIFY_DATA,
                    DSA_SIGN_HASH,
                    DSA_VERIFY_HASH);

    // =========================================================================
    // Primary creation rules
    // =========================================================================

    // DSA.Create() / DSA.Create(DSAParameters) / DSA.Create(int) / DSA.Create(string)
    private static final IDetectionRule<CSharpTree> DSA_CREATE =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes("DSA")
                    .forMethods("Create")
                    .shouldBeDetectedAs(new ValueActionFactory<>("DSA"))
                    .withAnyParameters()
                    .buildForContext(new KeyContext(Map.of("kind", "DSA")))
                    .inBundle(() -> "DotNet")
                    .withDependingDetectionRules(DSA_DEPENDING_RULES);

    // new DSACng() / new DSACng(CngKey) / new DSACng(int) — CNG-backed implementation
    private static final IDetectionRule<CSharpTree> DSA_CNG =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes("DSACng")
                    .forMethods("<init>")
                    .shouldBeDetectedAs(new ValueActionFactory<>("DSA"))
                    .withAnyParameters()
                    .buildForContext(new KeyContext(Map.of("kind", "DSA")))
                    .inBundle(() -> "DotNet")
                    .withDependingDetectionRules(DSA_DEPENDING_RULES);

    // new DSACryptoServiceProvider() / (CspParameters) / (int) / (int, CspParameters)
    private static final IDetectionRule<CSharpTree> DSA_CSP =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes("DSACryptoServiceProvider")
                    .forMethods("<init>")
                    .shouldBeDetectedAs(new ValueActionFactory<>("DSA"))
                    .withAnyParameters()
                    .buildForContext(new KeyContext(Map.of("kind", "DSA")))
                    .inBundle(() -> "DotNet")
                    .withDependingDetectionRules(DSA_DEPENDING_RULES);

    // new DSAOpenSsl() / (DSAParameters) / (int) / (IntPtr) / (SafeEvpPKeyHandle)
    private static final IDetectionRule<CSharpTree> DSA_OPENSSL =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes("DSAOpenSsl")
                    .forMethods("<init>")
                    .shouldBeDetectedAs(new ValueActionFactory<>("DSA"))
                    .withAnyParameters()
                    .buildForContext(new KeyContext(Map.of("kind", "DSA")))
                    .inBundle(() -> "DotNet")
                    .withDependingDetectionRules(DSA_DEPENDING_RULES);

    @Nonnull
    public static List<IDetectionRule<CSharpTree>> rules() {
        return List.of(DSA_CREATE, DSA_CNG, DSA_CSP, DSA_OPENSSL);
    }
}
