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
import com.ibm.engine.model.factory.AlgorithmFactory;
import com.ibm.engine.model.factory.KeySizeFactory;
import com.ibm.engine.model.factory.SignatureActionFactory;
import com.ibm.engine.model.factory.ValueActionFactory;
import com.ibm.engine.rule.DetectionRuleSet;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.RuleSets;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import com.ibm.plugin.rules.detection.dotnet.factory.DotNetEcKeySizeOrCurveFactory;
import java.util.List;
import java.util.Map;
import javax.annotation.Nonnull;

/**
 * Detection rules for ECDSA usage in System.Security.Cryptography.
 *
 * <p>Classes covered:
 *
 * <ul>
 *   <li>{@code ECDsa} — abstract base ({@code ECDsa.Create()}, {@code ECDsa.Create(ECCurve)},
 *       {@code ECDsa.Create(ECParameters)}, {@code ECDsa.Create(string)})
 *   <li>{@code ECDsaCng} — CNG-backed implementation, Windows-only ({@code ECDsaCng()}, {@code
 *       ECDsaCng(CngKey)}, {@code ECDsaCng(ECCurve)}, {@code ECDsaCng(int)})
 *   <li>{@code ECDsaOpenSsl} — OpenSSL-backed implementation, non-Windows only
 * </ul>
 *
 * <p>Architecture: all members inherited from {@code ECDsa} / {@code AsymmetricAlgorithm} (the
 * {@code KeySize} property, {@code SignData}/{@code VerifyData}, {@code SignHash}/{@code
 * VerifyHash}, and their {@code Try*} variants) are expressed as <em>depending rules</em> attached
 * to each primary creation rule. The detection engine tracks the variable and fires these rules on
 * every matching method call, regardless of the concrete ECDsa subclass.
 *
 * <p>Each method is covered by one rule whose parameters are declared by their .NET names, so that
 * rule accepts every overload of the method and no call can be detected twice (see {@code
 * CSharpNamedArgumentBinder}). Two things are captured. The single argument of the creation calls
 * is read by value, because .NET puts an {@code int} key size, an {@code ECCurve}, an {@code
 * ECParameters}, a {@code string} provider name and a {@code CngKey} in that one position; see
 * {@code DotNetEcKeySizeOrCurveFactory}. And the {@code HashAlgorithmName} of a signing call is
 * attached to the sign or verify action, found by declared type rather than by position, because
 * the overloads move it between index one and index four.
 *
 * <p>{@code SignHash}, {@code TrySignHash} and {@code VerifyHash} take an already-computed hash and
 * name no algorithm, so they carry no digest. The overloads that differ only by array against
 * {@code Span}, by offset and length, or by an output buffer need no distinction: those positions
 * hold no cryptographic information beyond what is already captured.
 *
 * <p>Unlike RSA, ECDSA has no encrypt/decrypt operations — it is signature-only. Per the {@code
 * ECDsa} API reference, there are no {@code TryVerifyData}/{@code TryVerifyHash} methods
 * (verification returns a bool directly, so there is no output buffer to size), mirroring RSA.
 */
@SuppressWarnings("java:S1192")
public final class DotNetECDsa extends DetectionRuleSet<CSharpTree> {

    // =========================================================================
    // Property setter rules (synthetic set_X method invocations)
    // =========================================================================

    // ecdsa.KeySize = 256  →  synthetic set_KeySize(256)
    private static final IDetectionRule<CSharpTree> ECDSA_SET_KEY_SIZE =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes(MethodMatcher.ANY)
                    .forMethods("set_KeySize")
                    .withMethodParameter(MethodMatcher.ANY)
                    .shouldBeDetectedAs(new KeySizeFactory<>(Size.UnitType.BIT))
                    .buildForContext(new KeyContext(Map.of("kind", "ECDSA")))
                    .inBundle(() -> "DotNet")
                    .withoutDependingDetectionRules();

    // =========================================================================
    // Signing / verification operation rules
    // Each rule covers every overload of the given method name. The HashAlgorithmName is found
    // by declared type, so it is captured whether it sits at index one, as in SignData(data,
    // hashAlgorithm), or at index three, as in SignData(data, offset, count, hashAlgorithm).
    // =========================================================================

    // ecdsa.SignData(data, hashAlgorithm[, format]) [+ offset/length or Stream overloads]
    private static final IDetectionRule<CSharpTree> ECDSA_SIGN_DATA =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes(MethodMatcher.ANY)
                    .forMethods("SignData")
                    .shouldBeDetectedAs(new SignatureActionFactory<>(SignatureAction.Action.SIGN))
                    .withNamedMethodParameter("data", MethodMatcher.ANY)
                    .withOptionalNamedMethodParameter("hashAlgorithm", "HashAlgorithmName")
                    .shouldBeDetectedAs(new AlgorithmFactory<>())
                    .asChildOfParameterWithId(-1)
                    .withOptionalNamedMethodParameter("offset", "int")
                    .withOptionalNamedMethodParameter("count", "int")
                    .withOptionalNamedMethodParameter("signatureFormat", MethodMatcher.ANY)
                    .buildForContext(new SignatureContext())
                    .inBundle(() -> "DotNet")
                    .withoutDependingDetectionRules();

    // ecdsa.TrySignData(data, destination, hashAlgorithm[, format], out bytesWritten)
    private static final IDetectionRule<CSharpTree> ECDSA_TRY_SIGN_DATA =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes(MethodMatcher.ANY)
                    .forMethods("TrySignData")
                    .shouldBeDetectedAs(new SignatureActionFactory<>(SignatureAction.Action.SIGN))
                    .withNamedMethodParameter("data", MethodMatcher.ANY)
                    .withOptionalNamedMethodParameter("hashAlgorithm", "HashAlgorithmName")
                    .shouldBeDetectedAs(new AlgorithmFactory<>())
                    .asChildOfParameterWithId(-1)
                    .withOptionalNamedMethodParameter("destination", MethodMatcher.ANY)
                    .withOptionalNamedMethodParameter("signatureFormat", MethodMatcher.ANY)
                    .withOptionalNamedMethodParameter("bytesWritten", MethodMatcher.ANY)
                    .buildForContext(new SignatureContext())
                    .inBundle(() -> "DotNet")
                    .withoutDependingDetectionRules();

    // ecdsa.SignHash(hash[, format]) — legacy byte[] overload (ECDsaOpenSsl) and modern
    // Span<byte>/DSASignatureFormat overloads (ECDsa base) are all covered.
    private static final IDetectionRule<CSharpTree> ECDSA_SIGN_HASH =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes(MethodMatcher.ANY)
                    .forMethods("SignHash")
                    .shouldBeDetectedAs(new SignatureActionFactory<>(SignatureAction.Action.SIGN))
                    .withAnyParameters()
                    .buildForContext(new SignatureContext())
                    .inBundle(() -> "DotNet")
                    .withoutDependingDetectionRules();

    // ecdsa.TrySignHash(hash, destination[, format], out bytesWritten)
    private static final IDetectionRule<CSharpTree> ECDSA_TRY_SIGN_HASH =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes(MethodMatcher.ANY)
                    .forMethods("TrySignHash")
                    .shouldBeDetectedAs(new SignatureActionFactory<>(SignatureAction.Action.SIGN))
                    .withAnyParameters()
                    .buildForContext(new SignatureContext())
                    .inBundle(() -> "DotNet")
                    .withoutDependingDetectionRules();

    // ecdsa.VerifyData(data, signature, hashAlgorithm[, format]) [+ offset/length or Stream
    // overloads]
    private static final IDetectionRule<CSharpTree> ECDSA_VERIFY_DATA =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes(MethodMatcher.ANY)
                    .forMethods("VerifyData")
                    .shouldBeDetectedAs(new SignatureActionFactory<>(SignatureAction.Action.VERIFY))
                    .withNamedMethodParameter("data", MethodMatcher.ANY)
                    .withOptionalNamedMethodParameter("hashAlgorithm", "HashAlgorithmName")
                    .shouldBeDetectedAs(new AlgorithmFactory<>())
                    .asChildOfParameterWithId(-1)
                    .withOptionalNamedMethodParameter("signature", MethodMatcher.ANY)
                    .withOptionalNamedMethodParameter("offset", "int")
                    .withOptionalNamedMethodParameter("count", "int")
                    .withOptionalNamedMethodParameter("signatureFormat", MethodMatcher.ANY)
                    .buildForContext(new SignatureContext())
                    .inBundle(() -> "DotNet")
                    .withoutDependingDetectionRules();

    // ecdsa.VerifyHash(hash, signature[, format]) — legacy byte[] overload (ECDsaOpenSsl) and
    // modern ReadOnlySpan<byte>/DSASignatureFormat overloads (ECDsa base) are all covered.
    private static final IDetectionRule<CSharpTree> ECDSA_VERIFY_HASH =
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

    /** Full set of depending rules for all ECDsa-derived classes. */
    private static final List<IDetectionRule<CSharpTree>> ECDSA_DEPENDING_RULES =
            List.of(
                    ECDSA_SET_KEY_SIZE,
                    ECDSA_SIGN_DATA,
                    ECDSA_TRY_SIGN_DATA,
                    ECDSA_SIGN_HASH,
                    ECDSA_TRY_SIGN_HASH,
                    ECDSA_VERIFY_DATA,
                    ECDSA_VERIFY_HASH);

    // =========================================================================
    // Primary creation rules
    // =========================================================================

    // ECDsa.Create() / ECDsa.Create(ECCurve) / ECDsa.Create(ECParameters) / ECDsa.Create(string)
    private static final IDetectionRule<CSharpTree> ECDSA_CREATE =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes("ECDsa")
                    .forMethods("Create")
                    .shouldBeDetectedAs(new ValueActionFactory<>("ECDSA"))
                    .withOptionalNamedMethodParameter("curve", MethodMatcher.ANY)
                    .shouldBeDetectedAs(new DotNetEcKeySizeOrCurveFactory<>())
                    .asChildOfParameterWithId(-1)
                    .addDependingDetectionRules(RuleSets.rulesOf(DotNetEcCurve.class))
                    .buildForContext(new KeyContext(Map.of("kind", "ECDSA")))
                    .inBundle(() -> "DotNet")
                    .withDependingDetectionRules(ECDSA_DEPENDING_RULES);

    // new ECDsaCng() / (CngKey) / (ECCurve) / (int) — CNG-backed implementation.
    // Uses withAnyParameters() to cover all constructor overloads in a single rule and avoid
    // double-detection (see AES_CNG_NAMED in DotNetAES.java / ECDH_CNG in
    // DotNetECDiffieHellman.java).
    private static final IDetectionRule<CSharpTree> ECDSA_CNG =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes("ECDsaCng")
                    .forMethods("<init>")
                    .shouldBeDetectedAs(new ValueActionFactory<>("ECDSA"))
                    .withOptionalNamedMethodParameter("curve", MethodMatcher.ANY)
                    .shouldBeDetectedAs(new DotNetEcKeySizeOrCurveFactory<>())
                    .asChildOfParameterWithId(-1)
                    .addDependingDetectionRules(RuleSets.rulesOf(DotNetEcCurve.class))
                    .buildForContext(new KeyContext(Map.of("kind", "ECDSA")))
                    .inBundle(() -> "DotNet")
                    .withDependingDetectionRules(ECDSA_DEPENDING_RULES);

    // new ECDsaOpenSsl() / (ECCurve) / (int) / (IntPtr) / (SafeEvpPKeyHandle) — OpenSSL-backed
    // implementation. Uses withAnyParameters() to avoid double-detection that would occur if
    // separate rules were added per overload (see AES_CNG_NAMED in DotNetAES.java).
    private static final IDetectionRule<CSharpTree> ECDSA_OPENSSL =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes("ECDsaOpenSsl")
                    .forMethods("<init>")
                    .shouldBeDetectedAs(new ValueActionFactory<>("ECDSA"))
                    .withOptionalNamedMethodParameter("curve", MethodMatcher.ANY)
                    .shouldBeDetectedAs(new DotNetEcKeySizeOrCurveFactory<>())
                    .asChildOfParameterWithId(-1)
                    .addDependingDetectionRules(RuleSets.rulesOf(DotNetEcCurve.class))
                    .buildForContext(new KeyContext(Map.of("kind", "ECDSA")))
                    .inBundle(() -> "DotNet")
                    .withDependingDetectionRules(ECDSA_DEPENDING_RULES);

    @Nonnull
    @Override
    protected List<IDetectionRule<CSharpTree>> buildRules() {
        return List.of(ECDSA_CREATE, ECDSA_CNG, ECDSA_OPENSSL);
    }
}
