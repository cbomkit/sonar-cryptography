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
 * every matching method call, regardless of the concrete ECDsa subclass. Method overloads that only
 * differ by array-vs-{@code Span}, offset/length, {@code DSASignatureFormat}, or output-buffer
 * parameters are intentionally collapsed into a single {@code withAnyParameters()} rule per method
 * name: the ANTLR4-based C# engine cannot resolve parameter types (see {@code
 * CSharpLanguageTranslation}), so distinguishing overloads by parameter type is not possible, and
 * none of the extra parameters carry additional cryptographic information worth extracting. Unlike
 * RSA, ECDSA has no encrypt/decrypt operations — it is signature-only. Per the {@code ECDsa} API
 * reference, there are no {@code TryVerifyData}/{@code TryVerifyHash} methods (verification returns
 * a bool directly, so there is no output buffer to size), mirroring RSA.
 */
@SuppressWarnings("java:S1192")
public final class DotNetECDsa {

    private DotNetECDsa() {
        // nothing
    }

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
    // Each rule covers every overload of the given method name (arities vary only
    // by hash-algorithm / DSASignatureFormat / offset-length / output-buffer
    // parameters, which are not individually tracked), mirroring the RSA/DSA
    // SignData()/VerifyData() rules.
    // =========================================================================

    // ecdsa.SignData(data, hashAlgorithm[, format]) [+ offset/length or Stream overloads]
    private static final IDetectionRule<CSharpTree> ECDSA_SIGN_DATA =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes(MethodMatcher.ANY)
                    .forMethods("SignData")
                    .shouldBeDetectedAs(new SignatureActionFactory<>(SignatureAction.Action.SIGN))
                    .withAnyParameters()
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
                    .withAnyParameters()
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
                    .withAnyParameters()
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
                    .withAnyParameters()
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
                    .withAnyParameters()
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
                    .withAnyParameters()
                    .buildForContext(new KeyContext(Map.of("kind", "ECDSA")))
                    .inBundle(() -> "DotNet")
                    .withDependingDetectionRules(ECDSA_DEPENDING_RULES);

    @Nonnull
    public static List<IDetectionRule<CSharpTree>> rules() {
        return List.of(ECDSA_CREATE, ECDSA_CNG, ECDSA_OPENSSL);
    }
}
