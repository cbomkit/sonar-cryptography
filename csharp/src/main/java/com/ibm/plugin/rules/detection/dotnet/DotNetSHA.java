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
import com.ibm.engine.model.context.DigestContext;
import com.ibm.engine.model.factory.ValueActionFactory;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import java.util.List;
import javax.annotation.Nonnull;

/**
 * Detection rules for the SHA/MD5 hash algorithm family in System.Security.Cryptography.
 *
 * <p>Classes covered:
 *
 * <ul>
 *   <li>{@code MD5} — abstract base ({@code MD5.Create()}, {@code MD5.Create(string)}), {@code
 *       MD5Cng}, {@code MD5CryptoServiceProvider}
 *   <li>{@code SHA1} — abstract base ({@code SHA1.Create()}, {@code SHA1.Create(string)}), {@code
 *       SHA1Managed}, {@code SHA1Cng}, {@code SHA1CryptoServiceProvider}
 *   <li>{@code SHA256} — abstract base ({@code SHA256.Create()}, {@code SHA256.Create(string)}),
 *       {@code SHA256Managed}, {@code SHA256Cng}, {@code SHA256CryptoServiceProvider}
 *   <li>{@code SHA384} — abstract base ({@code SHA384.Create()}, {@code SHA384.Create(string)}),
 *       {@code SHA384Managed}, {@code SHA384Cng}, {@code SHA384CryptoServiceProvider}
 *   <li>{@code SHA512} — abstract base ({@code SHA512.Create()}, {@code SHA512.Create(string)}),
 *       {@code SHA512Managed}, {@code SHA512Cng}, {@code SHA512CryptoServiceProvider}
 *   <li>{@code RIPEMD160} — abstract base ({@code RIPEMD160.Create()}, {@code
 *       RIPEMD160.Create(string)}), {@code RIPEMD160Managed}. Note: RIPEMD160 only ever existed in
 *       .NET Framework (documented up to net framework 4.8.1); it was never ported to .NET Core/5+.
 *       It is detected here for legacy/.NET Framework source code.
 * </ul>
 *
 * <p>Architecture: unlike cipher/signature algorithms, a hash algorithm's complete
 * cryptographically-relevant information (which digest algorithm, which digest length) is already
 * fully captured by the creation rule itself (e.g. {@code new SHA256Managed()} already says
 * everything necessary — SHA-256, 256 bits). Operation methods inherited from {@code HashAlgorithm}
 * ({@code ComputeHash}, {@code ComputeHash(byte[])}, {@code ComputeHash(Stream)}, {@code
 * TransformBlock}, {@code TransformFinalBlock}, {@code TryComputeHash}, the static {@code
 * HashData}/{@code TryHashData} helpers) do not add cryptographically relevant information to the
 * CBOM model (unlike Encrypt vs. Decrypt for ciphers, or Sign vs. Verify for signatures).
 * Consistent with the pre-existing rules in this file (which never attached depending rules for
 * these operations), no depending rules are added here either.
 */
@SuppressWarnings("java:S1192")
public final class DotNetSHA {

    private DotNetSHA() {
        // nothing
    }

    // =========================================================================
    // MD5
    // =========================================================================

    // MD5.Create() — abstract factory, no parameters
    private static final IDetectionRule<CSharpTree> MD5_CREATE =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes("MD5")
                    .forMethods("Create")
                    .shouldBeDetectedAs(new ValueActionFactory<>("MD5"))
                    .withoutParameters()
                    .buildForContext(new DigestContext())
                    .inBundle(() -> "DotNet")
                    .withDependingDetectionRules(List.of());

    // MD5.Create("MD5") — named factory (obsolete in .NET 7+, still detectable)
    private static final IDetectionRule<CSharpTree> MD5_CREATE_NAMED =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes("MD5")
                    .forMethods("Create")
                    .shouldBeDetectedAs(new ValueActionFactory<>("MD5"))
                    .withMethodParameter(MethodMatcher.ANY) // algorithm name string
                    .buildForContext(new DigestContext())
                    .inBundle(() -> "DotNet")
                    .withDependingDetectionRules(List.of());

    // new MD5CryptoServiceProvider() — legacy CAPI implementation
    private static final IDetectionRule<CSharpTree> MD5_CSP =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes("MD5CryptoServiceProvider")
                    .forMethods("<init>")
                    .shouldBeDetectedAs(new ValueActionFactory<>("MD5"))
                    .withoutParameters()
                    .buildForContext(new DigestContext())
                    .inBundle(() -> "DotNet")
                    .withDependingDetectionRules(List.of());

    // new MD5Cng() — CNG-backed implementation
    private static final IDetectionRule<CSharpTree> MD5_CNG =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes("MD5Cng")
                    .forMethods("<init>")
                    .shouldBeDetectedAs(new ValueActionFactory<>("MD5"))
                    .withoutParameters()
                    .buildForContext(new DigestContext())
                    .inBundle(() -> "DotNet")
                    .withDependingDetectionRules(List.of());

    // =========================================================================
    // SHA1
    // =========================================================================

    // SHA1.Create() — abstract factory, no parameters
    private static final IDetectionRule<CSharpTree> SHA1_CREATE =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes("SHA1")
                    .forMethods("Create")
                    .shouldBeDetectedAs(new ValueActionFactory<>("SHA1"))
                    .withoutParameters()
                    .buildForContext(new DigestContext())
                    .inBundle(() -> "DotNet")
                    .withDependingDetectionRules(List.of());

    // SHA1.Create("SHA1") — named factory (obsolete in .NET 7+, still detectable)
    private static final IDetectionRule<CSharpTree> SHA1_CREATE_NAMED =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes("SHA1")
                    .forMethods("Create")
                    .shouldBeDetectedAs(new ValueActionFactory<>("SHA1"))
                    .withMethodParameter(MethodMatcher.ANY) // algorithm name string
                    .buildForContext(new DigestContext())
                    .inBundle(() -> "DotNet")
                    .withDependingDetectionRules(List.of());

    // new SHA1Managed() — pure-managed implementation
    private static final IDetectionRule<CSharpTree> SHA1_MANAGED =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes("SHA1Managed")
                    .forMethods("<init>")
                    .shouldBeDetectedAs(new ValueActionFactory<>("SHA1"))
                    .withoutParameters()
                    .buildForContext(new DigestContext())
                    .inBundle(() -> "DotNet")
                    .withDependingDetectionRules(List.of());

    // new SHA1Cng() — CNG-backed implementation
    private static final IDetectionRule<CSharpTree> SHA1_CNG =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes("SHA1Cng")
                    .forMethods("<init>")
                    .shouldBeDetectedAs(new ValueActionFactory<>("SHA1"))
                    .withoutParameters()
                    .buildForContext(new DigestContext())
                    .inBundle(() -> "DotNet")
                    .withDependingDetectionRules(List.of());

    // new SHA1CryptoServiceProvider() — legacy CAPI implementation
    private static final IDetectionRule<CSharpTree> SHA1_CSP =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes("SHA1CryptoServiceProvider")
                    .forMethods("<init>")
                    .shouldBeDetectedAs(new ValueActionFactory<>("SHA1"))
                    .withoutParameters()
                    .buildForContext(new DigestContext())
                    .inBundle(() -> "DotNet")
                    .withDependingDetectionRules(List.of());

    // =========================================================================
    // SHA256
    // =========================================================================

    // SHA256.Create() — abstract factory, no parameters
    private static final IDetectionRule<CSharpTree> SHA256_CREATE =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes("SHA256")
                    .forMethods("Create")
                    .shouldBeDetectedAs(new ValueActionFactory<>("SHA256"))
                    .withoutParameters()
                    .buildForContext(new DigestContext())
                    .inBundle(() -> "DotNet")
                    .withDependingDetectionRules(List.of());

    // SHA256.Create("SHA256") — named factory (obsolete in .NET 7+, still detectable)
    private static final IDetectionRule<CSharpTree> SHA256_CREATE_NAMED =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes("SHA256")
                    .forMethods("Create")
                    .shouldBeDetectedAs(new ValueActionFactory<>("SHA256"))
                    .withMethodParameter(MethodMatcher.ANY) // algorithm name string
                    .buildForContext(new DigestContext())
                    .inBundle(() -> "DotNet")
                    .withDependingDetectionRules(List.of());

    // new SHA256Managed() — pure-managed implementation
    private static final IDetectionRule<CSharpTree> SHA256_MANAGED =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes("SHA256Managed")
                    .forMethods("<init>")
                    .shouldBeDetectedAs(new ValueActionFactory<>("SHA256"))
                    .withoutParameters()
                    .buildForContext(new DigestContext())
                    .inBundle(() -> "DotNet")
                    .withDependingDetectionRules(List.of());

    // new SHA256Cng() — CNG-backed implementation
    private static final IDetectionRule<CSharpTree> SHA256_CNG =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes("SHA256Cng")
                    .forMethods("<init>")
                    .shouldBeDetectedAs(new ValueActionFactory<>("SHA256"))
                    .withoutParameters()
                    .buildForContext(new DigestContext())
                    .inBundle(() -> "DotNet")
                    .withDependingDetectionRules(List.of());

    // new SHA256CryptoServiceProvider() — legacy CAPI implementation
    private static final IDetectionRule<CSharpTree> SHA256_CSP =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes("SHA256CryptoServiceProvider")
                    .forMethods("<init>")
                    .shouldBeDetectedAs(new ValueActionFactory<>("SHA256"))
                    .withoutParameters()
                    .buildForContext(new DigestContext())
                    .inBundle(() -> "DotNet")
                    .withDependingDetectionRules(List.of());

    // =========================================================================
    // SHA384
    // =========================================================================

    // SHA384.Create() — abstract factory, no parameters
    private static final IDetectionRule<CSharpTree> SHA384_CREATE =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes("SHA384")
                    .forMethods("Create")
                    .shouldBeDetectedAs(new ValueActionFactory<>("SHA384"))
                    .withoutParameters()
                    .buildForContext(new DigestContext())
                    .inBundle(() -> "DotNet")
                    .withDependingDetectionRules(List.of());

    // SHA384.Create("SHA384") — named factory (obsolete in .NET 7+, still detectable)
    private static final IDetectionRule<CSharpTree> SHA384_CREATE_NAMED =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes("SHA384")
                    .forMethods("Create")
                    .shouldBeDetectedAs(new ValueActionFactory<>("SHA384"))
                    .withMethodParameter(MethodMatcher.ANY) // algorithm name string
                    .buildForContext(new DigestContext())
                    .inBundle(() -> "DotNet")
                    .withDependingDetectionRules(List.of());

    // new SHA384Managed() — pure-managed implementation
    private static final IDetectionRule<CSharpTree> SHA384_MANAGED =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes("SHA384Managed")
                    .forMethods("<init>")
                    .shouldBeDetectedAs(new ValueActionFactory<>("SHA384"))
                    .withoutParameters()
                    .buildForContext(new DigestContext())
                    .inBundle(() -> "DotNet")
                    .withDependingDetectionRules(List.of());

    // new SHA384Cng() — CNG-backed implementation
    private static final IDetectionRule<CSharpTree> SHA384_CNG =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes("SHA384Cng")
                    .forMethods("<init>")
                    .shouldBeDetectedAs(new ValueActionFactory<>("SHA384"))
                    .withoutParameters()
                    .buildForContext(new DigestContext())
                    .inBundle(() -> "DotNet")
                    .withDependingDetectionRules(List.of());

    // new SHA384CryptoServiceProvider() — legacy CAPI implementation
    private static final IDetectionRule<CSharpTree> SHA384_CSP =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes("SHA384CryptoServiceProvider")
                    .forMethods("<init>")
                    .shouldBeDetectedAs(new ValueActionFactory<>("SHA384"))
                    .withoutParameters()
                    .buildForContext(new DigestContext())
                    .inBundle(() -> "DotNet")
                    .withDependingDetectionRules(List.of());

    // =========================================================================
    // SHA512
    // =========================================================================

    // SHA512.Create() — abstract factory, no parameters
    private static final IDetectionRule<CSharpTree> SHA512_CREATE =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes("SHA512")
                    .forMethods("Create")
                    .shouldBeDetectedAs(new ValueActionFactory<>("SHA512"))
                    .withoutParameters()
                    .buildForContext(new DigestContext())
                    .inBundle(() -> "DotNet")
                    .withDependingDetectionRules(List.of());

    // SHA512.Create("SHA512") — named factory (obsolete in .NET 7+, still detectable)
    private static final IDetectionRule<CSharpTree> SHA512_CREATE_NAMED =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes("SHA512")
                    .forMethods("Create")
                    .shouldBeDetectedAs(new ValueActionFactory<>("SHA512"))
                    .withMethodParameter(MethodMatcher.ANY) // algorithm name string
                    .buildForContext(new DigestContext())
                    .inBundle(() -> "DotNet")
                    .withDependingDetectionRules(List.of());

    // new SHA512Managed() — pure-managed implementation
    private static final IDetectionRule<CSharpTree> SHA512_MANAGED =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes("SHA512Managed")
                    .forMethods("<init>")
                    .shouldBeDetectedAs(new ValueActionFactory<>("SHA512"))
                    .withoutParameters()
                    .buildForContext(new DigestContext())
                    .inBundle(() -> "DotNet")
                    .withDependingDetectionRules(List.of());

    // new SHA512Cng() — CNG-backed implementation
    private static final IDetectionRule<CSharpTree> SHA512_CNG =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes("SHA512Cng")
                    .forMethods("<init>")
                    .shouldBeDetectedAs(new ValueActionFactory<>("SHA512"))
                    .withoutParameters()
                    .buildForContext(new DigestContext())
                    .inBundle(() -> "DotNet")
                    .withDependingDetectionRules(List.of());

    // new SHA512CryptoServiceProvider() — legacy CAPI implementation
    private static final IDetectionRule<CSharpTree> SHA512_CSP =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes("SHA512CryptoServiceProvider")
                    .forMethods("<init>")
                    .shouldBeDetectedAs(new ValueActionFactory<>("SHA512"))
                    .withoutParameters()
                    .buildForContext(new DigestContext())
                    .inBundle(() -> "DotNet")
                    .withDependingDetectionRules(List.of());

    // =========================================================================
    // RIPEMD160
    // Note: RIPEMD160/RIPEMD160Managed only ever existed in .NET Framework (documentation
    // covers up to netframework-4.8.1 only; no netcoreapp/net5+ monikers). It was never ported
    // to .NET Core / modern .NET, so it is only relevant for legacy .NET Framework source code.
    // =========================================================================

    // RIPEMD160.Create() — abstract factory, no parameters
    private static final IDetectionRule<CSharpTree> RIPEMD160_CREATE =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes("RIPEMD160")
                    .forMethods("Create")
                    .shouldBeDetectedAs(new ValueActionFactory<>("RIPEMD160"))
                    .withoutParameters()
                    .buildForContext(new DigestContext())
                    .inBundle(() -> "DotNet")
                    .withDependingDetectionRules(List.of());

    // RIPEMD160.Create("System.Security.Cryptography.RIPEMD160") — named factory
    private static final IDetectionRule<CSharpTree> RIPEMD160_CREATE_NAMED =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes("RIPEMD160")
                    .forMethods("Create")
                    .shouldBeDetectedAs(new ValueActionFactory<>("RIPEMD160"))
                    .withMethodParameter(MethodMatcher.ANY) // algorithm name string
                    .buildForContext(new DigestContext())
                    .inBundle(() -> "DotNet")
                    .withDependingDetectionRules(List.of());

    // new RIPEMD160Managed() — pure-managed implementation
    private static final IDetectionRule<CSharpTree> RIPEMD160_MANAGED =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes("RIPEMD160Managed")
                    .forMethods("<init>")
                    .shouldBeDetectedAs(new ValueActionFactory<>("RIPEMD160"))
                    .withoutParameters()
                    .buildForContext(new DigestContext())
                    .inBundle(() -> "DotNet")
                    .withDependingDetectionRules(List.of());

    @Nonnull
    public static List<IDetectionRule<CSharpTree>> rules() {
        return List.of(
                MD5_CREATE,
                MD5_CREATE_NAMED,
                MD5_CSP,
                MD5_CNG,
                SHA1_CREATE,
                SHA1_CREATE_NAMED,
                SHA1_MANAGED,
                SHA1_CNG,
                SHA1_CSP,
                SHA256_CREATE,
                SHA256_CREATE_NAMED,
                SHA256_MANAGED,
                SHA256_CNG,
                SHA256_CSP,
                SHA384_CREATE,
                SHA384_CREATE_NAMED,
                SHA384_MANAGED,
                SHA384_CNG,
                SHA384_CSP,
                SHA512_CREATE,
                SHA512_CREATE_NAMED,
                SHA512_MANAGED,
                SHA512_CNG,
                SHA512_CSP,
                RIPEMD160_CREATE,
                RIPEMD160_CREATE_NAMED,
                RIPEMD160_MANAGED);
    }
}
