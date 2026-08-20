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

import com.ibm.engine.language.csharp.tree.CSharpTree;
import com.ibm.engine.model.context.DigestContext;
import com.ibm.engine.model.factory.ValueActionFactory;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import java.util.List;
import javax.annotation.Nonnull;

/**
 * Detection rules for the SHA-3/SHAKE hash algorithm family in System.Security.Cryptography.
 *
 * <p>Classes covered:
 *
 * <ul>
 *   <li>{@code SHA3_256} — abstract base, {@code SHA3_256.Create()} only
 *   <li>{@code SHA3_384} — abstract base, {@code SHA3_384.Create()} only
 *   <li>{@code SHA3_512} — abstract base, {@code SHA3_512.Create()} only
 *   <li>{@code Shake128} — sealed class, directly constructible via {@code new Shake128()}
 *   <li>{@code Shake256} — sealed class, directly constructible via {@code new Shake256()}
 * </ul>
 *
 * <p>Unlike the SHA-1/SHA-2/MD5/RIPEMD160 family in {@link DotNetSHA}, none of these five classes
 * has a {@code Create(string)} named-factory overload (verified against the official API reference
 * for .NET 8/9/10/11 — the {@code Create()} method table for {@code SHA3_256}/{@code SHA3_384}/
 * {@code SHA3_512} lists only the parameterless overload), and none has legacy {@code *Managed},
 * {@code *Cng} or {@code *CryptoServiceProvider} implementations — these algorithms were introduced
 * directly with .NET 8 and are platform-dependent (see {@code IsSupported}, which is a pure
 * availability check and intentionally not modeled here, consistent with how other {@code
 * IsSupported} properties are ignored across this rule set).
 *
 * <p>{@code Shake128}/{@code Shake256} are sealed classes (not abstract), have a public
 * parameterless constructor, and have <em>no</em> {@code Create()} factory at all — they are
 * instantiated directly with {@code new Shake128()} / {@code new Shake256()}, which is why their
 * detection rule matches the constructor ({@code <init>}) rather than a static factory method, the
 * same pattern used for {@code AesManaged} in {@link DotNetAES}.
 *
 * <p><b>Why SHAKE's output-length parameter is not modeled as a depending rule:</b> SHAKE128/256
 * are extendable-output functions (XOF) whose output length is variable and specified per call
 * (e.g. {@code Shake128.HashData(data, outputLength)}, {@code shake.GetHashAndReset(outputLength)},
 * {@code shake.Read(outputLength)}). Per the official remarks: "The size of the XOF indicates the
 * security strength of the algorithm, not the output size" — i.e. the "128"/"256" in the class name
 * is a security-strength parameter (captured by the creation rule itself, analogous to AES-128 vs.
 * AES-256), while the length passed to {@code HashData}/{@code GetHashAndReset}/{@code
 * GetCurrentHash}/{@code Read} is an arbitrary output-length request that carries no additional
 * cryptographically relevant information about the algorithm. This mirrors two independent existing
 * conventions: (1) the pre-established rule in {@link DotNetSHA} that {@code ComputeHash} and
 * friends add nothing beyond what the creation rule already captures, and (2) the Go module's
 * {@code golang.org/x/crypto/sha3} rules ({@code GoCryptoSHA3}), which likewise detect only {@code
 * NewShake128()}/{@code NewShake256()} and attach no depending rules for any subsequent read/output
 * operation. No depending rules are added here either.
 *
 * <p>Both {@code SHA3_256}/{@code SHA3_384}/{@code SHA3_512} (fixed-length digests) and {@code
 * Shake128}/{@code Shake256} (XOF) inherit the same set of hash-computation operations ({@code
 * HashData}, {@code AppendData}, {@code TryHashData}, etc.) that, following the established
 * convention above, are not modeled as depending rules for the fixed-digest classes either.
 */
@SuppressWarnings("java:S1192")
public final class DotNetSHA3 {

    private DotNetSHA3() {
        // nothing
    }

    // =========================================================================
    // SHA3-256 / SHA3-384 / SHA3-512
    // =========================================================================

    // SHA3_256.Create() — abstract factory, no parameters, no named-factory overload
    private static final IDetectionRule<CSharpTree> SHA3_256_CREATE =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes("SHA3_256")
                    .forMethods("Create")
                    .shouldBeDetectedAs(new ValueActionFactory<>("SHA3_256"))
                    .withoutParameters()
                    .buildForContext(new DigestContext())
                    .inBundle(() -> "DotNet")
                    .withDependingDetectionRules(List.of());

    // SHA3_384.Create() — abstract factory, no parameters, no named-factory overload
    private static final IDetectionRule<CSharpTree> SHA3_384_CREATE =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes("SHA3_384")
                    .forMethods("Create")
                    .shouldBeDetectedAs(new ValueActionFactory<>("SHA3_384"))
                    .withoutParameters()
                    .buildForContext(new DigestContext())
                    .inBundle(() -> "DotNet")
                    .withDependingDetectionRules(List.of());

    // SHA3_512.Create() — abstract factory, no parameters, no named-factory overload
    private static final IDetectionRule<CSharpTree> SHA3_512_CREATE =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes("SHA3_512")
                    .forMethods("Create")
                    .shouldBeDetectedAs(new ValueActionFactory<>("SHA3_512"))
                    .withoutParameters()
                    .buildForContext(new DigestContext())
                    .inBundle(() -> "DotNet")
                    .withDependingDetectionRules(List.of());

    // =========================================================================
    // Shake128 / Shake256 (extendable-output functions, XOF)
    // =========================================================================

    // new Shake128() — sealed class, no Create() factory, only a public constructor
    private static final IDetectionRule<CSharpTree> SHAKE_128 =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes("Shake128")
                    .forMethods("<init>")
                    .shouldBeDetectedAs(new ValueActionFactory<>("Shake128"))
                    .withoutParameters()
                    .buildForContext(new DigestContext())
                    .inBundle(() -> "DotNet")
                    .withDependingDetectionRules(List.of());

    // new Shake256() — sealed class, no Create() factory, only a public constructor
    private static final IDetectionRule<CSharpTree> SHAKE_256 =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes("Shake256")
                    .forMethods("<init>")
                    .shouldBeDetectedAs(new ValueActionFactory<>("Shake256"))
                    .withoutParameters()
                    .buildForContext(new DigestContext())
                    .inBundle(() -> "DotNet")
                    .withDependingDetectionRules(List.of());

    @Nonnull
    public static List<IDetectionRule<CSharpTree>> rules() {
        return List.of(SHA3_256_CREATE, SHA3_384_CREATE, SHA3_512_CREATE, SHAKE_128, SHAKE_256);
    }
}
