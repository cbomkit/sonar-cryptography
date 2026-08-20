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
import com.ibm.engine.model.context.PRNGContext;
import com.ibm.engine.model.factory.ValueActionFactory;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import java.util.List;
import javax.annotation.Nonnull;

/**
 * Detection rules for {@code RandomNumberGenerator} and {@code RNGCryptoServiceProvider} in
 * System.Security.Cryptography.
 *
 * <p>Classes/members covered (per the official API reference, verified via WebFetch of
 * learn.microsoft.com — not guessed):
 *
 * <ul>
 *   <li>{@code RandomNumberGenerator.Create()} / {@code Create(string)} — instance factory (the
 *       {@code Create(string)} overload is marked {@code Obsolete} in recent .NET versions but
 *       remains valid, detectable legacy source). The returned instance exposes the abstract
 *       instance methods {@code GetBytes(byte[])}, {@code GetBytes(byte[], int, int)} and {@code
 *       GetNonZeroBytes(byte[])}, tracked as depending rules.
 *   <li><b>{@code RandomNumberGenerator}'s static-only members</b> — the actual focus of this
 *       batch, not just {@code Create()}: {@code Fill(Span<byte>)}, {@code GetBytes(int)} / {@code
 *       GetBytes(Span<byte>)}, {@code GetHexString(int, bool)} / {@code GetHexString(Span<char>,
 *       bool)}, {@code GetInt32(int)} / {@code GetInt32(int, int)}, {@code
 *       GetItems<T>(ReadOnlySpan<T>, int)} / {@code GetItems<T>(ReadOnlySpan<T>, Span<T>)}, {@code
 *       GetNonZeroBytes(Span<byte>)}, {@code GetString(ReadOnlySpan<char>, int)}, and {@code
 *       Shuffle<T>(Span<T>)}. "Using the static members of this class is the preferred way to
 *       generate random values" per the official documentation.
 *   <li>{@code RNGCryptoServiceProvider} — legacy CSP-backed implementation ({@code Obsolete} since
 *       .NET 6, still valid, detectable legacy source). Four constructor overloads ({@code ()},
 *       {@code (byte[])}, {@code (CspParameters)}, {@code (string)}), with instance {@code
 *       GetBytes}/{@code GetNonZeroBytes} (each with a {@code byte[]} and a {@code Span}-based
 *       overload) tracked as depending rules.
 * </ul>
 *
 * <p><b>Modeling decision — reused the existing {@code PseudorandomNumberGenerator} /{@code
 * PRNGContext} concept instead of inventing a new mapper model class:</b> the mapper module already
 * has a generic "randomness source" concept used by both the Java and Go modules for the exact same
 * kind of API (a call that produces cryptographically strong random output with no user-selectable
 * algorithm identity): {@code java.security.SecureRandom} ({@link
 * com.ibm.plugin.rules.detection.random.SecureRandomGetInstance} in the {@code java} module) and
 * Go's {@code crypto/rand} ({@link com.ibm.plugin.rules.detection.gocrypto.GoCryptoRand} in the
 * {@code go} module) both translate through {@code PRNGContext} to a {@code
 * com.ibm.mapper.model.Algorithm} node typed as {@code
 * com.ibm.mapper.model.PseudorandomNumberGenerator}. The Go precedent is architecturally the
 * closest analogue to .NET's {@code RandomNumberGenerator}: both are "ask the OS/platform for
 * cryptographically strong random bytes, no algorithm selection" APIs (unlike Java's {@code
 * SecureRandom}, which supports named provider algorithms such as {@code "NativePRNG"} or {@code
 * "SHA1PRNG"}). This file follows the Go precedent exactly: every self-contained creation/static
 * call is captured with {@code ValueActionFactory<>("NATIVEPRNG")} and dispatched in the new {@code
 * CSharpPRNGContextTranslator} to {@code new Algorithm("NATIVEPRNG",
 * PseudorandomNumberGenerator.class, detectionLocation)} — no new mapper model class was created
 * for this batch.
 *
 * <p><b>Modeling decision — static self-contained calls vs. instance depending-rule operations:</b>
 * mirrors the {@code HKDF} vs. {@code SP800108HmacCounterKdf} distinction established in {@link
 * DotNetKeyDerivation}. {@code RandomNumberGenerator}'s static methods ({@code Fill}, {@code
 * GetBytes(int)}/{@code GetBytes(Span<byte>)}, {@code GetHexString}, {@code GetInt32}, {@code
 * GetItems}, {@code GetNonZeroBytes(Span<byte>)}, {@code GetString}, {@code Shuffle}) are each a
 * complete, self-contained "the platform CSPRNG was used" event with no instance to track — they
 * are top-level rules mapping directly to the {@code NATIVEPRNG} algorithm identity, exactly like
 * {@code HKDF.Extract}/{@code Expand}/{@code DeriveKey}. Where an actual instance *is* tracked
 * ({@code RandomNumberGenerator.Create()}'s or {@code RNGCryptoServiceProvider}'s instance {@code
 * GetBytes}/{@code GetNonZeroBytes}), those calls are depending rules attached to the creation
 * rule, translated to the generic {@code Generate} functionality node (mirrors {@code
 * AES_GENERATE_IV} in {@link DotNetAES}, which also has no more specific {@code CipherAction}
 * available) as a child of the already-identified {@code NATIVEPRNG} algorithm node.
 *
 * <p>As with every other file in this rule set, the ANTLR4-based C# engine cannot resolve parameter
 * types (see {@code CSharpLanguageTranslation}) or values held in variables (see {@code
 * CSharpTreeConverter} — only literals and bare identifiers are read), so all overloads that only
 * differ by {@code byte[]} vs. {@code Span<byte>}/{@code ReadOnlySpan<T>}, by an optional trailing
 * {@code bool}/output-buffer parameter, or by generic type argument are collapsed into a single
 * {@code withAnyParameters()} rule per method name.
 *
 * <p><b>Known gap — {@code RandomNumberGenerator.Fill}/{@code GetNonZeroBytes(Span<byte>)}/etc.
 * called through a base-class-typed local variable that is itself the result of {@code
 * RandomNumberGenerator.Create()}:</b> only the truly-static call form ({@code
 * RandomNumberGenerator.Fill(...)}, receiver text literally {@code "RandomNumberGenerator"}) is
 * covered by the top-level static rules in this file. {@code Fill} and the static {@code
 * GetBytes(Span<byte>)}/{@code GetNonZeroBytes(Span<byte>)} overloads are <em>not</em> also
 * addressable as instance methods on a concrete {@code RandomNumberGenerator} object in real .NET
 * (they are {@code static} only), so this is not an actual coverage gap — it is called out here
 * only because it might look, at a glance, like a missing depending rule.
 */
@SuppressWarnings("java:S1192")
public final class DotNetRandomNumberGenerator {

    private DotNetRandomNumberGenerator() {
        // nothing
    }

    // =========================================================================
    // Depending rules — instance operations on an already-tracked RNG object,
    // shared by RandomNumberGenerator.Create()/Create(string) and
    // RNGCryptoServiceProvider's constructors (RNGCryptoServiceProvider derives from
    // RandomNumberGenerator and exposes the identical GetBytes/GetNonZeroBytes instance API).
    // =========================================================================

    // rng.GetBytes(data) / rng.GetBytes(data, offset, count)
    private static final IDetectionRule<CSharpTree> RNG_INSTANCE_GET_BYTES =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes(MethodMatcher.ANY)
                    .forMethods("GetBytes")
                    .shouldBeDetectedAs(new ValueActionFactory<>("GetBytes"))
                    .withAnyParameters()
                    .buildForContext(new PRNGContext())
                    .inBundle(() -> "DotNet")
                    .withoutDependingDetectionRules();

    // rng.GetNonZeroBytes(data)
    private static final IDetectionRule<CSharpTree> RNG_INSTANCE_GET_NON_ZERO_BYTES =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes(MethodMatcher.ANY)
                    .forMethods("GetNonZeroBytes")
                    .shouldBeDetectedAs(new ValueActionFactory<>("GetNonZeroBytes"))
                    .withAnyParameters()
                    .buildForContext(new PRNGContext())
                    .inBundle(() -> "DotNet")
                    .withoutDependingDetectionRules();

    private static final List<IDetectionRule<CSharpTree>> RNG_INSTANCE_DEPENDING_RULES =
            List.of(RNG_INSTANCE_GET_BYTES, RNG_INSTANCE_GET_NON_ZERO_BYTES);

    // =========================================================================
    // RandomNumberGenerator.Create() / Create(string) — instance factory.
    // =========================================================================

    // RandomNumberGenerator.Create()
    private static final IDetectionRule<CSharpTree> RNG_CREATE =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes("RandomNumberGenerator")
                    .forMethods("Create")
                    .shouldBeDetectedAs(new ValueActionFactory<>("NATIVEPRNG"))
                    .withoutParameters()
                    .buildForContext(new PRNGContext())
                    .inBundle(() -> "DotNet")
                    .withDependingDetectionRules(RNG_INSTANCE_DEPENDING_RULES);

    // RandomNumberGenerator.Create(string rngName) — Obsolete in recent .NET, still detectable.
    private static final IDetectionRule<CSharpTree> RNG_CREATE_NAMED =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes("RandomNumberGenerator")
                    .forMethods("Create")
                    .shouldBeDetectedAs(new ValueActionFactory<>("NATIVEPRNG"))
                    .withMethodParameter(MethodMatcher.ANY) // algorithm name string
                    .buildForContext(new PRNGContext())
                    .inBundle(() -> "DotNet")
                    .withDependingDetectionRules(RNG_INSTANCE_DEPENDING_RULES);

    // =========================================================================
    // RandomNumberGenerator static-only methods — each call is both the "creation" and
    // the "operation" at once (see class javadoc "Modeling decision"). Overloads distinguished
    // only by byte[] vs. Span<T>/ReadOnlySpan<T>, by an optional trailing bool/output-buffer
    // parameter, or by generic type argument are collapsed via withAnyParameters().
    // =========================================================================

    // RandomNumberGenerator.Fill(Span<byte> data)
    private static final IDetectionRule<CSharpTree> RNG_FILL =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes("RandomNumberGenerator")
                    .forMethods("Fill")
                    .shouldBeDetectedAs(new ValueActionFactory<>("NATIVEPRNG"))
                    .withAnyParameters()
                    .buildForContext(new PRNGContext())
                    .inBundle(() -> "DotNet")
                    .withoutDependingDetectionRules();

    // RandomNumberGenerator.GetBytes(int count) / GetBytes(Span<byte> data)
    private static final IDetectionRule<CSharpTree> RNG_STATIC_GET_BYTES =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes("RandomNumberGenerator")
                    .forMethods("GetBytes")
                    .shouldBeDetectedAs(new ValueActionFactory<>("NATIVEPRNG"))
                    .withAnyParameters()
                    .buildForContext(new PRNGContext())
                    .inBundle(() -> "DotNet")
                    .withoutDependingDetectionRules();

    // RandomNumberGenerator.GetHexString(int count, bool lowercase = false)
    // / GetHexString(Span<char> destination, bool lowercase = false)
    private static final IDetectionRule<CSharpTree> RNG_GET_HEX_STRING =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes("RandomNumberGenerator")
                    .forMethods("GetHexString")
                    .shouldBeDetectedAs(new ValueActionFactory<>("NATIVEPRNG"))
                    .withAnyParameters()
                    .buildForContext(new PRNGContext())
                    .inBundle(() -> "DotNet")
                    .withoutDependingDetectionRules();

    // RandomNumberGenerator.GetInt32(int toExclusive) / GetInt32(int fromInclusive, int
    // toExclusive)
    private static final IDetectionRule<CSharpTree> RNG_GET_INT32 =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes("RandomNumberGenerator")
                    .forMethods("GetInt32")
                    .shouldBeDetectedAs(new ValueActionFactory<>("NATIVEPRNG"))
                    .withAnyParameters()
                    .buildForContext(new PRNGContext())
                    .inBundle(() -> "DotNet")
                    .withoutDependingDetectionRules();

    // RandomNumberGenerator.GetItems<T>(ReadOnlySpan<T> choices, int length)
    // / GetItems<T>(ReadOnlySpan<T> choices, Span<T> destination)
    private static final IDetectionRule<CSharpTree> RNG_GET_ITEMS =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes("RandomNumberGenerator")
                    .forMethods("GetItems")
                    .shouldBeDetectedAs(new ValueActionFactory<>("NATIVEPRNG"))
                    .withAnyParameters()
                    .buildForContext(new PRNGContext())
                    .inBundle(() -> "DotNet")
                    .withoutDependingDetectionRules();

    // RandomNumberGenerator.GetNonZeroBytes(Span<byte> data) — static overload
    private static final IDetectionRule<CSharpTree> RNG_STATIC_GET_NON_ZERO_BYTES =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes("RandomNumberGenerator")
                    .forMethods("GetNonZeroBytes")
                    .shouldBeDetectedAs(new ValueActionFactory<>("NATIVEPRNG"))
                    .withAnyParameters()
                    .buildForContext(new PRNGContext())
                    .inBundle(() -> "DotNet")
                    .withoutDependingDetectionRules();

    // RandomNumberGenerator.GetString(ReadOnlySpan<char> choices, int length)
    private static final IDetectionRule<CSharpTree> RNG_GET_STRING =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes("RandomNumberGenerator")
                    .forMethods("GetString")
                    .shouldBeDetectedAs(new ValueActionFactory<>("NATIVEPRNG"))
                    .withAnyParameters()
                    .buildForContext(new PRNGContext())
                    .inBundle(() -> "DotNet")
                    .withoutDependingDetectionRules();

    // RandomNumberGenerator.Shuffle<T>(Span<T> values)
    private static final IDetectionRule<CSharpTree> RNG_SHUFFLE =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes("RandomNumberGenerator")
                    .forMethods("Shuffle")
                    .shouldBeDetectedAs(new ValueActionFactory<>("NATIVEPRNG"))
                    .withAnyParameters()
                    .buildForContext(new PRNGContext())
                    .inBundle(() -> "DotNet")
                    .withoutDependingDetectionRules();

    // =========================================================================
    // RNGCryptoServiceProvider — legacy CSP-backed implementation (Obsolete since .NET 6, still
    // detectable legacy source). Constructor + instance GetBytes/GetNonZeroBytes, reusing the
    // same depending-rule pair as RandomNumberGenerator.Create() above since both classes expose
    // the identical instance API.
    // =========================================================================

    // new RNGCryptoServiceProvider() / (byte[] rgb) / (CspParameters cspParams) / (string str)
    // — 4 constructor overloads, all collapsed via withAnyParameters() (mirrors the AesCng
    // precedent in DotNetAES: a single withAnyParameters() rule avoids double-detection that
    // would occur if a separate withoutParameters() rule were added alongside it).
    private static final IDetectionRule<CSharpTree> RNG_CSP_CTOR =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes("RNGCryptoServiceProvider")
                    .forMethods("<init>")
                    .shouldBeDetectedAs(new ValueActionFactory<>("NATIVEPRNG"))
                    .withAnyParameters()
                    .buildForContext(new PRNGContext())
                    .inBundle(() -> "DotNet")
                    .withDependingDetectionRules(RNG_INSTANCE_DEPENDING_RULES);

    @Nonnull
    public static List<IDetectionRule<CSharpTree>> rules() {
        return List.of(
                RNG_CREATE,
                RNG_CREATE_NAMED,
                RNG_FILL,
                RNG_STATIC_GET_BYTES,
                RNG_GET_HEX_STRING,
                RNG_GET_INT32,
                RNG_GET_ITEMS,
                RNG_STATIC_GET_NON_ZERO_BYTES,
                RNG_GET_STRING,
                RNG_SHUFFLE,
                RNG_CSP_CTOR);
    }
}
