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
import com.ibm.engine.model.context.KeyContext;
import com.ibm.engine.model.factory.ValueActionFactory;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import java.util.List;
import java.util.Map;
import javax.annotation.Nonnull;

/**
 * Detection rules for PBKDF2 via {@code Rfc2898DeriveBytes} in System.Security.Cryptography.
 *
 * <p>Detects:
 *
 * <ul>
 *   <li>{@code new Rfc2898DeriveBytes(password, salt, iterations)} — SHA-1 default
 *   <li>{@code new Rfc2898DeriveBytes(password, salt, iterations, hashAlgorithm)} — explicit hash
 *   <li>{@code Rfc2898DeriveBytes.Pbkdf2(...)} — static one-shot PBKDF2 (added in .NET 8; as of
 *       net-10.0/net-11.0 this is the recommended replacement for all 8 constructors above, which
 *       are now marked {@code Obsolete} per the official API reference)
 *   <li>{@code instance.GetBytes(int)} — pull more derived-key bytes from a constructed instance
 *   <li>{@code instance.CryptDeriveKey(string, string, int, byte[])} — CAPI-style key derivation
 *       from a constructed instance (also {@code Obsolete} per the reference, but still valid,
 *       detectable legacy source, same as the constructors)
 * </ul>
 *
 * <p><b>Modeling decision — {@code Pbkdf2(...)} as a top-level rule, not a depending rule:</b> all
 * 6 {@code Pbkdf2} overloads (per the official API reference: {@code Pbkdf2(byte[], byte[], int,
 * HashAlgorithmName, int)}, {@code Pbkdf2(ReadOnlySpan<byte>, ReadOnlySpan<byte>, int,
 * HashAlgorithmName, int)}, {@code Pbkdf2(ReadOnlySpan<byte>, ReadOnlySpan<byte>, Span<byte>, int,
 * HashAlgorithmName)}, {@code Pbkdf2(ReadOnlySpan<char>, ReadOnlySpan<byte>, int,
 * HashAlgorithmName, int)}, {@code Pbkdf2(ReadOnlySpan<char>, ReadOnlySpan<byte>, Span<byte>, int,
 * HashAlgorithmName)}, {@code Pbkdf2(string, byte[], int, HashAlgorithmName, int)}) are {@code
 * static} and self-contained: a single call is both the "creation" and the "operation" at once,
 * exactly like {@code HKDF.Extract}/{@code Expand}/{@code DeriveKey} in {@link DotNetKeyDerivation}
 * (see that class's javadoc "Modeling decision" for the full rationale). There is no object
 * instance to track between a "creation" and a later "operation" step, so the Batch 3
 * creation-rule-with-depending-operations pattern does not apply here; the call is captured
 * directly as a {@code ValueActionFactory<>("PBKDF2")} under the same {@code KeyContext} "kind"
 * ({@code "KDF"}) as the constructor rule below, so both map to the identical {@code PBKDF2} mapper
 * model node.
 *
 * <p>All 6 overloads happen to share the same arity (5 parameters each), so — as with every other
 * file in this rule set — the ANTLR4-based C# engine's inability to resolve parameter types (see
 * {@code CSharpLanguageTranslation}) is moot here even at the arity level: a single {@code
 * withAnyParameters()} rule covers every overload without needing to disambiguate by parameter
 * count. The {@code HashAlgorithmName} parameter is not decoded into a digest child node,
 * consistent with the constructor rule and with {@code DotNetKeyDerivation}'s HKDF rules.
 */
@SuppressWarnings("java:S1192")
public final class DotNetRfc2898DeriveBytes {

    private DotNetRfc2898DeriveBytes() {
        // nothing
    }

    // =========================================================================
    // Instance operation depending rules, reusing the Batch 3 KeyDerivation pattern
    // (see DotNetKeyDerivation's PasswordDeriveBytes section, which models the exact
    // same two operation shapes for its sibling legacy KDF class).
    // =========================================================================

    // instance.GetBytes(cb) — pull more pseudo-random derived-key bytes
    private static final IDetectionRule<CSharpTree> RFC2898_GET_BYTES =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes(MethodMatcher.ANY)
                    .forMethods("GetBytes")
                    .shouldBeDetectedAs(new ValueActionFactory<>("GetBytes"))
                    .withAnyParameters()
                    .buildForContext(new KeyContext(Map.of("kind", "KDF_RFC2898_GET_BYTES")))
                    .inBundle(() -> "DotNet")
                    .withoutDependingDetectionRules();

    // instance.CryptDeriveKey(algName, algHashName, keySize, rgbIV)
    private static final IDetectionRule<CSharpTree> RFC2898_CRYPT_DERIVE_KEY =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes(MethodMatcher.ANY)
                    .forMethods("CryptDeriveKey")
                    .shouldBeDetectedAs(new ValueActionFactory<>("CryptDeriveKey"))
                    .withAnyParameters()
                    .buildForContext(new KeyContext(Map.of("kind", "KDF_RFC2898_CRYPT_DERIVE_KEY")))
                    .inBundle(() -> "DotNet")
                    .withoutDependingDetectionRules();

    private static final List<IDetectionRule<CSharpTree>> RFC2898_DEPENDING_RULES =
            List.of(RFC2898_GET_BYTES, RFC2898_CRYPT_DERIVE_KEY);

    // =========================================================================
    // Primary rules
    // =========================================================================

    // new Rfc2898DeriveBytes(...) — all 8 constructor overloads, collapsed via withAnyParameters()
    private static final IDetectionRule<CSharpTree> RFC2898 =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes("Rfc2898DeriveBytes")
                    .forMethods("<init>")
                    .shouldBeDetectedAs(new ValueActionFactory<>("PBKDF2"))
                    .withAnyParameters()
                    .buildForContext(new KeyContext(Map.of("kind", "KDF")))
                    .inBundle(() -> "DotNet")
                    .withDependingDetectionRules(RFC2898_DEPENDING_RULES);

    // Rfc2898DeriveBytes.Pbkdf2(...) — static one-shot, all 6 overloads (see class javadoc
    // "Modeling decision").
    private static final IDetectionRule<CSharpTree> RFC2898_PBKDF2_STATIC =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes("Rfc2898DeriveBytes")
                    .forMethods("Pbkdf2")
                    .shouldBeDetectedAs(new ValueActionFactory<>("PBKDF2"))
                    .withAnyParameters()
                    .buildForContext(new KeyContext(Map.of("kind", "KDF")))
                    .inBundle(() -> "DotNet")
                    .withoutDependingDetectionRules();

    @Nonnull
    public static List<IDetectionRule<CSharpTree>> rules() {
        return List.of(RFC2898, RFC2898_PBKDF2_STATIC);
    }
}
