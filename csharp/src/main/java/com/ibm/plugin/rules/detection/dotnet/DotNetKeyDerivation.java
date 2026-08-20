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
 * Detection rules for the KDF (key derivation function) family in System.Security.Cryptography,
 * excluding {@code Rfc2898DeriveBytes} (covered separately in {@link DotNetRfc2898DeriveBytes}).
 *
 * <p>Classes covered:
 *
 * <ul>
 *   <li>{@code HKDF} — RFC 5869 HMAC-based Extract-and-Expand KDF. Static-only class (no
 *       constructor / no instance): {@code HKDF.Extract(...)}, {@code HKDF.Expand(...)}, {@code
 *       HKDF.DeriveKey(...)} (each with a {@code byte[]} and a {@code Span}-based overload).
 *   <li>{@code SP800108HmacCounterKdf} — NIST SP 800-108 HMAC counter-mode KDF (KBKDF). Both
 *       constructor-based ({@code new SP800108HmacCounterKdf(key, hashAlgorithm)} + instance-method
 *       {@code DeriveKey}/{@code DeriveBytes}) and a fully static one-shot overload ({@code
 *       SP800108HmacCounterKdf.DeriveBytes(key, hashAlgorithm, label, context, length)} — no
 *       instance required).
 *   <li>{@code PasswordDeriveBytes} — legacy PBKDF1 extension (per the official API reference:
 *       "This class uses an extension of the PBKDF1 algorithm"). Constructor-based, with instance
 *       methods {@code GetBytes(int)} (marked {@code Obsolete} since .NET Core, still detectable
 *       source) and {@code CryptDeriveKey(string, string, int, byte[])}.
 * </ul>
 *
 * <p><b>Modeling decision — why HKDF/SP800108's static overloads are top-level rules, not depending
 * rules:</b> the Batch 3 pattern established in {@link DotNetECDiffieHellman} (a creation rule for
 * the object, with derive-operations as depending rules attached to it, translated to the generic
 * {@code KeyDerivation} functionality node) assumes there is an object instance to track between
 * "creation" and "operation". {@code HKDF} has no such instance — every method is {@code static},
 * and a single static call (e.g. {@code HKDF.DeriveKey(...)}) is both the "creation" and the
 * "operation" at once, with nothing to chain afterwards. The same is true for {@code
 * SP800108HmacCounterKdf.DeriveBytes(...)}, which is static and self-contained (unlike its sibling
 * instance methods). For these static, self-contained calls this file follows the {@code
 * Rfc2898DeriveBytes} idiom instead: the call is captured directly as a top-level {@code
 * ValueActionFactory} mapping straight to the KDF algorithm model node ({@code HKDF} / {@code
 * KDFCounter}), exactly like {@code new Rfc2898DeriveBytes(...)} maps directly to {@code PBKDF2}
 * with no intermediate {@code KeyDerivation} functionality wrapper — because the class itself *is*
 * the KDF, unlike {@code ECDiffieHellman} which is a general-purpose key-agreement primitive that
 * only sometimes derives a key.
 *
 * <p>Where an actual object instance *is* tracked ({@code SP800108HmacCounterKdf}'s constructor +
 * instance {@code DeriveKey}, and {@code PasswordDeriveBytes}'s constructor + instance {@code
 * GetBytes}/{@code CryptDeriveKey}), the Batch 3 pattern is reused as instructed: each derive
 * operation is a depending rule capturing {@code ValueActionFactory<>(<method name>)} under its own
 * {@code KeyContext} "kind", dispatched in {@code CSharpKeyContextTranslator} to the generic {@code
 * KeyDerivation} functionality node — mirroring {@code AES_GENERATE_KEY}/{@code AES_GENERATE_IV} in
 * {@link DotNetAES} (an operation captured as a child of an already-identified algorithm) more
 * closely than the ECDH case, since here the parent node is already a concrete KDF algorithm, not
 * an ambiguous key-agreement primitive.
 *
 * <p>As with every other file in this rule set, the ANTLR4-based C# engine cannot resolve parameter
 * types (see {@code CSharpLanguageTranslation}), so all overloads that only differ by {@code
 * byte[]} vs. {@code ReadOnlySpan<byte>}/{@code Span<byte>}, {@code string} vs. {@code
 * ReadOnlySpan<char>}, or the presence of an output-buffer parameter are collapsed into a single
 * {@code withAnyParameters()} rule per method name. The {@code HashAlgorithmName} parameter that
 * several of these methods take (e.g. {@code HashAlgorithmName.SHA256}) is not decoded into a
 * digest child node — consistent with {@code DotNetECDsa}/{@code DotNetECDiffieHellman}, which
 * leave the same parameter opaque on {@code SignData}/{@code DeriveKeyFromHash}, since only
 * literals and bare identifiers are readable by the engine (see {@code CSharpTreeConverter}), not
 * static member-access expressions like {@code HashAlgorithmName.SHA256}.
 *
 * <p><b>Known gap — {@code SP800108HmacCounterKdf.DeriveBytes} (instance overload):</b> only the
 * instance {@code DeriveKey} overloads are modeled as depending rules; the instance {@code
 * DeriveBytes} overloads (which take the label/context/hash-algorithm again, redundantly with the
 * constructor) exist per the API reference but are not separately covered here — {@code DeriveKey}
 * already exercises the same depending-rule path and this avoids an unnecessary near-duplicate rule
 * for a method that behaves identically for detection purposes (an opaque {@code
 * withAnyParameters()} call site). Not a gap in coverage of the class's cryptographic identity or
 * of the "a key was derived" signal — only a granularity choice, called out here rather than
 * decided silently.
 */
@SuppressWarnings("java:S1192")
public final class DotNetKeyDerivation {

    private DotNetKeyDerivation() {
        // nothing
    }

    // =========================================================================
    // HKDF — static-only class, no instance. Each static method is its own
    // top-level rule (see class javadoc "Modeling decision").
    // =========================================================================

    // HKDF.Extract(hashAlgorithmName, ikm, salt) / Extract(hashAlgorithmName, ikm, salt, prk)
    private static final IDetectionRule<CSharpTree> HKDF_EXTRACT =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes("HKDF")
                    .forMethods("Extract")
                    .shouldBeDetectedAs(new ValueActionFactory<>("HKDF"))
                    .withAnyParameters()
                    .buildForContext(new KeyContext(Map.of("kind", "KDF_HKDF")))
                    .inBundle(() -> "DotNet")
                    .withoutDependingDetectionRules();

    // HKDF.Expand(hashAlgorithmName, prk, outputLength, info) / Expand(..., output, info)
    private static final IDetectionRule<CSharpTree> HKDF_EXPAND =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes("HKDF")
                    .forMethods("Expand")
                    .shouldBeDetectedAs(new ValueActionFactory<>("HKDF"))
                    .withAnyParameters()
                    .buildForContext(new KeyContext(Map.of("kind", "KDF_HKDF")))
                    .inBundle(() -> "DotNet")
                    .withoutDependingDetectionRules();

    // HKDF.DeriveKey(hashAlgorithmName, ikm, outputLength, salt, info) — full Extract+Expand
    private static final IDetectionRule<CSharpTree> HKDF_DERIVE_KEY =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes("HKDF")
                    .forMethods("DeriveKey")
                    .shouldBeDetectedAs(new ValueActionFactory<>("HKDF"))
                    .withAnyParameters()
                    .buildForContext(new KeyContext(Map.of("kind", "KDF_HKDF")))
                    .inBundle(() -> "DotNet")
                    .withoutDependingDetectionRules();

    // =========================================================================
    // SP800108HmacCounterKdf — instance derive-operation depending rules, reusing the Batch 3
    // KeyDerivation pattern (see class javadoc).
    // =========================================================================

    // kdf.DeriveKey(label, context, keyLengthBytes) — instance method, all overloads
    // (byte[]/ReadOnlySpan<byte>/ReadOnlySpan<char>/string label+context, Int32/Span<byte> output)
    private static final IDetectionRule<CSharpTree> SP800108_DERIVE_KEY =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes(MethodMatcher.ANY)
                    .forMethods("DeriveKey")
                    .shouldBeDetectedAs(new ValueActionFactory<>("DeriveKey"))
                    .withAnyParameters()
                    .buildForContext(new KeyContext(Map.of("kind", "KDF_SP800108_DERIVE_KEY")))
                    .inBundle(() -> "DotNet")
                    .withoutDependingDetectionRules();

    private static final List<IDetectionRule<CSharpTree>> SP800108_DEPENDING_RULES =
            List.of(SP800108_DERIVE_KEY);

    // new SP800108HmacCounterKdf(key, hashAlgorithmName) — byte[] or ReadOnlySpan<byte> key
    private static final IDetectionRule<CSharpTree> SP800108_CTOR =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes("SP800108HmacCounterKdf")
                    .forMethods("<init>")
                    .shouldBeDetectedAs(new ValueActionFactory<>("SP800108"))
                    .withAnyParameters()
                    .buildForContext(new KeyContext(Map.of("kind", "KDF_SP800108")))
                    .inBundle(() -> "DotNet")
                    .withDependingDetectionRules(SP800108_DEPENDING_RULES);

    // SP800108HmacCounterKdf.DeriveBytes(key, hashAlgorithmName, label, context, keyLengthBytes) —
    // fully static one-shot overload, no instance required (see class javadoc "Modeling decision").
    private static final IDetectionRule<CSharpTree> SP800108_STATIC_DERIVE_BYTES =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes("SP800108HmacCounterKdf")
                    .forMethods("DeriveBytes")
                    .shouldBeDetectedAs(new ValueActionFactory<>("SP800108"))
                    .withAnyParameters()
                    .buildForContext(new KeyContext(Map.of("kind", "KDF_SP800108")))
                    .inBundle(() -> "DotNet")
                    .withoutDependingDetectionRules();

    // =========================================================================
    // PasswordDeriveBytes — legacy PBKDF1 extension. Constructor-based, with instance
    // derive-operation depending rules reusing the Batch 3 KeyDerivation pattern.
    // =========================================================================

    // pdb.GetBytes(cb) — Obsolete since .NET Core, still valid/detectable legacy source
    private static final IDetectionRule<CSharpTree> PDB_GET_BYTES =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes(MethodMatcher.ANY)
                    .forMethods("GetBytes")
                    .shouldBeDetectedAs(new ValueActionFactory<>("GetBytes"))
                    .withAnyParameters()
                    .buildForContext(new KeyContext(Map.of("kind", "KDF_PDB_GET_BYTES")))
                    .inBundle(() -> "DotNet")
                    .withoutDependingDetectionRules();

    // pdb.CryptDeriveKey(algName, algHashName, keySize, rgbIV)
    private static final IDetectionRule<CSharpTree> PDB_CRYPT_DERIVE_KEY =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes(MethodMatcher.ANY)
                    .forMethods("CryptDeriveKey")
                    .shouldBeDetectedAs(new ValueActionFactory<>("CryptDeriveKey"))
                    .withAnyParameters()
                    .buildForContext(new KeyContext(Map.of("kind", "KDF_PDB_CRYPT_DERIVE_KEY")))
                    .inBundle(() -> "DotNet")
                    .withoutDependingDetectionRules();

    private static final List<IDetectionRule<CSharpTree>> PDB_DEPENDING_RULES =
            List.of(PDB_GET_BYTES, PDB_CRYPT_DERIVE_KEY);

    // new PasswordDeriveBytes(password, salt[, hashName, iterations][, cspParams]) — 8
    // constructor overloads (password as string or byte[]; optional hashName/iterations;
    // optional CspParameters), all collapsed via withAnyParameters().
    private static final IDetectionRule<CSharpTree> PASSWORD_DERIVE_BYTES_CTOR =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes("PasswordDeriveBytes")
                    .forMethods("<init>")
                    .shouldBeDetectedAs(new ValueActionFactory<>("PBKDF1"))
                    .withAnyParameters()
                    .buildForContext(new KeyContext(Map.of("kind", "KDF_PASSWORD_DERIVE_BYTES")))
                    .inBundle(() -> "DotNet")
                    .withDependingDetectionRules(PDB_DEPENDING_RULES);

    @Nonnull
    public static List<IDetectionRule<CSharpTree>> rules() {
        return List.of(
                HKDF_EXTRACT,
                HKDF_EXPAND,
                HKDF_DERIVE_KEY,
                SP800108_CTOR,
                SP800108_STATIC_DERIVE_BYTES,
                PASSWORD_DERIVE_BYTES_CTOR);
    }
}
