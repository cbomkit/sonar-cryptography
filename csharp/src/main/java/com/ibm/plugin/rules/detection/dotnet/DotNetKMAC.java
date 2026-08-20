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
import com.ibm.engine.model.context.MacContext;
import com.ibm.engine.model.factory.ValueActionFactory;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import java.util.List;
import javax.annotation.Nonnull;

/**
 * Detection rules for the KMAC family in {@code System.Security.Cryptography}.
 *
 * <p>Classes covered (a recent addition to .NET, specified by NIST SP 800-185; documented for the
 * net-9.0/net-10.0/net-11.0 monikers — verified against the official API reference, see {@code
 * IsSupported}, a platform-availability check intentionally not modeled here, consistent with how
 * other {@code IsSupported} properties are ignored across this rule set):
 *
 * <ul>
 *   <li>{@code Kmac128} — fixed-output KMAC128 MAC
 *   <li>{@code Kmac256} — fixed-output KMAC256 MAC
 *   <li>{@code KmacXof128} — extendable-output (XOF) variant of KMAC128
 *   <li>{@code KmacXof256} — extendable-output (XOF) variant of KMAC256
 * </ul>
 *
 * <p>All four classes are sealed, implement {@code IDisposable}, and share the identical
 * constructor shape: {@code Kmac128(byte[] key, byte[]? customizationString = default)} (plus a
 * {@code ReadOnlySpan<Byte>} overload with the same parameter roles). Both the {@code key} and
 * {@code customizationString} arguments are matched with {@code .withAnyParameters()}: per the
 * engine's documented limitations ({@code CSharpLanguageTranslation} — no parameter-type checking;
 * {@code CSharpTreeConverter} — only bare literals/identifiers are read), a {@code byte[]} key
 * argument is virtually always a variable reference in realistic code and its contents/length
 * cannot be resolved this way. This mirrors the exact precedent set for the {@code HMAC*} family in
 * {@link DotNetHMAC} (see that class's "Known gap" javadoc for the equivalent {@code Key} property
 * case).
 *
 * <p><b>Mapper reuse:</b> all four classes translate to the existing {@code
 * com.ibm.mapper.model.algorithms.KMAC} model class (already used by the BouncyCastle {@code KMAC}
 * mapper — see {@code BcMacMapper}/{@code BcDigestMapper}), via its {@code KMAC(int
 * parameterSetIdentifier, DetectionLocation)} constructor: {@code KMAC(128, ...)} for {@code
 * Kmac128}/{@code KmacXof128}, {@code KMAC(256, ...)} for {@code Kmac256}/{@code KmacXof256}. No
 * new mapper model class was introduced for this batch.
 *
 * <p><b>Known modeling gap — fixed vs. XOF variant collapse:</b> the existing {@code KMAC} mapper
 * model has no concept distinguishing the fixed-output KMAC128/256 construction (domain-separated
 * internally with {@code right_encode(L)}, for a specific requested output length {@code L}) from
 * the true extendable-output KMACXOF128/256 construction (domain-separated with {@code
 * right_encode(0)}, per NIST SP 800-185) — its constructor always wraps a plain {@code CSHAKE}
 * child regardless of which .NET class triggered detection. Consequently {@code Kmac128} and {@code
 * KmacXof128} both translate to an identical node ({@code asString() == "KMAC128"}), and likewise
 * for the 256-bit pair. The raw detected value string ({@code "KMAC128"} vs. {@code "KMACXOF128"},
 * i.e. {@link com.ibm.engine.model.ValueAction#asString()} before translation) still distinguishes
 * the four .NET classes at the detection-store level, so this is a translation-layer precision gap,
 * not a detection gap — it is documented here rather than fixed by inventing a new mapper model
 * class. See {@code CSharpMacContextTranslator} for the translation switch.
 *
 * <p><b>Why the output-length parameter is not modeled as a depending rule:</b> like {@code
 * Shake128}/{@code Shake256} in {@link DotNetSHA3}, all four KMAC classes expose {@code
 * GetHashAndReset(int outputLength)}/{@code GetCurrentHash(int outputLength)}/{@code HashData(...,
 * int outputLength, ...)} overloads (in addition to span-based overloads) whose length argument is
 * an arbitrary per-call output-size request, not additional information about the algorithm itself
 * — the "128"/"256" in the class name is the security-strength parameter, already captured by the
 * creation rule. No depending rules are attached for these methods, or for {@code
 * AppendData}/{@code Verify}/{@code VerifyCurrentHash}/{@code VerifyHashAndReset}/{@code Clone},
 * consistent with the same convention already established for {@code Shake128}/{@code Shake256} and
 * the {@code HMAC*} family (see {@link DotNetHMAC}), where no depending rules are attached for the
 * equivalent hash-computation methods either.
 */
@SuppressWarnings("java:S1192")
public final class DotNetKMAC {

    private DotNetKMAC() {
        // nothing
    }

    // new Kmac128(key) / new Kmac128(key, customizationString) — and the KmacXof128/256, Kmac256
    // siblings. Both constructor overloads (byte[], byte[]) and (ReadOnlySpan<Byte>,
    // ReadOnlySpan<Byte>) are covered by withAnyParameters().
    private static IDetectionRule<CSharpTree> kmacRule(String className) {
        return new DetectionRuleBuilder<CSharpTree>()
                .createDetectionRule()
                .forObjectTypes(className)
                .forMethods("<init>")
                .shouldBeDetectedAs(new ValueActionFactory<>(className.toUpperCase()))
                .withAnyParameters()
                .buildForContext(new MacContext())
                .inBundle(() -> "DotNet")
                .withDependingDetectionRules(List.of());
    }

    @Nonnull
    public static List<IDetectionRule<CSharpTree>> rules() {
        return List.of(
                kmacRule("Kmac128"),
                kmacRule("Kmac256"),
                kmacRule("KmacXof128"),
                kmacRule("KmacXof256"));
    }
}
