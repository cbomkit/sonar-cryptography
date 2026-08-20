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
 * Detection rules for the HMAC family, and for {@code MACTripleDES}, in {@code
 * System.Security.Cryptography}.
 *
 * <p>Classes covered:
 *
 * <ul>
 *   <li>{@code HMACMD5}, {@code HMACSHA1}, {@code HMACSHA256}, {@code HMACSHA384}, {@code
 *       HMACSHA512} — standard HMAC implementations, available across all .NET versions.
 *   <li>{@code HMACRIPEMD160} — like {@code RIPEMD160}/{@code RIPEMD160Managed} (see {@link
 *       DotNetSHA}), this class only ever existed in .NET Framework (documented up to
 *       netframework-4.8.1 only; no netcoreapp/net5+ monikers). It is detected here for legacy .NET
 *       Framework source code.
 *   <li>{@code HMACSHA3_256}, {@code HMACSHA3_384}, {@code HMACSHA3_512} — introduced in .NET 8,
 *       same platform-dependent status ({@code IsSupported}, intentionally not modeled — consistent
 *       with how other {@code IsSupported} properties are ignored across this rule set) as their
 *       {@code SHA3_*} digest counterparts in {@link DotNetSHA3}.
 *   <li>{@code MACTripleDES} — <b>not</b> an {@code HMAC} subclass. Per the official API reference,
 *       it derives directly from {@code KeyedHashAlgorithm} (the same base class {@code HMAC}
 *       itself derives from) and computes a TripleDES/CBC-keyed MAC, not a hash-based one. It only
 *       ever existed in .NET Framework (documented up to netframework-4.8.1 only), same legacy
 *       status as {@code HMACRIPEMD160}. It is included in this file because it is part of the .NET
 *       "keyed hash"/MAC surface that this batch covers, not because it shares an implementation
 *       with HMAC.
 * </ul>
 *
 * <p>The detected value encodes the full class name (e.g., {@code "HMACSHA256"}) so the translator
 * ({@code CSharpMacContextTranslator}) can resolve the inner hash algorithm. {@code MACTripleDES}
 * is translated separately, by reusing the existing {@code DESede} algorithm model reinterpreted
 * "as" a {@code Mac} kind — the same idiom already used elsewhere in this codebase to reinterpret
 * {@code DESede} as a {@code KeyWrap} (see {@code JcaCipherMapper}/{@code BcWrapperMapper}, and the
 * {@code DESede(Class, DESede)} "as-kind" constructor). Note that {@code MACTripleDES} is a plain
 * TripleDES-keyed CBC-MAC construction, which is a distinct (and cryptographically weaker)
 * construction from the NIST {@code CMAC}/OMAC1 standard also present in this codebase's model — it
 * is therefore intentionally <b>not</b> modeled as {@code CMAC}.
 *
 * <p><b>Known gap — the {@code Key} property setter:</b> none of these classes' {@code Key}
 * property (inherited from {@code HMAC}/{@code KeyedHashAlgorithm}) is modeled as a depending rule
 * here. A grep across every {@code DotNet*.java} rule file in this module found no existing
 * precedent for capturing a raw {@code byte[]} property value: unlike {@code Aes.KeySize} (an
 * {@code int} literal, capturable via {@code KeySizeFactory}, see {@link DotNetAES}), {@code
 * hmac.Key} is virtually always assigned from a variable in realistic code (e.g. {@code hmac.Key =
 * keyBytes;}), and per the engine's documented limitations ({@code CSharpSymbol}/{@code
 * CSharpTreeConverter}), only literals and bare identifiers are read — the byte contents/length of
 * a variable cannot be resolved this way. Recording only that "a key was set" (with no value) would
 * require inventing a new marker/translation with no established counterpart elsewhere in this
 * codebase, so this is left as a documented, explicit gap (TODO) rather than a guessed modeling
 * decision.
 */
// TODO: the `Key` property setter (`hmac.Key = ...`) is not modeled as a depending rule — see
// class javadoc "Known gap" section above for the rationale.
@SuppressWarnings("java:S1192")
public final class DotNetHMAC {

    private DotNetHMAC() {
        // nothing
    }

    private static IDetectionRule<CSharpTree> hmacRule(String className) {
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

    // new MACTripleDES() / new MACTripleDES(byte[] key) / new MACTripleDES(string algName, byte[]
    // key)
    // Not an HMAC subclass (see class javadoc); modeled as a distinct MAC value, resolved to
    // DESede-as-Mac by CSharpMacContextTranslator.
    private static final IDetectionRule<CSharpTree> MAC_TRIPLE_DES =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes("MACTripleDES")
                    .forMethods("<init>")
                    .shouldBeDetectedAs(new ValueActionFactory<>("MACTRIPLEDES"))
                    .withAnyParameters()
                    .buildForContext(new MacContext())
                    .inBundle(() -> "DotNet")
                    .withDependingDetectionRules(List.of());

    @Nonnull
    public static List<IDetectionRule<CSharpTree>> rules() {
        return List.of(
                hmacRule("HMACSHA1"),
                hmacRule("HMACSHA256"),
                hmacRule("HMACSHA384"),
                hmacRule("HMACSHA512"),
                hmacRule("HMACMD5"),
                hmacRule("HMACRIPEMD160"),
                hmacRule("HMACSHA3_256"),
                hmacRule("HMACSHA3_384"),
                hmacRule("HMACSHA3_512"),
                MAC_TRIPLE_DES);
    }
}
