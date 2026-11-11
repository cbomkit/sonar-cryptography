/*
 * Sonar Cryptography Plugin
 * Copyright (C) 2026 PQCA
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
import com.ibm.engine.model.context.ProtocolContext;
import com.ibm.engine.model.factory.CipherSuiteFactory;
import com.ibm.engine.model.factory.ValueActionFactory;
import com.ibm.engine.rule.DetectionRuleSet;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import java.util.List;
import java.util.Map;
import javax.annotation.Nonnull;

/**
 * The cipher suites a TLS connection is allowed to negotiate.
 *
 * <p>{@code CipherSuitesPolicy} is the only place in .NET where an application names cipher suites
 * directly, and it names them as themselves: the members of {@code TlsCipherSuite} are spelled
 * exactly like the IANA registry entries, so {@code TlsCipherSuite.TLS_AES_256_GCM_SHA384} resolves
 * through the project's existing {@code CipherSuiteMapper} into the key exchange, the cipher and
 * the digest it is made of, with its two-byte identifier. Everywhere else .NET speaks only of
 * protocol versions and leaves the suite choice to the platform.
 *
 * <p>The suites arrive as the elements of the collection passed to the constructor. Reading them
 * needed a change in the C# engine: a braced initializer used to resolve to its element *count* for
 * every asking factory, so this list could only ever have produced the number 2. The engine now
 * branches the way the Java engine always has — a {@code SizeFactory} gets the length, everything
 * else gets the values.
 *
 * <p>The finding is a {@code TLS} protocol with the suites beneath it, rather than bare suites at
 * the top level. A cipher suite is not a thing on its own; it is what a TLS handshake agreed on,
 * and the C# reorganizer -- unlike the Java one -- does not wrap a loose suite in its protocol.
 *
 * <p>Platform note worth knowing when reading a CBOM that contains these: the class is annotated
 * {@code [UnsupportedOSPlatform("windows")]} and {@code ("android")}. It configures the
 * OpenSSL-backed TLS stack and throws a {@code PlatformNotSupportedException} on the
 * Schannel-backed one, so a suite list detected here is in force on Linux and macOS and inert on
 * Windows. That is a property of the code, not of the detection, and the right place to say it is
 * here rather than in the inventory.
 */
public final class DotNetCipherSuites extends DetectionRuleSet<CSharpTree> {

    /**
     * {@code new CipherSuitesPolicy(new[] { TlsCipherSuite.TLS_AES_256_GCM_SHA384, ... })}.
     *
     * <p>One constructor, one parameter, so there is no overload to tell apart. The parameter is
     * declared {@code ANY} because the argument may be an array, a collection expression, a {@code
     * List}, or anything else {@code IEnumerable<TlsCipherSuite>} accepts; what makes the rule
     * precise is not the parameter type but that only a name the IANA table knows becomes a suite.
     * A member of some other enum, or a suite name that does not exist, resolves to nothing.
     */
    private static final IDetectionRule<CSharpTree> CIPHER_SUITES_POLICY =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes("CipherSuitesPolicy")
                    .forMethods("<init>")
                    .shouldBeDetectedAs(new ValueActionFactory<>("TLS"))
                    .withMethodParameter(MethodMatcher.ANY)
                    .shouldBeDetectedAs(new CipherSuiteFactory<>())
                    .asChildOfParameterWithId(-1)
                    .buildForContext(new ProtocolContext(Map.of("kind", "TLS")))
                    .inBundle(() -> "DotNetTls")
                    .withoutDependingDetectionRules();

    @Nonnull
    @Override
    protected List<IDetectionRule<CSharpTree>> buildRules() {
        return List.of(CIPHER_SUITES_POLICY);
    }
}
