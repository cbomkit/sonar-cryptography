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
package com.ibm.plugin.rules.detection.openssl;

import com.ibm.engine.detection.MethodMatcher;
import com.ibm.engine.language.csharp.tree.CSharpTree;
import com.ibm.engine.model.context.ProtocolContext;
import com.ibm.engine.model.factory.CipherSuiteFactory;
import com.ibm.engine.model.factory.ParameterIdentifierFactory;
import com.ibm.engine.model.factory.ValueActionFactory;
import com.ibm.engine.rule.DetectionRuleSet;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;
import javax.annotation.Nonnull;

/**
 * OpenSSL's TLS configuration, as C# reaches it through P/Invoke.
 *
 * <p>Four calls carry the detail a bill of materials wants, and they are usually all four in the
 * same handful of lines:
 *
 * <pre>{@code
 * var ctx = Native.SSL_CTX_new(Native.TLS_client_method());
 * Native.SSL_CTX_set_min_proto_version(ctx, Ssl.TLS1_2_VERSION);
 * Native.SSL_CTX_set_cipher_list(ctx, "ECDHE-RSA-AES256-GCM-SHA384");
 * Native.SSL_CTX_set_ciphersuites(ctx, "TLS_AES_256_GCM_SHA384");
 * }</pre>
 *
 * <h2>The version</h2>
 *
 * <p>Three of those lines can state a version and they do not agree about how.
 *
 * <p>{@code SSL_CTX_new} takes an {@code SSL_METHOD *}. The modern methods ({@code TLS_method} and
 * its {@code SSLv23_} alias) are version-flexible and name no version at all; the deprecated {@code
 * TLSv1_2_method} family and {@code SSLv3_method} are version-locked and name one. Both are read
 * from the method function rather than from {@code SSL_CTX_new}, because the method is where the
 * version is written -- and because the argument is as often a handle held in a variable ({@code
 * SSL_CTX_new(sslMethod.Handle)}, which is openssl-net's own line) as it is an inline call. {@code
 * SSL_CTX_new} itself still reports an unversioned TLS, for the same reason {@code DotNetTls}'s
 * {@code UseHttps} rule does: the call is proof that this code terminates or opens a TLS
 * connection, and the version, when it is stated anywhere, arrives as a finding of its own on the
 * line that states it.
 *
 * <p>{@code SSL_CTX_set_min_proto_version} and its three siblings state a version outright, in
 * either of two spellings that both occur in P/Invoke code. A wrapper that keeps the constants as
 * members ({@code Ssl.TLS1_2_VERSION}) resolves to the member's name; one that declares them as C#
 * {@code const int} fields resolves through the constant to {@code 0x0303}. {@link OpenSslApi}
 * holds both, because the numbers are the TLS wire versions and are fixed by the RFCs. A {@code 0},
 * an unknown constant, or a version that arrives in a variable or a method parameter resolves to
 * nothing.
 *
 * <h2>Why {@code SSL_CTX_set_options} states no version</h2>
 *
 * <p>{@code SSL_CTX_set_options(ctx, SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_1)} is the older way to pin
 * a version, and it is read here only as "a TLS context is being configured". The names are
 * <em>not</em> turned into versions, and the reason is that they say the opposite of what they look
 * like: {@code SSL_OP_NO_TLSv1} means TLS 1.0 is refused. Reporting TLS 1.0 for that line would
 * invert the finding, which is the worst outcome this rule set can produce.
 *
 * <p>Inferring the enabled version from the disabled ones is not sound either. The set {@code
 * {NO_SSLv3, NO_TLSv1, NO_TLSv1_1}} leaves TLS 1.2 and TLS 1.3 enabled on an OpenSSL 1.1.1 or 3.x
 * build, TLS 1.2 alone on a 1.0.2 build, and nothing at all on a build compiled without TLS 1.2 --
 * the answer depends on the library the binary links against, which is not in the source. The
 * numeric form is refused for a second reason as well: the {@code SSL_OP_*} bit values were
 * reassigned when the options word became 64 bits in 1.1.0, so a C# {@code const} carrying {@code
 * 0x04000000} means {@code SSL_OP_NO_TLSv1} against one header and something else against another.
 *
 * <h2>The cipher selection</h2>
 *
 * <p>{@code SSL_CTX_set_cipher_list} takes an OpenSSL cipher-list expression for TLS 1.2 and below
 * and {@code SSL_CTX_set_ciphersuites} takes a colon-separated list of TLS 1.3 suite names. One
 * rule reads both: the translator splits on {@code :} and keeps the tokens that are suites, which
 * is the only guard that makes this safe. A list expression is not a list of suites -- {@code
 * "HIGH:!aNULL:!MD5"} and {@code "DEFAULT:@STRENGTH"} are selectors, {@code "-RC4"} and {@code
 * "+SHA"} are operators -- and the shared {@code CipherSuiteMapper} answers an unknown name with a
 * {@code CipherSuite} node named after the string rather than with nothing, so passing the string
 * through unchecked would put a cipher suite called {@code HIGH} in the CBOM. The translator
 * therefore consults {@code CipherSuiteMapper.findCipherSuite} first and drops every token that is
 * not a real suite.
 *
 * <p>No alias had to be added to the mapper for this: its suite table already carries OpenSSL's own
 * names ({@code openssl_name} in {@code mapper/ciphersuites.json}, 161 of them) and {@code
 * findCipherSuite} already tries them after the IANA name and the JSSE {@code SSL_} legacy
 * spelling. {@code "ECDHE-RSA-AES256-GCM-SHA384"} resolves to {@code
 * TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384} through that path, and the TLS 1.3 suites OpenSSL names
 * ({@code TLS_AES_256_GCM_SHA384} and friends) are IANA names already.
 */
public final class OpenSslTls extends DetectionRuleSet<CSharpTree> {

    /** Marks a call that proves a TLS endpoint without naming a version. */
    public static final String TLS = "TLS";

    /** Marks the action of an {@code SSL_METHOD}-returning function. See {@link OpenSslApi}. */
    public static final String SSL_METHOD = "SSL_METHOD";

    @Nonnull
    private static ProtocolContext context() {
        return new ProtocolContext(Map.of(OpenSslDetectionRules.CONTEXT_KEY, "TLS"));
    }

    /**
     * {@code SSL_CTX_new(method)} and {@code SSL_CTX_new_ex(libctx, propq, method)}.
     *
     * <p>The arity is left open because the two differ in it and both mean the same thing, and
     * nothing is read out of the arguments -- the method function is its own finding.
     */
    private static final IDetectionRule<CSharpTree> SSL_CTX_NEW =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes(MethodMatcher.ANY)
                    .forMethods("SSL_CTX_new", "SSL_CTX_new_ex")
                    .shouldBeDetectedAs(new ValueActionFactory<>(TLS))
                    .withAnyParameters()
                    .buildForContext(context())
                    .inBundle(() -> "OpenSsl")
                    .withoutDependingDetectionRules();

    /**
     * Every {@code const SSL_METHOD *<name>(void)} of {@code SSL_CTX_new(3)}, in one rule.
     *
     * <p>One rule rather than thirty, for the reason given on {@code OpenSslCipher}'s
     * cipher-function rule: the method name is the value, and the finding already carries it as its
     * location keyword.
     */
    /**
     * One rule per function, built in a loop from the same table the translator reads -- every
     * SSL_METHOD constructor OpenSSL ships, each carrying its own name as the action constant.
     * Written this way rather than as one rule over the whole name list so that the matched
     * function arrives as a value, which is how every other rule set in this project states what it
     * found; the alternative read the name back out of the detection location's keywords, a
     * coupling nothing else relies on.
     */
    @Nonnull
    private static List<IDetectionRule<CSharpTree>> ssl_methods() {
        final List<IDetectionRule<CSharpTree>> rules = new ArrayList<>();
        for (String function : OpenSslApi.sslMethodNames()) {
            rules.add(
                    new DetectionRuleBuilder<CSharpTree>()
                            .createDetectionRule()
                            .forObjectTypes(MethodMatcher.ANY)
                            .forMethods(function)
                            .shouldBeDetectedAs(new ValueActionFactory<>(function))
                            .withoutParameters()
                            .buildForContext(context())
                            .inBundle(() -> "OpenSsl")
                            .withoutDependingDetectionRules());
        }
        return List.copyOf(rules);
    }

    /**
     * {@code SSL_CTX_set_min_proto_version(ctx, version)} and its three siblings.
     *
     * <p>No action is declared, so the version the argument resolves to <em>is</em> the finding and
     * a call whose version cannot be resolved contributes nothing at all. Both the minimum and the
     * maximum are read the same way: each names a version that this endpoint speaks, which is what
     * the component records, and neither is a bound the CBOM model can express.
     *
     * <p>{@code ParameterIdentifierFactory} is the factory here because it is the only one that
     * carries a value through whether it resolved to a name or to a number, which is precisely the
     * two spellings these constants have in C#. The interpretation is the translator's, against the
     * closed set in {@link OpenSslApi}.
     */
    private static final IDetectionRule<CSharpTree> PROTO_VERSION =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes(MethodMatcher.ANY)
                    .forMethods(
                            "SSL_CTX_set_min_proto_version",
                            "SSL_CTX_set_max_proto_version",
                            "SSL_set_min_proto_version",
                            "SSL_set_max_proto_version")
                    .withMethodParameter(MethodMatcher.ANY) // ctx / ssl
                    .withMethodParameter("int") // version
                    .shouldBeDetectedAs(new ParameterIdentifierFactory<>())
                    .buildForContext(context())
                    .inBundle(() -> "OpenSsl")
                    .withoutDependingDetectionRules();

    /**
     * {@code SSL_CTX_set_cipher_list}, {@code SSL_CTX_set_ciphersuites} and their {@code SSL_*}
     * counterparts.
     *
     * <p>All four in one rule because the string is handled identically: split on {@code :}, keep
     * the tokens that are cipher suites. No action, so a string that names no suite -- a list
     * expression, an alias, or anything built at run time -- leaves the call unreported.
     */
    private static final IDetectionRule<CSharpTree> CIPHER_SELECTION =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes(MethodMatcher.ANY)
                    .forMethods(
                            "SSL_CTX_set_cipher_list",
                            "SSL_set_cipher_list",
                            "SSL_CTX_set_ciphersuites",
                            "SSL_set_ciphersuites")
                    .withMethodParameter(MethodMatcher.ANY) // ctx / ssl
                    .withMethodParameter("string") // str
                    .shouldBeDetectedAs(new CipherSuiteFactory<>())
                    .buildForContext(context())
                    .inBundle(() -> "OpenSsl")
                    .withoutDependingDetectionRules();

    /**
     * {@code SSL_CTX_set_options(ctx, options)} and {@code SSL_set_options(ssl, options)}.
     *
     * <p>Reports an unversioned TLS and reads nothing from the bitmask. See the class comment for
     * why the {@code SSL_OP_NO_*} flags are not turned into versions.
     */
    private static final IDetectionRule<CSharpTree> SET_OPTIONS =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes(MethodMatcher.ANY)
                    .forMethods("SSL_CTX_set_options", "SSL_set_options")
                    .shouldBeDetectedAs(new ValueActionFactory<>(TLS))
                    .withAnyParameters()
                    .buildForContext(context())
                    .inBundle(() -> "OpenSsl")
                    .withoutDependingDetectionRules();

    @Nonnull
    @Override
    protected List<IDetectionRule<CSharpTree>> buildRules() {
        return Stream.concat(
                        ssl_methods().stream(),
                        Stream.of(SSL_CTX_NEW, PROTO_VERSION, CIPHER_SELECTION, SET_OPTIONS))
                .toList();
    }
}
