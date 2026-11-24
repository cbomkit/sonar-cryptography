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
import com.ibm.engine.model.factory.ProtocolFactory;
import com.ibm.engine.model.factory.ValueActionFactory;
import com.ibm.engine.rule.DetectionRuleSet;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import java.util.List;
import java.util.Map;
import javax.annotation.Nonnull;

/**
 * .NET transport security: {@code SslStream} and the properties that configure it.
 *
 * <p>The Java side has read {@code SSLContext}, {@code SSLParameters.setProtocols} and {@code
 * setEnabledCipherSuites} for a long time; C# had nothing of the kind, so every .NET service that
 * speaks TLS was invisible to a bill of materials. These rules close that, and they are what makes
 * the DICOM rules say something: fo-dicom's {@code DefaultTlsInitiator} and {@code
 * DefaultTlsAcceptor} configure the handshake through a {@code Protocols} property, so a DICOM
 * association and the TLS version it offers are read by two rule sets that meet in the same {@code
 * TLS} component.
 *
 * <p>Three shapes carry a version in real code, measured across MailKit, RabbitMQ's .NET client,
 * Npgsql and fo-dicom:
 *
 * <ul>
 *   <li>A property assignment, by far the most common: {@code EnabledSslProtocols =
 *       SslProtocols.None} inside an options object, {@code client.SslProtocols =
 *       SslProtocols.Tls12 | SslProtocols.Tls13}, {@code cf.Ssl.Version = SslProtocols.Tls12}. Both
 *       a plain assignment and an object initializer arrive as a synthetic {@code set_<Property>}
 *       call.
 *   <li>The handshake itself, {@code AuthenticateAsClient} and its three siblings, which take the
 *       versions as an argument in their long overload.
 *   <li>The legacy global switch {@code ServicePointManager.SecurityProtocol}.
 * </ul>
 *
 * <p>The property names split into two groups, and the split is what keeps this honest. {@code
 * EnabledSslProtocols}, {@code SslProtocols} and {@code DefaultSslProtocols} can mean nothing else,
 * so their rule accepts any argument and reads whatever name it resolves to. {@code Protocols},
 * {@code Version} and {@code SecurityProtocol} are ordinary words that any class may use, so their
 * rules additionally require the argument to be a member of the enum itself -- {@code
 * SslProtocols.Tls12} resolves to that type, a string or a number does not, and the rule then
 * refuses the call rather than reporting a protocol named after someone's version field.
 *
 * <p>A flags combination resolves to both members, so {@code SslProtocols.Tls12 |
 * SslProtocols.Tls13} states two versions rather than none. {@code SslProtocols.None} means the
 * platform chooses, which is reported as TLS without a version -- that is exactly what is known.
 */
@SuppressWarnings("java:S1192")
public final class DotNetTls extends DetectionRuleSet<CSharpTree> {

    private static final String TLS = "TLS";
    private static final String SSL_PROTOCOLS = "SslProtocols";

    @Nonnull
    private static ProtocolContext tlsContext() {
        return new ProtocolContext(Map.of("kind", TLS));
    }

    /**
     * Properties whose name can only mean the TLS versions in force.
     *
     * <p>The receiver is any type, because a synthetic setter carries the variable it was written
     * on rather than its type, and because these property names belong to half a dozen unrelated
     * classes -- {@code SslClientAuthenticationOptions}, {@code HttpClientHandler}, MailKit's
     * {@code MailService}, {@code ServicePointManager}. The name alone is the guard.
     */
    private static final IDetectionRule<CSharpTree> SET_UNAMBIGUOUS_PROTOCOLS =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes(MethodMatcher.ANY)
                    .forMethods(
                            "set_EnabledSslProtocols",
                            "set_SslProtocols",
                            "set_DefaultSslProtocols")
                    .withMethodParameter(MethodMatcher.ANY)
                    .shouldBeDetectedAs(new ProtocolFactory<>())
                    .buildForContext(tlsContext())
                    .inBundle(() -> "DotNetTls")
                    .withoutDependingDetectionRules();

    /**
     * Properties whose name is an ordinary word, so the argument has to prove itself.
     *
     * <p>{@code Protocols} is fo-dicom's, {@code Version} is RabbitMQ's {@code SslOption}. Both are
     * names a class may use for anything, so the parameter is named rather than positional, which
     * brings the strict side of the type check into play: a member access reports {@code
     * SslProtocols} as its type and passes, while a string or a number is refused because the enum
     * is a recognized named type. The positional form would not do -- the matcher there asks only
     * whether an argument <em>might</em> fit, and a string might fit anything.
     */
    private static final IDetectionRule<CSharpTree> SET_AMBIGUOUS_PROTOCOLS =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes(MethodMatcher.ANY)
                    .forMethods("set_Protocols", "set_Version")
                    .withNamedMethodParameter("value", SSL_PROTOCOLS)
                    .shouldBeDetectedAs(new ProtocolFactory<>())
                    .buildForContext(tlsContext())
                    .inBundle(() -> "DotNetTls")
                    .withoutDependingDetectionRules();

    /**
     * {@code ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12} — the global
     * switch.
     */
    private static final IDetectionRule<CSharpTree> SET_SECURITY_PROTOCOL =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes(MethodMatcher.ANY)
                    .forMethods("set_SecurityProtocol")
                    .withNamedMethodParameter("value", "SecurityProtocolType")
                    .shouldBeDetectedAs(new ProtocolFactory<>())
                    .buildForContext(tlsContext())
                    .inBundle(() -> "DotNetTls")
                    .withoutDependingDetectionRules();

    /**
     * The handshake itself, client side.
     *
     * <p>The call states that TLS is spoken at all, whichever overload is used, and the long
     * overload names the versions. MailKit calls the options overload and fo-dicom the long one, so
     * both occur; the short ones contribute the protocol without a version, which is what is known
     * about them.
     */
    /**
     * {@code listenOptions.UseHttps(...)} -- ASP.NET Core's server-side TLS.
     *
     * <p>The counterpart of the handshake rules on the serving side. A Kestrel endpoint set up with
     * {@code UseHttps} terminates TLS, and that is the whole statement the call makes: every
     * overload means the same thing, and none of them names a version, so the arity is left open
     * and nothing is read out of the arguments. The method name carries the match on its own --
     * unlike {@code Connect} or {@code set_Enabled}, {@code UseHttps} cannot plausibly mean
     * anything but HTTPS, which is why an {@code ANY} receiver is safe here.
     *
     * <p>The versions are not in the call. Kestrel takes them from {@code
     * HttpsConnectionAdapterOptions.SslProtocols}, which the protocol setters above already read,
     * and a configuration that leaves them alone gets the operating system's defaults -- which is
     * exactly what a TLS component without a version says.
     */
    private static final IDetectionRule<CSharpTree> USE_HTTPS =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes(MethodMatcher.ANY)
                    .forMethods("UseHttps")
                    .shouldBeDetectedAs(new ValueActionFactory<>(TLS))
                    .withAnyParameters()
                    .buildForContext(new ProtocolContext(Map.of("kind", TLS)))
                    .inBundle(() -> "DotNetTls")
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<CSharpTree> AUTHENTICATE_AS_CLIENT =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes(MethodMatcher.ANY)
                    .forMethods("AuthenticateAsClient", "AuthenticateAsClientAsync")
                    .shouldBeDetectedAs(new ValueActionFactory<>(TLS))
                    .withNamedMethodParameter("targetHost", MethodMatcher.ANY)
                    .withOptionalNamedMethodParameter("clientCertificates", MethodMatcher.ANY)
                    .withOptionalNamedMethodParameter("enabledSslProtocols", SSL_PROTOCOLS)
                    .shouldBeDetectedAs(new ProtocolFactory<>())
                    .asChildOfParameterWithId(-1)
                    .withOptionalNamedMethodParameter("checkCertificateRevocation", "bool")
                    .buildForContext(tlsContext())
                    .inBundle(() -> "DotNetTls")
                    .withoutDependingDetectionRules();

    /** The handshake, server side: the certificate comes first and a client-auth flag follows. */
    private static final IDetectionRule<CSharpTree> AUTHENTICATE_AS_SERVER =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes(MethodMatcher.ANY)
                    .forMethods("AuthenticateAsServer", "AuthenticateAsServerAsync")
                    .shouldBeDetectedAs(new ValueActionFactory<>(TLS))
                    .withNamedMethodParameter("serverCertificate", MethodMatcher.ANY)
                    .withOptionalNamedMethodParameter("clientCertificateRequired", "bool")
                    .withOptionalNamedMethodParameter("enabledSslProtocols", SSL_PROTOCOLS)
                    .shouldBeDetectedAs(new ProtocolFactory<>())
                    .asChildOfParameterWithId(-1)
                    .withOptionalNamedMethodParameter("checkCertificateRevocation", "bool")
                    .buildForContext(tlsContext())
                    .inBundle(() -> "DotNetTls")
                    .withoutDependingDetectionRules();

    @Nonnull
    @Override
    protected List<IDetectionRule<CSharpTree>> buildRules() {
        return List.of(
                SET_UNAMBIGUOUS_PROTOCOLS,
                SET_AMBIGUOUS_PROTOCOLS,
                SET_SECURITY_PROTOCOL,
                AUTHENTICATE_AS_CLIENT,
                AUTHENTICATE_AS_SERVER,
                USE_HTTPS);
    }
}
