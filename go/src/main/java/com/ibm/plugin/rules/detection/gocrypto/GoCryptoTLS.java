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
package com.ibm.plugin.rules.detection.gocrypto;

import com.ibm.engine.model.context.ProtocolContext;
import com.ibm.engine.model.factory.CipherSuiteFactory;
import com.ibm.engine.model.factory.ProtocolFactory;
import com.ibm.engine.model.factory.ValueActionFactory;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import java.util.List;
import javax.annotation.Nonnull;
import org.sonar.plugins.go.api.Tree;

/**
 * Detection rules for Go's crypto/tls package.
 *
 * <p>Detects usage of:
 *
 * <ul>
 *   <li>tls.Dial(network, addr, config) - dials a TLS connection
 *   <li>tls.DialWithDialer(dialer, network, addr, config) - dials with custom dialer
 *   <li>tls.Listen(network, laddr, config) - listens for TLS connections
 *   <li>tls.NewListener(inner, config) - wraps a listener with TLS
 *   <li>tls.Server(conn, config) - creates a TLS server connection
 *   <li>tls.Client(conn, config) - creates a TLS client connection
 * </ul>
 *
 * <p>The *tls.Config parameter has depending detection rules for cipher suites
 * (GoCryptoTLSCipherSuites) and TLS versions (GoCryptoTLSVersions). When a cipher suite is
 * identified, the CipherSuiteMapper maps the IANA name to structured nodes.
 */
@SuppressWarnings("java:S1192")
public final class GoCryptoTLS {

    private GoCryptoTLS() {
        // private
    }

    private static final IDetectionRule<Tree> CONFIG =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("crypto/tls.Config")
                    .forConstructor()
                    .shouldBeDetectedAs(new ValueActionFactory<>("TLS"))
                    .withMethodParameter("CipherSuites")
                    .shouldBeDetectedAs(new CipherSuiteFactory<>())
                    .asChildOfParameterWithId(-1)
                    .withMethodParameter("MinVersion")
                    .shouldBeDetectedAs(new ProtocolFactory<>())
                    .asChildOfParameterWithId(-1)
                    .withMethodParameter("MaxVersion")
                    .shouldBeDetectedAs(new ProtocolFactory<>())
                    .asChildOfParameterWithId(-1)
                    .buildForContext(new ProtocolContext(ProtocolContext.Kind.TLS))
                    .inBundle(() -> "GoCrypto")
                    .withoutDependingDetectionRules();

    // tls.Dial(network, addr string, config *Config) (*Conn, error)
    private static final IDetectionRule<Tree> DIAL =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("crypto/tls")
                    .forMethods("Dial")
                    .withMethodParameter("string") // network
                    .withMethodParameter("string") // addr
                    .withMethodParameter("*tls.Config") // config
                    .addDependingDetectionRules(List.of(CONFIG))
                    .buildForContext(new ProtocolContext(ProtocolContext.Kind.TLS))
                    .inBundle(() -> "GoCrypto")
                    .withoutDependingDetectionRules();

    // tls.DialWithDialer(dialer *net.Dialer, network, addr string, config *Config) (*Conn, error)
    private static final IDetectionRule<Tree> DIAL_WITH_DIALER =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("crypto/tls")
                    .forMethods("DialWithDialer")
                    .withMethodParameter("*net.Dialer") // dialer
                    .withMethodParameter("string") // network
                    .withMethodParameter("string") // addr
                    .withMethodParameter("*tls.Config") // config
                    .addDependingDetectionRules(List.of(CONFIG))
                    .buildForContext(new ProtocolContext(ProtocolContext.Kind.TLS))
                    .inBundle(() -> "GoCrypto")
                    .withoutDependingDetectionRules();

    // tls.Listen(network, laddr string, config *Config) (net.Listener, error)
    private static final IDetectionRule<Tree> LISTEN =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("crypto/tls")
                    .forMethods("Listen")
                    .withMethodParameter("string") // network
                    .withMethodParameter("string") // laddr
                    .withMethodParameter("*tls.Config") // config
                    .addDependingDetectionRules(List.of(CONFIG))
                    .buildForContext(new ProtocolContext(ProtocolContext.Kind.TLS))
                    .inBundle(() -> "GoCrypto")
                    .withoutDependingDetectionRules();

    // tls.NewListener(inner net.Listener, config *Config) net.Listener
    private static final IDetectionRule<Tree> NEW_LISTENER =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("crypto/tls")
                    .forMethods("NewListener")
                    .withMethodParameter("net.Listener") // inner
                    .withMethodParameter("*tls.Config") // config
                    .addDependingDetectionRules(List.of(CONFIG))
                    .buildForContext(new ProtocolContext(ProtocolContext.Kind.TLS))
                    .inBundle(() -> "GoCrypto")
                    .withoutDependingDetectionRules();

    // tls.Server(conn net.Conn, config *Config) *Conn
    private static final IDetectionRule<Tree> SERVER =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("crypto/tls")
                    .forMethods("Server")
                    .withMethodParameter("net.Conn") // conn
                    .withMethodParameter("*tls.Config") // config
                    .addDependingDetectionRules(List.of(CONFIG))
                    .buildForContext(new ProtocolContext(ProtocolContext.Kind.TLS))
                    .inBundle(() -> "GoCrypto")
                    .withoutDependingDetectionRules();

    // tls.Client(conn net.Conn, config *Config) *Conn
    private static final IDetectionRule<Tree> CLIENT =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("crypto/tls")
                    .forMethods("Client")
                    .withMethodParameter("net.Conn") // conn
                    .withMethodParameter("*tls.Config") // config
                    .addDependingDetectionRules(List.of(CONFIG))
                    .buildForContext(new ProtocolContext(ProtocolContext.Kind.TLS))
                    .inBundle(() -> "GoCrypto")
                    .withoutDependingDetectionRules();

    @Nonnull
    public static List<IDetectionRule<Tree>> rules() {
        return List.of(DIAL, DIAL_WITH_DIALER, LISTEN, NEW_LISTENER, SERVER, CLIENT);
    }
}
