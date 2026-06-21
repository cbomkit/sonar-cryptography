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
package com.ibm.plugin.rules.detection.rustcrypto;

import com.ibm.engine.model.context.ProtocolContext;
import com.ibm.engine.model.factory.ValueActionFactory;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import java.util.List;
import javax.annotation.Nonnull;
import org.sonar.plugins.go.api.Tree;

/**
 * Detection rules for Rust's rustls TLS library.
 *
 * <p>Detects usage of:
 *
 * <ul>
 *   <li>rustls::ClientConfig::builder - creates a TLS client configuration builder
 *   <li>rustls::ServerConfig::builder - creates a TLS server configuration builder
 *   <li>rustls::ClientConfig::builder_with_protocol_versions - creates a TLS client config with
 *       specific protocol versions
 *   <li>rustls::ServerConfig::builder_with_protocol_versions - creates a TLS server config with
 *       specific protocol versions
 *   <li>rustls::ClientConnection::new - creates a new TLS client connection
 *   <li>rustls::ServerConnection::new - creates a new TLS server connection
 * </ul>
 */
@SuppressWarnings("java:S1192")
public final class RustlsTLS {

    private RustlsTLS() {
        // private
    }

    // rustls::ClientConfig::builder() -> ConfigBuilder<ClientConfig, WantsVerifier>
    // Creates a TLS client configuration builder with default protocol versions
    private static final IDetectionRule<Tree> CLIENT_CONFIG_BUILDER =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("rustls::ClientConfig")
                    .forMethods("builder")
                    .shouldBeDetectedAs(new ValueActionFactory<>("TLS"))
                    .withoutParameters()
                    .buildForContext(new ProtocolContext(ProtocolContext.Kind.TLS))
                    .inBundle(() -> "RustlsCrypto")
                    .withoutDependingDetectionRules();

    // rustls::ServerConfig::builder() -> ConfigBuilder<ServerConfig, WantsVerifier>
    // Creates a TLS server configuration builder with default protocol versions
    private static final IDetectionRule<Tree> SERVER_CONFIG_BUILDER =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("rustls::ServerConfig")
                    .forMethods("builder")
                    .shouldBeDetectedAs(new ValueActionFactory<>("TLS"))
                    .withoutParameters()
                    .buildForContext(new ProtocolContext(ProtocolContext.Kind.TLS))
                    .inBundle(() -> "RustlsCrypto")
                    .withoutDependingDetectionRules();

    // rustls::ClientConfig::builder_with_protocol_versions(
    //     versions: &[&'static SupportedProtocolVersion]
    // ) -> ConfigBuilder<ClientConfig, WantsVerifier>
    // Creates a TLS client configuration builder with specific protocol versions
    private static final IDetectionRule<Tree> CLIENT_CONFIG_BUILDER_WITH_VERSIONS =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("rustls::ClientConfig")
                    .forMethods("builder_with_protocol_versions")
                    .shouldBeDetectedAs(new ValueActionFactory<>("TLS"))
                    .withMethodParameter("&[&SupportedProtocolVersion]")
                    .buildForContext(new ProtocolContext(ProtocolContext.Kind.TLS))
                    .inBundle(() -> "RustlsCrypto")
                    .withoutDependingDetectionRules();

    // rustls::ServerConfig::builder_with_protocol_versions(
    //     versions: &[&'static SupportedProtocolVersion]
    // ) -> ConfigBuilder<ServerConfig, WantsVerifier>
    // Creates a TLS server configuration builder with specific protocol versions
    private static final IDetectionRule<Tree> SERVER_CONFIG_BUILDER_WITH_VERSIONS =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("rustls::ServerConfig")
                    .forMethods("builder_with_protocol_versions")
                    .shouldBeDetectedAs(new ValueActionFactory<>("TLS"))
                    .withMethodParameter("&[&SupportedProtocolVersion]")
                    .buildForContext(new ProtocolContext(ProtocolContext.Kind.TLS))
                    .inBundle(() -> "RustlsCrypto")
                    .withoutDependingDetectionRules();

    // rustls::ClientConnection::new(
    //     config: Arc<ClientConfig>, name: ServerName<'_>
    // ) -> Result<Self, Error>
    // Creates a new TLS client connection with the given configuration
    private static final IDetectionRule<Tree> CLIENT_CONNECTION_NEW =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("rustls::ClientConnection")
                    .forMethods("new")
                    .shouldBeDetectedAs(new ValueActionFactory<>("TLS"))
                    .withMethodParameter("Arc<ClientConfig>")
                    .addDependingDetectionRules(
                            List.of(CLIENT_CONFIG_BUILDER, CLIENT_CONFIG_BUILDER_WITH_VERSIONS))
                    .withMethodParameter("ServerName")
                    .buildForContext(new ProtocolContext(ProtocolContext.Kind.TLS))
                    .inBundle(() -> "RustlsCrypto")
                    .withoutDependingDetectionRules();

    // rustls::ServerConnection::new(
    //     config: Arc<ServerConfig>
    // ) -> Result<Self, Error>
    // Creates a new TLS server connection with the given configuration
    private static final IDetectionRule<Tree> SERVER_CONNECTION_NEW =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("rustls::ServerConnection")
                    .forMethods("new")
                    .shouldBeDetectedAs(new ValueActionFactory<>("TLS"))
                    .withMethodParameter("Arc<ServerConfig>")
                    .addDependingDetectionRules(
                            List.of(SERVER_CONFIG_BUILDER, SERVER_CONFIG_BUILDER_WITH_VERSIONS))
                    .buildForContext(new ProtocolContext(ProtocolContext.Kind.TLS))
                    .inBundle(() -> "RustlsCrypto")
                    .withoutDependingDetectionRules();

    @Nonnull
    public static List<IDetectionRule<Tree>> rules() {
        return List.of(
                CLIENT_CONFIG_BUILDER,
                SERVER_CONFIG_BUILDER,
                CLIENT_CONFIG_BUILDER_WITH_VERSIONS,
                SERVER_CONFIG_BUILDER_WITH_VERSIONS,
                CLIENT_CONNECTION_NEW,
                SERVER_CONNECTION_NEW);
    }
}
