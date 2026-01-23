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
import com.ibm.engine.model.factory.ValueActionFactory;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import java.util.List;
import javax.annotation.Nonnull;
import org.sonar.plugins.go.api.Tree;

/**
 * Detection rules for Go's crypto/tls version constants.
 *
 * <p>Detects usage of TLS version constants:
 *
 * <ul>
 *   <li>tls.VersionSSL30 (0x0300) - SSLv3 (deprecated)
 *   <li>tls.VersionTLS10 (0x0301) - TLS 1.0
 *   <li>tls.VersionTLS11 (0x0302) - TLS 1.1
 *   <li>tls.VersionTLS12 (0x0303) - TLS 1.2
 *   <li>tls.VersionTLS13 (0x0304) - TLS 1.3
 * </ul>
 *
 * <p>These rules are used as depending detection rules for TLS entry point functions to detect
 * which TLS versions are configured via MinVersion/MaxVersion in tls.Config.
 */
public final class GoCryptoTLSVersions {

    private GoCryptoTLSVersions() {
        // private
    }

    private static final IDetectionRule<Tree> VERSION_SSL30 =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("crypto/tls")
                    .forMethods("VersionSSL30")
                    .shouldBeDetectedAs(new ValueActionFactory<>("SSLv3"))
                    .withoutParameters()
                    .buildForContext(new ProtocolContext(ProtocolContext.Kind.TLS))
                    .inBundle(() -> "GoCrypto")
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<Tree> VERSION_TLS10 =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("crypto/tls")
                    .forMethods("VersionTLS10")
                    .shouldBeDetectedAs(new ValueActionFactory<>("TLSv1.0"))
                    .withoutParameters()
                    .buildForContext(new ProtocolContext(ProtocolContext.Kind.TLS))
                    .inBundle(() -> "GoCrypto")
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<Tree> VERSION_TLS11 =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("crypto/tls")
                    .forMethods("VersionTLS11")
                    .shouldBeDetectedAs(new ValueActionFactory<>("TLSv1.1"))
                    .withoutParameters()
                    .buildForContext(new ProtocolContext(ProtocolContext.Kind.TLS))
                    .inBundle(() -> "GoCrypto")
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<Tree> VERSION_TLS12 =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("crypto/tls")
                    .forMethods("VersionTLS12")
                    .shouldBeDetectedAs(new ValueActionFactory<>("TLSv1.2"))
                    .withoutParameters()
                    .buildForContext(new ProtocolContext(ProtocolContext.Kind.TLS))
                    .inBundle(() -> "GoCrypto")
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<Tree> VERSION_TLS13 =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("crypto/tls")
                    .forMethods("VersionTLS13")
                    .shouldBeDetectedAs(new ValueActionFactory<>("TLSv1.3"))
                    .withoutParameters()
                    .buildForContext(new ProtocolContext(ProtocolContext.Kind.TLS))
                    .inBundle(() -> "GoCrypto")
                    .withoutDependingDetectionRules();

    @Nonnull
    public static List<IDetectionRule<Tree>> rules() {
        return List.of(VERSION_SSL30, VERSION_TLS10, VERSION_TLS11, VERSION_TLS12, VERSION_TLS13);
    }
}
