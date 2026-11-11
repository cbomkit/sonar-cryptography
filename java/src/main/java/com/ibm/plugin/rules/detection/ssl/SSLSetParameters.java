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
package com.ibm.plugin.rules.detection.ssl;

import com.ibm.engine.model.context.ProtocolContext;
import com.ibm.engine.rule.DetectionRuleSet;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.RuleSets;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;
import javax.annotation.Nonnull;
import org.sonar.plugins.java.api.tree.Tree;

public final class SSLSetParameters extends DetectionRuleSet<Tree> {

    private static final IDetectionRule<Tree> SSL_PARAMETERS =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    // All three JSSE endpoints declare setSSLParameters, and the Java frontend
                    // matches the exact declared type, so naming only the server socket left the
                    // client socket and the SSLEngine uncovered.
                    .forObjectExactTypes(
                            "javax.net.ssl.SSLServerSocket",
                            "javax.net.ssl.SSLSocket",
                            "javax.net.ssl.SSLEngine")
                    .forMethods("setSSLParameters")
                    .withMethodParameter("javax.net.ssl.SSLParameters")
                    .addDependingDetectionRules(
                            Stream.of(
                                            RuleSets.rulesOf(SSLParametersSetProtocols.class)
                                                    .stream(),
                                            RuleSets.rulesOf(SSLParametersSetCipherSuites.class)
                                                    .stream())
                                    .flatMap(i -> i)
                                    .toList())
                    .buildForContext(new ProtocolContext(Map.of("kind", "TLS")))
                    .inBundle(() -> "SSL")
                    .withoutDependingDetectionRules();

    @Nonnull
    @Override
    protected List<IDetectionRule<Tree>> buildRules() {
        return List.of(SSL_PARAMETERS);
    }
}
