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
package com.ibm.plugin.rules.detection.nodecrypto;

import static com.ibm.engine.detection.MethodMatcher.ANY;

import com.ibm.engine.model.context.ProtocolContext;
import com.ibm.engine.model.factory.CipherSuiteFactory;
import com.ibm.engine.model.factory.ProtocolFactory;
import com.ibm.engine.model.factory.ValueActionFactory;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import com.ibm.plugin.javascript.api.Tree;
import com.ibm.plugin.rules.detection.Memoize;
import java.util.List;
import java.util.function.Supplier;
import javax.annotation.Nonnull;

/**
 * Detection rules for Node.js {@code tls} module APIs.
 *
 * <p>Detects usage of:
 *
 * <ul>
 *   <li>tls.createSecureContext(options) - creates a TLS secure context
 *   <li>tls.connect(options, callback) - establishes a TLS client connection
 *   <li>tls.createServer(options, callback) - creates a TLS server
 * </ul>
 */
@SuppressWarnings("java:S1192")
public final class NodeCryptoTLS {

    private NodeCryptoTLS() {
        // private
    }

    private static final IDetectionRule<Tree> SECURE_CONTEXT =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("tls.SecureContext", "SecureContext")
                    .forConstructor()
                    .shouldBeDetectedAs(new ValueActionFactory<>("TLS"))
                    .withMethodParameter("object")
                    .buildForContext(new ProtocolContext(ProtocolContext.Kind.TLS))
                    .inBundle(() -> NodeCryptoTypes.BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<Tree> CREATE_SECURE_CONTEXT =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes(NodeCryptoTypes.TLS, NodeCryptoTypes.NODE_TLS)
                    .forMethods("createSecureContext")
                    .shouldBeDetectedAs(new ValueActionFactory<>("TLS"))
                    .withMethodParameter("object")
                    .buildForContext(new ProtocolContext(ProtocolContext.Kind.TLS))
                    .inBundle(() -> NodeCryptoTypes.BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<Tree> CONNECT =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes(NodeCryptoTypes.TLS, NodeCryptoTypes.NODE_TLS)
                    .forMethods("connect")
                    .withMethodParameter("object")
                    .addDependingDetectionRules(List.of(CREATE_SECURE_CONTEXT))
                    .withMethodParameter(ANY)
                    .buildForContext(new ProtocolContext(ProtocolContext.Kind.TLS))
                    .inBundle(() -> NodeCryptoTypes.BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<Tree> CREATE_SERVER =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes(NodeCryptoTypes.TLS, NodeCryptoTypes.NODE_TLS)
                    .forMethods("createServer")
                    .shouldBeDetectedAs(new ValueActionFactory<>("TLS"))
                    .withMethodParameter("object")
                    .shouldBeDetectedAs(new CipherSuiteFactory<>())
                    .asChildOfParameterWithId(-1)
                    .withMethodParameter(ANY)
                    .buildForContext(new ProtocolContext(ProtocolContext.Kind.TLS))
                    .inBundle(() -> NodeCryptoTypes.BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<Tree> TLS_OPTIONS =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes(NodeCryptoTypes.TLS, NodeCryptoTypes.NODE_TLS)
                    .forMethods("connect")
                    .withMethodParameter("object")
                    .shouldBeDetectedAs(new ProtocolFactory<>())
                    .withMethodParameter(ANY)
                    .buildForContext(new ProtocolContext(ProtocolContext.Kind.TLS))
                    .inBundle(() -> NodeCryptoTypes.BUNDLE)
                    .withoutDependingDetectionRules();

    private static final Supplier<List<IDetectionRule<Tree>>> RULES =
            Memoize.of(NodeCryptoTLS::buildRules);

    @Nonnull
    public static List<IDetectionRule<Tree>> rules() {
        return RULES.get();
    }

    @Nonnull
    private static List<IDetectionRule<Tree>> buildRules() {
        return List.of(SECURE_CONTEXT, CREATE_SECURE_CONTEXT, CONNECT, CREATE_SERVER, TLS_OPTIONS);
    }
}
