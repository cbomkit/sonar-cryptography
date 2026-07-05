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
import com.ibm.engine.model.factory.ProtocolFactory;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import com.ibm.plugin.rules.detection.Memoize;
import java.util.List;
import java.util.function.Supplier;
import javax.annotation.Nonnull;
import org.sonar.plugins.java.api.tree.Tree;

@SuppressWarnings("java:S1192")
public final class SSLContext {

    private static final IDetectionRule<Tree> SSLContext_1 =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectExactTypes("javax.net.ssl.SSLContext")
                    .forMethods("getInstance")
                    .withMethodParameter("java.lang.String")
                    .shouldBeDetectedAs(new ProtocolFactory<>())
                    .buildForContext(new ProtocolContext(ProtocolContext.Kind.TLS))
                    .inBundle(() -> "SSL")
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<Tree> SSLContext_2 =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectExactTypes("javax.net.ssl.SSLContext")
                    .forMethods("getInstance")
                    .withMethodParameter("java.lang.String")
                    .shouldBeDetectedAs(new ProtocolFactory<>())
                    .withMethodParameter("java.lang.String")
                    .buildForContext(new ProtocolContext(ProtocolContext.Kind.TLS))
                    .inBundle(() -> "SSL")
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<Tree> SSLContext_3 =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectExactTypes("javax.net.ssl.SSLContext")
                    .forMethods("getInstance")
                    .withMethodParameter("java.lang.String")
                    .shouldBeDetectedAs(new ProtocolFactory<>())
                    .withMethodParameter("java.security.Provider")
                    .buildForContext(new ProtocolContext(ProtocolContext.Kind.TLS))
                    .inBundle(() -> "SSL")
                    .withoutDependingDetectionRules();

    private SSLContext() {
        // nothing
    }

    private static final Supplier<List<IDetectionRule<Tree>>> RULES =
            Memoize.of(SSLContext::buildRules);

    @Nonnull
    public static List<IDetectionRule<Tree>> rules() {
        return RULES.get();
    }

    @Nonnull
    private static List<IDetectionRule<Tree>> buildRules() {
        return List.of(SSLContext_1, SSLContext_2, SSLContext_3);
    }
}
