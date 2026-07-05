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
package com.ibm.plugin.rules.detection.auth;

import com.ibm.engine.model.context.AuthContext;
import com.ibm.engine.model.factory.ValueActionFactory;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import java.util.List;
import javax.annotation.Nonnull;
import org.sonar.plugins.java.api.tree.Tree;

@SuppressWarnings("java:S1192")
public final class ApiKeyAuthRules {

    private ApiKeyAuthRules() {
        // nothing
    }

    private static final IDetectionRule<Tree> PAC4J_DIRECT_CLIENT =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes(
                            "org.pac4j.http.client.direct.HeaderClient",
                            "org.pac4j.http.client.direct.ParameterClient")
                    .forConstructor()
                    .shouldBeDetectedAs(new ValueActionFactory<>("API_KEY"))
                    .withAnyParameters()
                    .buildForContext(new AuthContext(AuthContext.Kind.API_KEY))
                    .inBundle(() -> "Auth")
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<Tree> SPRING_REQUEST_HEADER_FILTER =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes(
                            "org.springframework.security.web.authentication.preauth.RequestHeaderAuthenticationFilter")
                    .forConstructor()
                    .shouldBeDetectedAs(new ValueActionFactory<>("API_KEY"))
                    .withAnyParameters()
                    .buildForContext(new AuthContext(AuthContext.Kind.API_KEY))
                    .inBundle(() -> "Auth")
                    .withoutDependingDetectionRules();

    @Nonnull
    public static List<IDetectionRule<Tree>> rules() {
        return List.of(PAC4J_DIRECT_CLIENT, SPRING_REQUEST_HEADER_FILTER);
    }
}
