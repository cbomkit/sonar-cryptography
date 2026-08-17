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
public final class OAuthAuthRules {

    private OAuthAuthRules() {
        // nothing
    }

    private static final IDetectionRule<Tree> SPRING_JWT_DECODER =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes(
                            "org.springframework.security.oauth2.jwt.JwtDecoder",
                            "org.springframework.security.oauth2.jwt.ReactiveJwtDecoder")
                    .forMethods("decode")
                    .shouldBeDetectedAs(new ValueActionFactory<>("OAUTH"))
                    .withAnyParameters()
                    .buildForContext(new AuthContext(AuthContext.Kind.OAUTH))
                    .inBundle(() -> "Auth")
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<Tree> SPRING_OPAQUE_INTROSPECTOR =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes(
                            "org.springframework.security.oauth2.server.resource.introspection.OpaqueTokenIntrospector")
                    .forMethods("introspect")
                    .shouldBeDetectedAs(new ValueActionFactory<>("OAUTH"))
                    .withAnyParameters()
                    .buildForContext(new AuthContext(AuthContext.Kind.OAUTH))
                    .inBundle(() -> "Auth")
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<Tree> NIMBUS_ID_TOKEN_VALIDATOR =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("com.nimbusds.openid.connect.sdk.validators.IDTokenValidator")
                    .forMethods("validate")
                    .shouldBeDetectedAs(new ValueActionFactory<>("OAUTH"))
                    .withAnyParameters()
                    .buildForContext(new AuthContext(AuthContext.Kind.OAUTH))
                    .inBundle(() -> "Auth")
                    .withoutDependingDetectionRules();

    @Nonnull
    public static List<IDetectionRule<Tree>> rules() {
        return List.of(SPRING_JWT_DECODER, SPRING_OPAQUE_INTROSPECTOR, NIMBUS_ID_TOKEN_VALIDATOR);
    }
}
