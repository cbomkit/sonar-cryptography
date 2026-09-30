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
package com.ibm.plugin.rules.detection.openssl.legacy;

import com.ibm.engine.model.context.KeyAgreementContext;
import com.ibm.engine.model.context.KeyContext;
import com.ibm.engine.model.context.PrivateKeyContext;
import com.ibm.engine.model.context.SignatureContext;
import com.ibm.engine.model.factory.ValueActionFactory;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import com.ibm.plugin.rules.detection.Memoize;
import com.sonar.cxx.sslr.api.AstNode;
import java.util.List;
import java.util.Map;
import java.util.function.Supplier;
import java.util.stream.Stream;
import javax.annotation.Nonnull;

/**
 * Detection rules for OpenSSL legacy EC APIs.
 *
 * <p>These rules detect direct EC operations using the legacy (pre-EVP) APIs from ec.h. These APIs
 * are deprecated but still widely used in existing codebases.
 *
 * <p>Covers: EC key management, ECDSA signatures, ECDH key agreement, EC group/curve, EC point
 * operations
 */
@SuppressWarnings("java:S1192")
public final class OpenSSLLegacyEc {

    private static final String BUNDLE = "OpenSSL";

    // ECDSA Signature functions

    private static final IDetectionRule<AstNode> ECDSA_SIGN =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("ECDSA_sign")
                    .shouldBeDetectedAs(new ValueActionFactory<>("ECDSA-SIGN"))
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .buildForContext(new SignatureContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> ECDSA_DO_SIGN =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("ECDSA_do_sign")
                    .shouldBeDetectedAs(new ValueActionFactory<>("ECDSA-SIGN"))
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .buildForContext(new SignatureContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> ECDSA_SIGN_EX =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("ECDSA_sign_ex")
                    .shouldBeDetectedAs(new ValueActionFactory<>("ECDSA-SIGN"))
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .buildForContext(new SignatureContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> ECDSA_DO_SIGN_EX =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("ECDSA_do_sign_ex")
                    .shouldBeDetectedAs(new ValueActionFactory<>("ECDSA-SIGN"))
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .buildForContext(new SignatureContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    // Key Generation

    private static final IDetectionRule<AstNode> EC_KEY_NEW_BY_CURVE_NAME =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EC_KEY_new_by_curve_name")
                    .withMethodParameter("*")
                    .shouldBeDetectedAs(new OpenSSLNidLookupFactory())
                    .buildForContext(new KeyContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EC_KEY_NEW_BY_CURVE_NAME_EX =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EC_KEY_new_by_curve_name_ex")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .shouldBeDetectedAs(new OpenSSLNidLookupFactory())
                    .buildForContext(new KeyContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EC_GROUP_NEW_BY_CURVE_NAME =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EC_GROUP_new_by_curve_name")
                    .withMethodParameter("*")
                    .shouldBeDetectedAs(new OpenSSLNidLookupFactory())
                    .buildForContext(new KeyContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EC_GROUP_NEW_BY_CURVE_NAME_EX =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EC_GROUP_new_by_curve_name_ex")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .shouldBeDetectedAs(new OpenSSLNidLookupFactory())
                    .buildForContext(new KeyContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    // A group on a curve given by its parameters, not by name: EC_GROUP_new_curve_GFp(p, a, b, ctx)
    // and EC_GROUP_new_curve_GF2m(p, a, b, ctx), EC_GROUP_new_from_params(params, libctx, propq),
    // EC_GROUP_new_from_ecparameters(params) and EC_GROUP_new_from_ecpkparameters(params)
    private static final List<IDetectionRule<AstNode>> EC_GROUP_NEW_CUSTOM_CURVE =
            List.of(
                    customCurve(4, "EC_GROUP_new_curve_GFp", "EC_GROUP_new_curve_GF2m"),
                    customCurve(3, "EC_GROUP_new_from_params"),
                    customCurve(
                            1,
                            "EC_GROUP_new_from_ecparameters",
                            "EC_GROUP_new_from_ecpkparameters"));

    @Nonnull
    private static IDetectionRule<AstNode> customCurve(
            int parameterCount, @Nonnull String... functions) {
        IDetectionRule.ParametersFactoryBuilder<AstNode> parameters =
                new DetectionRuleBuilder<AstNode>()
                        .createDetectionRule()
                        .forObjectTypes("*")
                        .forMethods(functions)
                        .shouldBeDetectedAs(new ValueActionFactory<>("EC"))
                        .withMethodParameter("*");
        for (int i = 1; i < parameterCount; i++) {
            parameters = parameters.withMethodParameter("*");
        }
        return parameters
                .buildForContext(new KeyContext())
                .inBundle(() -> BUNDLE)
                .withoutDependingDetectionRules();
    }

    // EC_KEY_set_group(key, group): the curve of the key is the curve of the group
    private static final IDetectionRule<AstNode> EC_KEY_SET_GROUP =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EC_KEY_set_group")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .addDependingDetectionRules(
                            Stream.concat(
                                            Stream.of(
                                                    EC_GROUP_NEW_BY_CURVE_NAME,
                                                    EC_GROUP_NEW_BY_CURVE_NAME_EX),
                                            EC_GROUP_NEW_CUSTOM_CURVE.stream())
                                    .toList())
                    .buildForContext(new KeyContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    // EC_KEY_generate_key(key): a key is generated on the curve of key, set when the key is
    // created for a named curve or by EC_KEY_set_group
    private static final IDetectionRule<AstNode> EC_KEY_GENERATE_KEY =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EC_KEY_generate_key")
                    .shouldBeDetectedAs(new ValueActionFactory<>("EC"))
                    .withMethodParameter("*")
                    .addDependingDetectionRules(
                            List.of(
                                    EC_KEY_NEW_BY_CURVE_NAME,
                                    EC_KEY_NEW_BY_CURVE_NAME_EX,
                                    EC_KEY_SET_GROUP))
                    .buildForContext(new PrivateKeyContext(Map.of()))
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    // Key Agreement functions

    private static final IDetectionRule<AstNode> ECDH_COMPUTE_KEY =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("ECDH_compute_key")
                    .shouldBeDetectedAs(new ValueActionFactory<>("ECDH"))
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .buildForContext(new KeyAgreementContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private OpenSSLLegacyEc() {
        // private
    }

    @Nonnull
    private static List<IDetectionRule<AstNode>> buildRules() {
        return Stream.concat(
                        Stream.of(
                                // ECDSA Signatures
                                ECDSA_SIGN,
                                ECDSA_SIGN_EX,
                                ECDSA_DO_SIGN,
                                ECDSA_DO_SIGN_EX,
                                // Keys and groups
                                EC_KEY_NEW_BY_CURVE_NAME,
                                EC_KEY_NEW_BY_CURVE_NAME_EX,
                                EC_GROUP_NEW_BY_CURVE_NAME,
                                EC_GROUP_NEW_BY_CURVE_NAME_EX,
                                EC_KEY_GENERATE_KEY,
                                // Key Agreement
                                ECDH_COMPUTE_KEY),
                        // Groups on custom curves
                        EC_GROUP_NEW_CUSTOM_CURVE.stream())
                .toList();
    }

    private static final Supplier<List<IDetectionRule<AstNode>>> RULES =
            Memoize.of(OpenSSLLegacyEc::buildRules);

    @Nonnull
    public static List<IDetectionRule<AstNode>> rules() {
        return RULES.get();
    }
}
