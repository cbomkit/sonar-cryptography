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
package com.ibm.plugin.rules.detection.openssl.keygen;

import com.ibm.engine.model.context.KeyContext;
import com.ibm.engine.model.factory.AlgorithmFactory;
import com.ibm.engine.model.factory.ValueActionFactory;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import com.ibm.plugin.rules.detection.Memoize;
import com.ibm.plugin.rules.detection.openssl.digest.OpenSSLNameCanonicalizerFactory;
import com.ibm.plugin.rules.detection.openssl.legacy.OpenSSLNidLookupFactory;
import com.sonar.cxx.sslr.api.AstNode;
import java.util.List;
import java.util.function.Supplier;
import java.util.stream.Stream;
import javax.annotation.Nonnull;

/**
 * Detection rules for OpenSSL EVP key/parameter generation.
 *
 * <p>RSA and DSA key/paramgen setters live in their own {@code OpenSSLEvpKeyGen<Family>} classes;
 * this class holds EC key generation, the generic EVP_PKEY keygen/generate/paramgen detection,
 * KEYMGMT fetch, and group/curve selection setters, and aggregates every family's rules in {@link
 * #rules()}.
 */
@SuppressWarnings("java:S1192")
public final class OpenSSLEvpKeyGen {

    private static final String BUNDLE = "OpenSSL";

    private static final IDetectionRule<AstNode> EVP_EC_PARAMGEN_CURVE_NID =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_PKEY_CTX_set_ec_paramgen_curve_nid")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .shouldBeDetectedAs(new OpenSSLNidLookupFactory())
                    .buildForContext(new KeyContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_PKEY_KEYGEN =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_PKEY_keygen")
                    .shouldBeDetectedAs(new ValueActionFactory<>("KEYGEN"))
                    .withAnyParameters()
                    .buildForContext(new KeyContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_PKEY_KEYGEN_INIT =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_PKEY_keygen_init")
                    .shouldBeDetectedAs(new ValueActionFactory<>("KEYGEN-INIT"))
                    .withAnyParameters()
                    .buildForContext(new KeyContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_PKEY_GENERATE =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_PKEY_generate")
                    .shouldBeDetectedAs(new ValueActionFactory<>("KEYGEN"))
                    .withAnyParameters()
                    .buildForContext(new KeyContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_PKEY_Q_KEYGEN =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_PKEY_Q_keygen")
                    .shouldBeDetectedAs(new ValueActionFactory<>("KEYGEN"))
                    .withAnyParameters()
                    .buildForContext(new KeyContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_PKEY_PARAMGEN =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_PKEY_paramgen")
                    .shouldBeDetectedAs(new ValueActionFactory<>("PARAMGEN"))
                    .withAnyParameters()
                    .buildForContext(new KeyContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_PKEY_PARAMGEN_INIT =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_PKEY_paramgen_init")
                    .shouldBeDetectedAs(new ValueActionFactory<>("PARAMGEN"))
                    .withAnyParameters()
                    .buildForContext(new KeyContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_KEYMGMT_FETCH =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_KEYMGMT_fetch")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .shouldBeDetectedAs(new AlgorithmFactory<>())
                    .withMethodParameter("*")
                    .buildForContext(new KeyContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_PKEY_CTX_SET_GROUP_NAME =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_PKEY_CTX_set_group_name")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .shouldBeDetectedAs(
                            new OpenSSLNameCanonicalizerFactory(
                                    OpenSSLNameCanonicalizerFactory.GROUP_NAMES))
                    .buildForContext(new KeyContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_PKEY_CTX_SET_EC_PARAM_ENC =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_PKEY_CTX_set_ec_param_enc")
                    .shouldBeDetectedAs(new ValueActionFactory<>("EC-PARAM-ENC"))
                    .withAnyParameters()
                    .buildForContext(new KeyContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private OpenSSLEvpKeyGen() {
        // private
    }

    @Nonnull
    private static List<IDetectionRule<AstNode>> buildRules() {
        return Stream.of(
                        OpenSSLEvpKeyGenRsa.rules().stream(),
                        OpenSSLEvpKeyGenDsa.rules().stream(),
                        directRules().stream())
                .flatMap(i -> i)
                .toList();
    }

    @Nonnull
    private static List<IDetectionRule<AstNode>> directRules() {
        return List.of(
                // EC Key Generation
                EVP_EC_PARAMGEN_CURVE_NID,
                // EVP_PKEY_keygen (generic keygen detection)
                EVP_PKEY_KEYGEN,
                EVP_PKEY_KEYGEN_INIT,
                // Generate / paramgen
                EVP_PKEY_GENERATE,
                EVP_PKEY_Q_KEYGEN,
                EVP_PKEY_PARAMGEN,
                EVP_PKEY_PARAMGEN_INIT,
                // KEYMGMT fetch
                EVP_KEYMGMT_FETCH,
                // Group / curve selection setters
                EVP_PKEY_CTX_SET_GROUP_NAME,
                EVP_PKEY_CTX_SET_EC_PARAM_ENC);
    }

    private static final Supplier<List<IDetectionRule<AstNode>>> RULES =
            Memoize.of(OpenSSLEvpKeyGen::buildRules);

    @Nonnull
    public static List<IDetectionRule<AstNode>> rules() {
        return RULES.get();
    }
}
