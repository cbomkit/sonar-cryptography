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
package com.ibm.plugin.rules.detection.openssl.rand;

import com.ibm.engine.model.context.CipherContext;
import com.ibm.engine.model.context.DigestContext;
import com.ibm.engine.model.context.PRNGContext;
import com.ibm.engine.model.factory.AlgorithmFactory;
import com.ibm.engine.model.factory.ValueActionFactory;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import com.ibm.plugin.rules.detection.Memoize;
import com.ibm.plugin.rules.detection.openssl.digest.OpenSSLNameCanonicalizerFactory;
import com.ibm.plugin.rules.detection.openssl.kdf.OpenSSLParamsScannerFactory;
import com.sonar.cxx.sslr.api.AstNode;
import java.util.List;
import java.util.function.Supplier;
import javax.annotation.Nonnull;

/**
 * Detection rules for OpenSSL random number generation.
 *
 * <p>These rules detect random number generation through the RAND API and EVP_RAND API. Covers
 * basic RAND_bytes operations and Deterministic Random Bit Generators (DRBG) using CTR, HASH, and
 * HMAC modes.
 */
@SuppressWarnings("java:S1192")
public final class OpenSSLRand {

    private static final String BUNDLE = "OpenSSL";

    // Legacy RAND API

    private static final IDetectionRule<AstNode> RAND_BYTES =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("RAND_bytes")
                    .shouldBeDetectedAs(new ValueActionFactory<>("RAND"))
                    .withAnyParameters()
                    .buildForContext(new PRNGContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> RAND_PRIV_BYTES =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("RAND_priv_bytes")
                    .shouldBeDetectedAs(new ValueActionFactory<>("RAND"))
                    .withAnyParameters()
                    .buildForContext(new PRNGContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    // EVP_RAND API: the DRBG is fetched by name; its cipher (CTR-DRBG) or digest (HASH-DRBG,
    // HMAC-DRBG) is set through OSSL_PARAMs of the context created from it

    private static final IDetectionRule<AstNode> EVP_RAND_CTX_SET_PARAMS_CIPHER =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_RAND_CTX_set_params")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .shouldBeDetectedAs(
                            new OpenSSLParamsScannerFactory(
                                    "cipher", OpenSSLNameCanonicalizerFactory.CIPHER_NAMES))
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_RAND_CTX_SET_PARAMS_DIGEST =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_RAND_CTX_set_params")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .shouldBeDetectedAs(
                            new OpenSSLParamsScannerFactory(
                                    "digest", OpenSSLNameCanonicalizerFactory.DIGEST_NAMES))
                    .buildForContext(new DigestContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_RAND_INSTANTIATE_CIPHER =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_RAND_instantiate")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .shouldBeDetectedAs(
                            new OpenSSLParamsScannerFactory(
                                    "cipher", OpenSSLNameCanonicalizerFactory.CIPHER_NAMES))
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_RAND_INSTANTIATE_DIGEST =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_RAND_instantiate")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .shouldBeDetectedAs(
                            new OpenSSLParamsScannerFactory(
                                    "digest", OpenSSLNameCanonicalizerFactory.DIGEST_NAMES))
                    .buildForContext(new DigestContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_RAND_CTX_NEW =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_RAND_CTX_new")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .buildForContext(new PRNGContext())
                    .inBundle(() -> BUNDLE)
                    .withDependingDetectionRules(
                            List.of(
                                    EVP_RAND_CTX_SET_PARAMS_CIPHER,
                                    EVP_RAND_CTX_SET_PARAMS_DIGEST,
                                    EVP_RAND_INSTANTIATE_CIPHER,
                                    EVP_RAND_INSTANTIATE_DIGEST));

    private static final IDetectionRule<AstNode> EVP_RAND_FETCH =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_RAND_fetch")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .shouldBeDetectedAs(new AlgorithmFactory<>())
                    .withMethodParameter("*")
                    .buildForContext(new PRNGContext())
                    .inBundle(() -> BUNDLE)
                    .withDependingDetectionRules(List.of(EVP_RAND_CTX_NEW));

    // EVP_RAND seed source

    private static final IDetectionRule<AstNode> RAND_SET_SEED_SOURCE_TYPE =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("RAND_set_seed_source_type")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .shouldBeDetectedAs(new AlgorithmFactory<>())
                    .withMethodParameter("*")
                    .buildForContext(new PRNGContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    // 3.0+ ex-variants and DRBG type selector

    private static final IDetectionRule<AstNode> RAND_BYTES_EX =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("RAND_bytes_ex")
                    .shouldBeDetectedAs(new ValueActionFactory<>("RAND"))
                    .withAnyParameters()
                    .buildForContext(new PRNGContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> RAND_PRIV_BYTES_EX =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("RAND_priv_bytes_ex")
                    .shouldBeDetectedAs(new ValueActionFactory<>("RAND"))
                    .withAnyParameters()
                    .buildForContext(new PRNGContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> RAND_SET_DRBG_TYPE =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("RAND_set_DRBG_type")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .shouldBeDetectedAs(new AlgorithmFactory<>())
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .buildForContext(new PRNGContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private OpenSSLRand() {
        // private
    }

    @Nonnull
    private static List<IDetectionRule<AstNode>> buildRules() {
        return List.of(
                // Legacy RAND API
                RAND_BYTES,
                RAND_PRIV_BYTES,
                // EVP_RAND API
                EVP_RAND_FETCH,
                // EVP_RAND seed source
                RAND_SET_SEED_SOURCE_TYPE,
                // 3.0+ ex-variants + DRBG type
                RAND_BYTES_EX,
                RAND_PRIV_BYTES_EX,
                RAND_SET_DRBG_TYPE);
    }

    private static final Supplier<List<IDetectionRule<AstNode>>> RULES =
            Memoize.of(OpenSSLRand::buildRules);

    @Nonnull
    public static List<IDetectionRule<AstNode>> rules() {
        return RULES.get();
    }
}
