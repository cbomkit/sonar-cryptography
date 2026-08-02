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

import com.ibm.engine.model.context.PRNGContext;
import com.ibm.engine.model.factory.AlgorithmFactory;
import com.ibm.engine.model.factory.ValueActionFactory;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import com.sonar.cxx.sslr.api.AstNode;
import java.util.List;
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

    // ====================================================================
    // Legacy RAND API
    // ====================================================================

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

    // ====================================================================
    // EVP_RAND API - CTR-DRBG (Counter mode DRBG)
    // ====================================================================

    private static final IDetectionRule<AstNode> CTR_DRBG_AES128 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_RAND_fetch")
                    .shouldBeDetectedAs(new ValueActionFactory<>("CTR-DRBG-AES128"))
                    .withMethodParameter("*")
                    .withMethodParameter("\"CTR-DRBG\"")
                    .withMethodParameter("*")
                    .buildForContext(new PRNGContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> CTR_DRBG_AES192 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_RAND_fetch")
                    .shouldBeDetectedAs(new ValueActionFactory<>("CTR-DRBG-AES192"))
                    .withMethodParameter("*")
                    .withMethodParameter("\"CTR-DRBG\"")
                    .withMethodParameter("*")
                    .buildForContext(new PRNGContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> CTR_DRBG_AES256 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_RAND_fetch")
                    .shouldBeDetectedAs(new ValueActionFactory<>("CTR-DRBG-AES256"))
                    .withMethodParameter("*")
                    .withMethodParameter("\"CTR-DRBG\"")
                    .withMethodParameter("*")
                    .buildForContext(new PRNGContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    // ====================================================================
    // EVP_RAND API - HASH-DRBG (Hash-based DRBG)
    // ====================================================================

    private static final IDetectionRule<AstNode> HASH_DRBG_SHA1 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_RAND_fetch")
                    .shouldBeDetectedAs(new ValueActionFactory<>("HASH-DRBG-SHA1"))
                    .withMethodParameter("*")
                    .withMethodParameter("\"HASH-DRBG\"")
                    .withMethodParameter("*")
                    .buildForContext(new PRNGContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> HASH_DRBG_SHA256 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_RAND_fetch")
                    .shouldBeDetectedAs(new ValueActionFactory<>("HASH-DRBG-SHA256"))
                    .withMethodParameter("*")
                    .withMethodParameter("\"HASH-DRBG\"")
                    .withMethodParameter("*")
                    .buildForContext(new PRNGContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> HASH_DRBG_SHA384 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_RAND_fetch")
                    .shouldBeDetectedAs(new ValueActionFactory<>("HASH-DRBG-SHA384"))
                    .withMethodParameter("*")
                    .withMethodParameter("\"HASH-DRBG\"")
                    .withMethodParameter("*")
                    .buildForContext(new PRNGContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> HASH_DRBG_SHA512 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_RAND_fetch")
                    .shouldBeDetectedAs(new ValueActionFactory<>("HASH-DRBG-SHA512"))
                    .withMethodParameter("*")
                    .withMethodParameter("\"HASH-DRBG\"")
                    .withMethodParameter("*")
                    .buildForContext(new PRNGContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    // ====================================================================
    // EVP_RAND API - HMAC-DRBG (HMAC-based DRBG)
    // ====================================================================

    private static final IDetectionRule<AstNode> HMAC_DRBG_SHA1 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_RAND_fetch")
                    .shouldBeDetectedAs(new ValueActionFactory<>("HMAC-DRBG-SHA1"))
                    .withMethodParameter("*")
                    .withMethodParameter("\"HMAC-DRBG\"")
                    .withMethodParameter("*")
                    .buildForContext(new PRNGContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> HMAC_DRBG_SHA256 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_RAND_fetch")
                    .shouldBeDetectedAs(new ValueActionFactory<>("HMAC-DRBG-SHA256"))
                    .withMethodParameter("*")
                    .withMethodParameter("\"HMAC-DRBG\"")
                    .withMethodParameter("*")
                    .buildForContext(new PRNGContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> HMAC_DRBG_SHA384 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_RAND_fetch")
                    .shouldBeDetectedAs(new ValueActionFactory<>("HMAC-DRBG-SHA384"))
                    .withMethodParameter("*")
                    .withMethodParameter("\"HMAC-DRBG\"")
                    .withMethodParameter("*")
                    .buildForContext(new PRNGContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> HMAC_DRBG_SHA512 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_RAND_fetch")
                    .shouldBeDetectedAs(new ValueActionFactory<>("HMAC-DRBG-SHA512"))
                    .withMethodParameter("*")
                    .withMethodParameter("\"HMAC-DRBG\"")
                    .withMethodParameter("*")
                    .buildForContext(new PRNGContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    // ====================================================================
    // EVP_RAND API - Entropy Sources
    // ====================================================================

    private static final IDetectionRule<AstNode> SEED_SRC =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_RAND_fetch")
                    .shouldBeDetectedAs(new ValueActionFactory<>("SEED-SRC"))
                    .withMethodParameter("*")
                    .withMethodParameter("\"SEED-SRC\"")
                    .withMethodParameter("*")
                    .buildForContext(new PRNGContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> JITTER =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_RAND_fetch")
                    .shouldBeDetectedAs(new ValueActionFactory<>("JITTER"))
                    .withMethodParameter("*")
                    .withMethodParameter("\"JITTER\"")
                    .withMethodParameter("*")
                    .buildForContext(new PRNGContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> TEST_RAND =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_RAND_fetch")
                    .shouldBeDetectedAs(new ValueActionFactory<>("TEST-RAND"))
                    .withMethodParameter("*")
                    .withMethodParameter("\"TEST-RAND\"")
                    .withMethodParameter("*")
                    .buildForContext(new PRNGContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    // ====================================================================
    // EVP_RAND seed source
    // ====================================================================

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

    // ====================================================================
    // 3.0+ ex-variants and DRBG type selector
    // ====================================================================

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
        // nothing
    }

    @Nonnull
    public static List<IDetectionRule<AstNode>> rules() {
        return List.of(
                // Legacy RAND API
                RAND_BYTES,
                RAND_PRIV_BYTES,
                // CTR-DRBG
                CTR_DRBG_AES128,
                CTR_DRBG_AES192,
                CTR_DRBG_AES256,
                // HASH-DRBG
                HASH_DRBG_SHA1,
                HASH_DRBG_SHA256,
                HASH_DRBG_SHA384,
                HASH_DRBG_SHA512,
                // HMAC-DRBG
                HMAC_DRBG_SHA1,
                HMAC_DRBG_SHA256,
                HMAC_DRBG_SHA384,
                HMAC_DRBG_SHA512,
                // Entropy Sources
                SEED_SRC,
                JITTER,
                TEST_RAND,
                // EVP_RAND seed source
                RAND_SET_SEED_SOURCE_TYPE,
                // 3.0+ ex-variants + DRBG type
                RAND_BYTES_EX,
                RAND_PRIV_BYTES_EX,
                RAND_SET_DRBG_TYPE);
    }
}
