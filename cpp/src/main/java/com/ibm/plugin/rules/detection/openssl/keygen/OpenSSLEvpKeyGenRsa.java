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
import com.ibm.engine.model.factory.ValueActionFactory;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import com.ibm.plugin.rules.detection.Memoize;
import com.sonar.cxx.sslr.api.AstNode;
import java.util.List;
import java.util.function.Supplier;
import javax.annotation.Nonnull;

/**
 * Detection rules for OpenSSL EVP RSA key generation setters (keygen bits, public exponent, and
 * prime count).
 */
public final class OpenSSLEvpKeyGenRsa {

    private static final String BUNDLE = "OpenSSL";

    private static final IDetectionRule<AstNode> EVP_RSA_KEYGEN_BITS =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_PKEY_CTX_set_rsa_keygen_bits")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .shouldBeDetectedAs(new OpenSSLKeygenBitsFactory("RSA"))
                    .buildForContext(new KeyContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_PKEY_CTX_SET1_RSA_KEYGEN_PUBEXP =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_PKEY_CTX_set1_rsa_keygen_pubexp")
                    .shouldBeDetectedAs(new ValueActionFactory<>("RSA-KEYGEN-PUBEXP"))
                    .withAnyParameters()
                    .buildForContext(new KeyContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_PKEY_CTX_SET_RSA_KEYGEN_PRIMES =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_PKEY_CTX_set_rsa_keygen_primes")
                    .shouldBeDetectedAs(new ValueActionFactory<>("RSA-KEYGEN-PRIMES"))
                    .withAnyParameters()
                    .buildForContext(new KeyContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private OpenSSLEvpKeyGenRsa() {
        // private
    }

    @Nonnull
    private static List<IDetectionRule<AstNode>> buildRules() {
        return List.of(
                // RSA Key Generation
                EVP_RSA_KEYGEN_BITS,
                // RSA keygen pubexp/primes
                EVP_PKEY_CTX_SET1_RSA_KEYGEN_PUBEXP,
                EVP_PKEY_CTX_SET_RSA_KEYGEN_PRIMES);
    }

    private static final Supplier<List<IDetectionRule<AstNode>>> RULES =
            Memoize.of(OpenSSLEvpKeyGenRsa::buildRules);

    @Nonnull
    public static List<IDetectionRule<AstNode>> rules() {
        return RULES.get();
    }
}
