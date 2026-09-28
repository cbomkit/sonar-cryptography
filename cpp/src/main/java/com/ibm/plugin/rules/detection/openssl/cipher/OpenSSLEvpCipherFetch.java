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
package com.ibm.plugin.rules.detection.openssl.cipher;

import com.ibm.engine.model.context.CipherContext;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import com.ibm.plugin.rules.detection.Memoize;
import com.ibm.plugin.rules.detection.openssl.digest.OpenSSLNameCanonicalizerFactory;
import com.sonar.cxx.sslr.api.AstNode;
import java.util.List;
import java.util.function.Supplier;
import javax.annotation.Nonnull;

/**
 * Detection rule for {@code EVP_CIPHER_fetch}, which selects a cipher by name through the OpenSSL
 * 3.0 provider API, e.g. {@code EVP_CIPHER_fetch(NULL, "AES-256-GCM", NULL)}.
 *
 * <p>The name argument is resolved to its string value, whether it is a literal or a variable, and
 * normalized with {@link OpenSSLNameCanonicalizerFactory#CIPHER_NAMES}, since OpenSSL matches
 * cipher names case-insensitively and accepts aliases such as {@code "DES3"} or {@code
 * "id-aes256-GCM"}.
 */
public final class OpenSSLEvpCipherFetch {

    private static final String BUNDLE = "OpenSSL";

    private static final IDetectionRule<AstNode> EVP_CIPHER_FETCH =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_CIPHER_fetch")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .shouldBeDetectedAs(
                            new OpenSSLNameCanonicalizerFactory(
                                    OpenSSLNameCanonicalizerFactory.CIPHER_NAMES))
                    .withMethodParameter("*")
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private OpenSSLEvpCipherFetch() {
        // private
    }

    @Nonnull
    private static List<IDetectionRule<AstNode>> buildRules() {
        return List.of(EVP_CIPHER_FETCH);
    }

    private static final Supplier<List<IDetectionRule<AstNode>>> RULES =
            Memoize.of(OpenSSLEvpCipherFetch::buildRules);

    @Nonnull
    public static List<IDetectionRule<AstNode>> rules() {
        return RULES.get();
    }
}
