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
import com.sonar.cxx.sslr.api.AstNode;
import java.util.List;
import javax.annotation.Nonnull;

/**
 * Detection rule for OpenSSL provider-only cipher modes accessible via EVP_CIPHER_fetch.
 *
 * <p>These cipher modes don't have convenience EVP_* functions and must be accessed through the
 * provider API using string identifiers. Covers modern AEAD modes (AES-SIV, AES-GCM-SIV), key
 * wrapping variants, and encrypt-then-MAC constructions.
 *
 * <p>A single rule matches any second-argument shape and delegates value resolution and mode-name
 * validation to {@link OpenSSLCipherFetchFactory}, so a mode name reaching the call site via a
 * resolved local variable/constant is detected the same as a string literal (see {@link
 * OpenSSLCipherFetchFactory} javadoc).
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
                    .shouldBeDetectedAs(new OpenSSLCipherFetchFactory())
                    .withMethodParameter("*")
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private OpenSSLEvpCipherFetch() {
        // nothing
    }

    @Nonnull
    public static List<IDetectionRule<AstNode>> rules() {
        return List.of(EVP_CIPHER_FETCH);
    }
}
