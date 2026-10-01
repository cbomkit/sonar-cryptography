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
package com.ibm.plugin.rules.detection.openssl.kdf;

import com.ibm.engine.model.context.KeyDerivationFunctionContext;
import com.ibm.engine.model.factory.ValueActionFactory;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import com.ibm.plugin.rules.detection.Memoize;
import com.sonar.cxx.sslr.api.AstNode;
import java.util.List;
import java.util.function.Supplier;
import javax.annotation.Nonnull;

/** Detection rules for the OpenSSL Argon2 memory-hard KDF variants (Argon2d, Argon2i, Argon2id). */
@SuppressWarnings("java:S1192")
public final class OpenSSLEvpKdfArgon2 {

    private static final String BUNDLE = "OpenSSL";

    private static final IDetectionRule<AstNode> ARGON2D =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_KDF_fetch")
                    .shouldBeDetectedAs(new ValueActionFactory<>("ARGON2D"))
                    .withMethodParameter("*")
                    .withMethodParameter("\"ARGON2D\"")
                    .withMethodParameter("*")
                    .buildForContext(new KeyDerivationFunctionContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> ARGON2I =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_KDF_fetch")
                    .shouldBeDetectedAs(new ValueActionFactory<>("ARGON2I"))
                    .withMethodParameter("*")
                    .withMethodParameter("\"ARGON2I\"")
                    .withMethodParameter("*")
                    .buildForContext(new KeyDerivationFunctionContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> ARGON2ID =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_KDF_fetch")
                    .shouldBeDetectedAs(new ValueActionFactory<>("ARGON2ID"))
                    .withMethodParameter("*")
                    .withMethodParameter("\"ARGON2ID\"")
                    .withMethodParameter("*")
                    .buildForContext(new KeyDerivationFunctionContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private OpenSSLEvpKdfArgon2() {
        // private
    }

    @Nonnull
    private static List<IDetectionRule<AstNode>> buildRules() {
        return List.of(
                // Argon2 - Memory-hard password hashing and KDF
                ARGON2D, ARGON2I, ARGON2ID);
    }

    private static final Supplier<List<IDetectionRule<AstNode>>> RULES =
            Memoize.of(OpenSSLEvpKdfArgon2::buildRules);

    @Nonnull
    public static List<IDetectionRule<AstNode>> rules() {
        return RULES.get();
    }
}
