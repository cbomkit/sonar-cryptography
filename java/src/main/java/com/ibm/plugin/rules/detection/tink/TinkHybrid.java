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
package com.ibm.plugin.rules.detection.tink;

import com.ibm.engine.detection.MethodMatcher;
import com.ibm.engine.model.context.CipherContext;
import com.ibm.engine.model.factory.ValueActionFactory;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import java.util.List;
import javax.annotation.Nonnull;
import org.sonar.plugins.java.api.tree.Tree;

/**
 * Detection rules for Google Tink hybrid encryption primitive.
 *
 * <ul>
 *   <li>{@code KeysetHandle.generateNew(HybridKeyTemplates.ECIES_P256_HKDF_HMAC_SHA256_AES128_GCM)}
 *   <li>{@code hybridEncrypt.encrypt(plaintext, contextInfo)}
 *   <li>{@code hybridDecrypt.decrypt(ciphertext, contextInfo)}
 * </ul>
 */
@SuppressWarnings("java:S1192")
public final class TinkHybrid {

    private TinkHybrid() {
        // nothing
    }

    // hybridEncrypt.encrypt(byte[] plaintext, byte[] contextInfo)
    private static final IDetectionRule<Tree> HYBRID_ENCRYPT =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("com.google.crypto.tink.HybridEncrypt")
                    .forMethods("encrypt")
                    .shouldBeDetectedAs(new ValueActionFactory<>("ENCRYPT"))
                    .withMethodParameter(MethodMatcher.ANY)
                    .withMethodParameter(MethodMatcher.ANY)
                    .buildForContext(new CipherContext())
                    .inBundle(() -> "Tink")
                    .withoutDependingDetectionRules();

    // hybridDecrypt.decrypt(byte[] ciphertext, byte[] contextInfo)
    private static final IDetectionRule<Tree> HYBRID_DECRYPT =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("com.google.crypto.tink.HybridDecrypt")
                    .forMethods("decrypt")
                    .shouldBeDetectedAs(new ValueActionFactory<>("DECRYPT"))
                    .withMethodParameter(MethodMatcher.ANY)
                    .withMethodParameter(MethodMatcher.ANY)
                    .buildForContext(new CipherContext())
                    .inBundle(() -> "Tink")
                    .withoutDependingDetectionRules();

    private static final List<IDetectionRule<Tree>> HYBRID_OP_RULES =
            List.of(HYBRID_ENCRYPT, HYBRID_DECRYPT);

    private static IDetectionRule<Tree> hybridKeyRule(String value) {
        return new DetectionRuleBuilder<Tree>()
                .createDetectionRule()
                .forObjectTypes("com.google.crypto.tink.KeysetHandle")
                .forMethods("generateNew")
                .shouldBeDetectedAs(new ValueActionFactory<>(value))
                .withAnyParameters()
                .buildForContext(new CipherContext())
                .inBundle(() -> "Tink")
                .withDependingDetectionRules(HYBRID_OP_RULES);
    }

    private static final IDetectionRule<Tree> ECIES_P256_HKDF_HMAC_SHA256_AES128_GCM =
            hybridKeyRule("ECIES_P256_HKDF_HMAC_SHA256_AES128_GCM");
    private static final IDetectionRule<Tree> ECIES_P256_HKDF_HMAC_SHA256_AES128_CTR_HMAC_SHA256 =
            hybridKeyRule("ECIES_P256_HKDF_HMAC_SHA256_AES128_CTR_HMAC_SHA256");

    @Nonnull
    public static List<IDetectionRule<Tree>> rules() {
        return List.of(
                ECIES_P256_HKDF_HMAC_SHA256_AES128_GCM,
                ECIES_P256_HKDF_HMAC_SHA256_AES128_CTR_HMAC_SHA256);
    }
}
