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
 * Detection rules for Google Tink AEAD.
 *
 * <p>Detects key generation and encrypt/decrypt operations:
 *
 * <ul>
 *   <li>{@code KeysetHandle.generateNew(AeadKeyTemplates.AES128_GCM)}
 *   <li>{@code KeysetHandle.generateNew(AeadKeyTemplates.AES256_GCM)}
 *   <li>{@code KeysetHandle.generateNew(AeadKeyTemplates.AES128_CTR_HMAC_SHA256)}
 *   <li>{@code KeysetHandle.generateNew(AeadKeyTemplates.AES256_CTR_HMAC_SHA256)}
 *   <li>{@code aead.encrypt(plaintext, aad)}
 *   <li>{@code aead.decrypt(ciphertext, aad)}
 * </ul>
 */
@SuppressWarnings("java:S1192")
public final class TinkAead {

    private TinkAead() {
        // nothing
    }

    // aead.encrypt(plaintext, aad)
    private static final IDetectionRule<Tree> AEAD_ENCRYPT =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("com.google.crypto.tink.Aead")
                    .forMethods("encrypt")
                    .shouldBeDetectedAs(new ValueActionFactory<>("ENCRYPT"))
                    .withMethodParameter(MethodMatcher.ANY)
                    .withMethodParameter(MethodMatcher.ANY)
                    .buildForContext(new CipherContext())
                    .inBundle(() -> "Tink")
                    .withoutDependingDetectionRules();

    // aead.decrypt(ciphertext, aad)
    private static final IDetectionRule<Tree> AEAD_DECRYPT =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("com.google.crypto.tink.Aead")
                    .forMethods("decrypt")
                    .shouldBeDetectedAs(new ValueActionFactory<>("DECRYPT"))
                    .withMethodParameter(MethodMatcher.ANY)
                    .withMethodParameter(MethodMatcher.ANY)
                    .buildForContext(new CipherContext())
                    .inBundle(() -> "Tink")
                    .withoutDependingDetectionRules();

    private static final List<IDetectionRule<Tree>> AEAD_OP_RULES =
            List.of(AEAD_ENCRYPT, AEAD_DECRYPT);

    // KeysetHandle.generateNew(AeadKeyTemplates.AES128_GCM)
    private static final IDetectionRule<Tree> AES128_GCM =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("com.google.crypto.tink.KeysetHandle")
                    .forMethods("generateNew")
                    .shouldBeDetectedAs(new ValueActionFactory<>("AES128_GCM"))
                    .withAnyParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> "Tink")
                    .withDependingDetectionRules(AEAD_OP_RULES);

    // KeysetHandle.generateNew(AeadKeyTemplates.AES256_GCM)
    private static final IDetectionRule<Tree> AES256_GCM =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("com.google.crypto.tink.KeysetHandle")
                    .forMethods("generateNew")
                    .shouldBeDetectedAs(new ValueActionFactory<>("AES256_GCM"))
                    .withAnyParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> "Tink")
                    .withDependingDetectionRules(AEAD_OP_RULES);

    // KeysetHandle.generateNew(AeadKeyTemplates.AES128_CTR_HMAC_SHA256)
    private static final IDetectionRule<Tree> AES128_CTR_HMAC_SHA256 =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("com.google.crypto.tink.KeysetHandle")
                    .forMethods("generateNew")
                    .shouldBeDetectedAs(new ValueActionFactory<>("AES128_CTR_HMAC_SHA256"))
                    .withAnyParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> "Tink")
                    .withDependingDetectionRules(AEAD_OP_RULES);

    // KeysetHandle.generateNew(AeadKeyTemplates.AES256_CTR_HMAC_SHA256)
    private static final IDetectionRule<Tree> AES256_CTR_HMAC_SHA256 =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("com.google.crypto.tink.KeysetHandle")
                    .forMethods("generateNew")
                    .shouldBeDetectedAs(new ValueActionFactory<>("AES256_CTR_HMAC_SHA256"))
                    .withAnyParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> "Tink")
                    .withDependingDetectionRules(AEAD_OP_RULES);

    @Nonnull
    public static List<IDetectionRule<Tree>> rules() {
        return List.of(AES128_GCM, AES256_GCM, AES128_CTR_HMAC_SHA256, AES256_CTR_HMAC_SHA256);
    }
}
