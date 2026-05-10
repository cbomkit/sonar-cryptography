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
import com.ibm.engine.model.context.MacContext;
import com.ibm.engine.model.factory.ValueActionFactory;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import java.util.List;
import javax.annotation.Nonnull;
import org.sonar.plugins.java.api.tree.Tree;

/**
 * Detection rules for Google Tink MAC primitive.
 *
 * <p>Detects key generation and MAC operations:
 *
 * <ul>
 *   <li>{@code KeysetHandle.generateNew(MacKeyTemplates.HMAC_SHA256_128BITTAG)}
 *   <li>{@code KeysetHandle.generateNew(MacKeyTemplates.HMAC_SHA256_256BITTAG)}
 *   <li>{@code KeysetHandle.generateNew(MacKeyTemplates.HMAC_SHA512_256BITTAG)}
 *   <li>{@code KeysetHandle.generateNew(MacKeyTemplates.HMAC_SHA512_512BITTAG)}
 *   <li>{@code KeysetHandle.generateNew(MacKeyTemplates.AES_CMAC)}
 *   <li>{@code mac.computeMac(data)}
 *   <li>{@code mac.verifyMac(tag, data)}
 * </ul>
 */
@SuppressWarnings("java:S1192")
public final class TinkMac {

    private TinkMac() {
        // nothing
    }

    // mac.computeMac(byte[] data)
    private static final IDetectionRule<Tree> MAC_COMPUTE =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("com.google.crypto.tink.Mac")
                    .forMethods("computeMac")
                    .shouldBeDetectedAs(new ValueActionFactory<>("COMPUTE"))
                    .withMethodParameter(MethodMatcher.ANY)
                    .buildForContext(new MacContext())
                    .inBundle(() -> "Tink")
                    .withoutDependingDetectionRules();

    // mac.verifyMac(byte[] tag, byte[] data)
    private static final IDetectionRule<Tree> MAC_VERIFY =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("com.google.crypto.tink.Mac")
                    .forMethods("verifyMac")
                    .shouldBeDetectedAs(new ValueActionFactory<>("VERIFY"))
                    .withMethodParameter(MethodMatcher.ANY)
                    .withMethodParameter(MethodMatcher.ANY)
                    .buildForContext(new MacContext())
                    .inBundle(() -> "Tink")
                    .withoutDependingDetectionRules();

    private static final List<IDetectionRule<Tree>> MAC_OP_RULES = List.of(MAC_COMPUTE, MAC_VERIFY);

    private static IDetectionRule<Tree> macKeyRule(String value) {
        return new DetectionRuleBuilder<Tree>()
                .createDetectionRule()
                .forObjectTypes("com.google.crypto.tink.KeysetHandle")
                .forMethods("generateNew")
                .shouldBeDetectedAs(new ValueActionFactory<>(value))
                .withAnyParameters()
                .buildForContext(new MacContext())
                .inBundle(() -> "Tink")
                .withDependingDetectionRules(MAC_OP_RULES);
    }

    private static final IDetectionRule<Tree> HMAC_SHA256_128BITTAG =
            macKeyRule("HMAC_SHA256_128BITTAG");
    private static final IDetectionRule<Tree> HMAC_SHA256_256BITTAG =
            macKeyRule("HMAC_SHA256_256BITTAG");
    private static final IDetectionRule<Tree> HMAC_SHA512_256BITTAG =
            macKeyRule("HMAC_SHA512_256BITTAG");
    private static final IDetectionRule<Tree> HMAC_SHA512_512BITTAG =
            macKeyRule("HMAC_SHA512_512BITTAG");
    private static final IDetectionRule<Tree> AES_CMAC = macKeyRule("AES_CMAC");

    @Nonnull
    public static List<IDetectionRule<Tree>> rules() {
        return List.of(
                HMAC_SHA256_128BITTAG,
                HMAC_SHA256_256BITTAG,
                HMAC_SHA512_256BITTAG,
                HMAC_SHA512_512BITTAG,
                AES_CMAC);
    }
}
