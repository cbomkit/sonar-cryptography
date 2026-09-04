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
package com.ibm.plugin.rules.detection.nodecrypto;

import static com.ibm.engine.detection.MethodMatcher.ANY;

import com.ibm.engine.model.CipherAction;
import com.ibm.engine.model.context.CipherContext;
import com.ibm.engine.model.factory.CipherActionFactory;
import com.ibm.engine.model.factory.ValueActionFactory;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import com.ibm.plugin.javascript.api.Tree;
import com.ibm.plugin.rules.detection.Memoize;
import java.util.List;
import java.util.Map;
import java.util.function.Supplier;
import javax.annotation.Nonnull;

/**
 * Detection rules for Node.js RSA asymmetric encryption APIs.
 *
 * <p>Detects usage of:
 *
 * <ul>
 *   <li>crypto.publicEncrypt(key, buffer) - RSA public key encryption
 *   <li>crypto.privateDecrypt(key, buffer) - RSA private key decryption
 *   <li>crypto.privateEncrypt(key, buffer) - RSA private key encryption
 *   <li>crypto.publicDecrypt(key, buffer) - RSA public key decryption
 * </ul>
 */
@SuppressWarnings("java:S1192")
public final class NodeCryptoRSA {

    private NodeCryptoRSA() {
        // private
    }

    private static final IDetectionRule<Tree> PUBLIC_ENCRYPT =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes(NodeCryptoTypes.CRYPTO, NodeCryptoTypes.NODE_CRYPTO)
                    .forMethods("publicEncrypt")
                    .shouldBeDetectedAs(new ValueActionFactory<>("RSA"))
                    .withMethodParameter(ANY)
                    .withMethodParameter(ANY)
                    .buildForContext(new CipherContext(Map.of("algorithm", "RSA")))
                    .inBundle(() -> NodeCryptoTypes.BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<Tree> PRIVATE_DECRYPT =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes(NodeCryptoTypes.CRYPTO, NodeCryptoTypes.NODE_CRYPTO)
                    .forMethods("privateDecrypt")
                    .shouldBeDetectedAs(new ValueActionFactory<>("RSA"))
                    .withMethodParameter(ANY)
                    .withMethodParameter(ANY)
                    .buildForContext(new CipherContext(Map.of("algorithm", "RSA")))
                    .inBundle(() -> NodeCryptoTypes.BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<Tree> PRIVATE_ENCRYPT =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes(NodeCryptoTypes.CRYPTO, NodeCryptoTypes.NODE_CRYPTO)
                    .forMethods("privateEncrypt")
                    .shouldBeDetectedAs(new ValueActionFactory<>("RSA"))
                    .withMethodParameter(ANY)
                    .withMethodParameter(ANY)
                    .buildForContext(new CipherContext(Map.of("algorithm", "RSA")))
                    .inBundle(() -> NodeCryptoTypes.BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<Tree> PUBLIC_DECRYPT =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes(NodeCryptoTypes.CRYPTO, NodeCryptoTypes.NODE_CRYPTO)
                    .forMethods("publicDecrypt")
                    .shouldBeDetectedAs(new ValueActionFactory<>("RSA"))
                    .withMethodParameter(ANY)
                    .withMethodParameter(ANY)
                    .buildForContext(new CipherContext(Map.of("algorithm", "RSA")))
                    .inBundle(() -> NodeCryptoTypes.BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<Tree> PRIVATE_DECRYPT_WITH_PADDING =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes(NodeCryptoTypes.CRYPTO, NodeCryptoTypes.NODE_CRYPTO)
                    .forMethods("privateDecrypt")
                    .shouldBeDetectedAs(new CipherActionFactory<>(CipherAction.Action.DECRYPT))
                    .withMethodParameter("object")
                    .withMethodParameter(ANY)
                    .buildForContext(new CipherContext(Map.of("algorithm", "RSA")))
                    .inBundle(() -> NodeCryptoTypes.BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<Tree> PUBLIC_ENCRYPT_WITH_PADDING =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes(NodeCryptoTypes.CRYPTO, NodeCryptoTypes.NODE_CRYPTO)
                    .forMethods("publicEncrypt")
                    .shouldBeDetectedAs(new CipherActionFactory<>(CipherAction.Action.ENCRYPT))
                    .withMethodParameter("object")
                    .withMethodParameter(ANY)
                    .buildForContext(new CipherContext(Map.of("algorithm", "RSA")))
                    .inBundle(() -> NodeCryptoTypes.BUNDLE)
                    .withoutDependingDetectionRules();

    private static final Supplier<List<IDetectionRule<Tree>>> RULES =
            Memoize.of(NodeCryptoRSA::buildRules);

    @Nonnull
    public static List<IDetectionRule<Tree>> rules() {
        return RULES.get();
    }

    @Nonnull
    private static List<IDetectionRule<Tree>> buildRules() {
        return List.of(
                PUBLIC_ENCRYPT,
                PRIVATE_DECRYPT,
                PRIVATE_ENCRYPT,
                PUBLIC_DECRYPT,
                PUBLIC_ENCRYPT_WITH_PADDING,
                PRIVATE_DECRYPT_WITH_PADDING);
    }
}
