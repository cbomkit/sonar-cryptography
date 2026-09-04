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

import com.ibm.engine.model.KeyAction;
import com.ibm.engine.model.context.KeyContext;
import com.ibm.engine.model.context.PrivateKeyContext;
import com.ibm.engine.model.context.PublicKeyContext;
import com.ibm.engine.model.context.SecretKeyContext;
import com.ibm.engine.model.factory.AlgorithmFactory;
import com.ibm.engine.model.factory.KeyActionFactory;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import com.ibm.plugin.javascript.api.Tree;
import com.ibm.plugin.rules.detection.Memoize;
import java.util.List;
import java.util.Map;
import java.util.function.Supplier;
import javax.annotation.Nonnull;

/**
 * Detection rules for Node.js key generation and import APIs.
 *
 * <p>Detects usage of:
 *
 * <ul>
 *   <li>crypto.generateKey(type, options, callback) - generates a secret key
 *   <li>crypto.generateKeySync(type, options) - synchronous secret key generation
 *   <li>crypto.generateKeyPair(type, options, callback) - generates a key pair
 *   <li>crypto.generateKeyPairSync(type, options) - synchronous key pair generation
 *   <li>crypto.createSecretKey(key) - imports a secret key
 *   <li>crypto.createPublicKey(key) - imports a public key
 *   <li>crypto.createPrivateKey(key) - imports a private key
 * </ul>
 */
@SuppressWarnings("java:S1192")
public final class NodeCryptoKeyGen {

    private NodeCryptoKeyGen() {
        // private
    }

    private static final IDetectionRule<Tree> GENERATE_KEY =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes(NodeCryptoTypes.CRYPTO, NodeCryptoTypes.NODE_CRYPTO)
                    .forMethods("generateKey")
                    .withMethodParameter("string")
                    .shouldBeDetectedAs(new AlgorithmFactory<>())
                    .withMethodParameter("object")
                    .withMethodParameter(ANY)
                    .buildForContext(new SecretKeyContext(Map.of()))
                    .inBundle(() -> NodeCryptoTypes.BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<Tree> GENERATE_KEY_SYNC =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes(NodeCryptoTypes.CRYPTO, NodeCryptoTypes.NODE_CRYPTO)
                    .forMethods("generateKeySync")
                    .withMethodParameter("string")
                    .shouldBeDetectedAs(new AlgorithmFactory<>())
                    .withMethodParameter("object")
                    .buildForContext(new SecretKeyContext(Map.of()))
                    .inBundle(() -> NodeCryptoTypes.BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<Tree> GENERATE_KEY_PAIR =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes(NodeCryptoTypes.CRYPTO, NodeCryptoTypes.NODE_CRYPTO)
                    .forMethods("generateKeyPair")
                    .withMethodParameter("string")
                    .shouldBeDetectedAs(new AlgorithmFactory<>())
                    .withMethodParameter("object")
                    .withMethodParameter(ANY)
                    .buildForContext(new KeyContext())
                    .inBundle(() -> NodeCryptoTypes.BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<Tree> GENERATE_KEY_PAIR_SYNC =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes(NodeCryptoTypes.CRYPTO, NodeCryptoTypes.NODE_CRYPTO)
                    .forMethods("generateKeyPairSync")
                    .withMethodParameter("string")
                    .shouldBeDetectedAs(new AlgorithmFactory<>())
                    .withMethodParameter("object")
                    .buildForContext(new KeyContext())
                    .inBundle(() -> NodeCryptoTypes.BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<Tree> CREATE_SECRET_KEY =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes(NodeCryptoTypes.CRYPTO, NodeCryptoTypes.NODE_CRYPTO)
                    .forMethods("createSecretKey")
                    .shouldBeDetectedAs(new KeyActionFactory<>(KeyAction.Action.GENERATION))
                    .withMethodParameter(ANY)
                    .buildForContext(new SecretKeyContext(Map.of()))
                    .inBundle(() -> NodeCryptoTypes.BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<Tree> CREATE_PUBLIC_KEY =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes(NodeCryptoTypes.CRYPTO, NodeCryptoTypes.NODE_CRYPTO)
                    .forMethods("createPublicKey")
                    .shouldBeDetectedAs(
                            new KeyActionFactory<>(KeyAction.Action.PUBLIC_KEY_GENERATION))
                    .withMethodParameter(ANY)
                    .buildForContext(new PublicKeyContext(Map.of()))
                    .inBundle(() -> NodeCryptoTypes.BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<Tree> CREATE_PRIVATE_KEY =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes(NodeCryptoTypes.CRYPTO, NodeCryptoTypes.NODE_CRYPTO)
                    .forMethods("createPrivateKey")
                    .shouldBeDetectedAs(
                            new KeyActionFactory<>(KeyAction.Action.PRIVATE_KEY_GENERATION))
                    .withMethodParameter(ANY)
                    .buildForContext(new PrivateKeyContext(Map.of("kind", "import")))
                    .inBundle(() -> NodeCryptoTypes.BUNDLE)
                    .withoutDependingDetectionRules();

    private static final Supplier<List<IDetectionRule<Tree>>> RULES =
            Memoize.of(NodeCryptoKeyGen::buildRules);

    @Nonnull
    public static List<IDetectionRule<Tree>> rules() {
        return RULES.get();
    }

    @Nonnull
    private static List<IDetectionRule<Tree>> buildRules() {
        return List.of(
                GENERATE_KEY,
                GENERATE_KEY_SYNC,
                GENERATE_KEY_PAIR,
                GENERATE_KEY_PAIR_SYNC,
                CREATE_SECRET_KEY,
                CREATE_PUBLIC_KEY,
                CREATE_PRIVATE_KEY);
    }
}
