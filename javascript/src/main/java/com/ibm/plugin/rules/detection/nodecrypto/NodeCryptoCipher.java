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

import com.ibm.engine.model.context.CipherContext;
import com.ibm.engine.model.factory.AlgorithmFactory;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import com.ibm.plugin.javascript.api.Tree;
import com.ibm.plugin.rules.detection.Memoize;
import java.util.List;
import java.util.function.Supplier;
import javax.annotation.Nonnull;

/**
 * Detection rules for Node.js symmetric cipher APIs.
 *
 * <p>Detects usage of:
 *
 * <ul>
 *   <li>crypto.createCipheriv(algorithm, key, iv) - creates a cipher for encryption
 *   <li>crypto.createDecipheriv(algorithm, key, iv) - creates a decipher for decryption
 *   <li>crypto.createCipher(algorithm, password) - deprecated password-based cipher
 *   <li>crypto.createDecipher(algorithm, password) - deprecated password-based decipher
 * </ul>
 */
@SuppressWarnings("java:S1192")
public final class NodeCryptoCipher {

    private NodeCryptoCipher() {
        // private
    }

    private static final IDetectionRule<Tree> CREATE_CIPHERIV =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes(NodeCryptoTypes.CRYPTO, NodeCryptoTypes.NODE_CRYPTO)
                    .forMethods("createCipheriv")
                    .withMethodParameter("string")
                    .shouldBeDetectedAs(new AlgorithmFactory<>())
                    .withMethodParameter(ANY)
                    .withMethodParameter(ANY)
                    .buildForContext(new CipherContext())
                    .inBundle(() -> NodeCryptoTypes.BUNDLE)
                    .withDependingDetectionRules(NodeCryptoCipherStream.rules());

    private static final IDetectionRule<Tree> CREATE_DECIPHERIV =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes(NodeCryptoTypes.CRYPTO, NodeCryptoTypes.NODE_CRYPTO)
                    .forMethods("createDecipheriv")
                    .withMethodParameter("string")
                    .shouldBeDetectedAs(new AlgorithmFactory<>())
                    .withMethodParameter(ANY)
                    .withMethodParameter(ANY)
                    .buildForContext(new CipherContext())
                    .inBundle(() -> NodeCryptoTypes.BUNDLE)
                    .withDependingDetectionRules(NodeCryptoDecipherStream.rules());

    private static final IDetectionRule<Tree> CREATE_CIPHER =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes(NodeCryptoTypes.CRYPTO, NodeCryptoTypes.NODE_CRYPTO)
                    .forMethods("createCipher")
                    .withMethodParameter("string")
                    .shouldBeDetectedAs(new AlgorithmFactory<>())
                    .withMethodParameter(ANY)
                    .buildForContext(new CipherContext())
                    .inBundle(() -> NodeCryptoTypes.BUNDLE)
                    .withDependingDetectionRules(NodeCryptoCipherStream.rules());

    private static final IDetectionRule<Tree> CREATE_DECIPHER =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes(NodeCryptoTypes.CRYPTO, NodeCryptoTypes.NODE_CRYPTO)
                    .forMethods("createDecipher")
                    .withMethodParameter("string")
                    .shouldBeDetectedAs(new AlgorithmFactory<>())
                    .withMethodParameter(ANY)
                    .buildForContext(new CipherContext())
                    .inBundle(() -> NodeCryptoTypes.BUNDLE)
                    .withDependingDetectionRules(NodeCryptoDecipherStream.rules());

    private static final Supplier<List<IDetectionRule<Tree>>> RULES =
            Memoize.of(NodeCryptoCipher::buildRules);

    @Nonnull
    public static List<IDetectionRule<Tree>> rules() {
        return RULES.get();
    }

    @Nonnull
    private static List<IDetectionRule<Tree>> buildRules() {
        return List.of(CREATE_CIPHERIV, CREATE_DECIPHERIV, CREATE_CIPHER, CREATE_DECIPHER);
    }
}
