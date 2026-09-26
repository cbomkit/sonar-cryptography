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
import com.ibm.engine.model.context.KeyAgreementContext;
import com.ibm.engine.model.factory.CurveFactory;
import com.ibm.engine.model.factory.KeyActionFactory;
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
 * Detection rules for Node.js key agreement APIs.
 *
 * <p>Detects usage of:
 *
 * <ul>
 *   <li>crypto.createDiffieHellman(size) - creates a Diffie-Hellman key exchange object
 *   <li>crypto.createDiffieHellman(prime, generator) - creates DH with custom prime
 *   <li>crypto.createECDH(curveName) - creates an ECDH key exchange object
 * </ul>
 */
@SuppressWarnings("java:S1192")
public final class NodeCryptoKeyAgreement {

    private NodeCryptoKeyAgreement() {
        // private
    }

    private static final IDetectionRule<Tree> DH_COMPUTE_SECRET =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes(NodeCryptoTypes.DIFFIE_HELLMAN)
                    .forMethods("computeSecret")
                    .shouldBeDetectedAs(new ValueActionFactory<>("computeSecret"))
                    .withMethodParameter(ANY)
                    .buildForContext(new KeyAgreementContext(Map.of("algorithm", "DH")))
                    .inBundle(() -> NodeCryptoTypes.BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<Tree> DH_GENERATE_KEYS =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes(NodeCryptoTypes.DIFFIE_HELLMAN)
                    .forMethods("generateKeys")
                    .shouldBeDetectedAs(new KeyActionFactory<>(KeyAction.Action.GENERATION))
                    .withAnyParameters()
                    .buildForContext(new KeyAgreementContext(Map.of("algorithm", "DH")))
                    .inBundle(() -> NodeCryptoTypes.BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<Tree> CREATE_DIFFIE_HELLMAN =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes(NodeCryptoTypes.CRYPTO, NodeCryptoTypes.NODE_CRYPTO)
                    .forMethods("createDiffieHellman")
                    .shouldBeDetectedAs(new ValueActionFactory<>("DH"))
                    .withMethodParameter(ANY)
                    .buildForContext(new KeyAgreementContext(Map.of("algorithm", "DH")))
                    .inBundle(() -> NodeCryptoTypes.BUNDLE)
                    .withDependingDetectionRules(List.of(DH_COMPUTE_SECRET, DH_GENERATE_KEYS));

    private static final IDetectionRule<Tree> ECDH_COMPUTE_SECRET =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes(NodeCryptoTypes.ECDH)
                    .forMethods("computeSecret")
                    .shouldBeDetectedAs(new ValueActionFactory<>("computeSecret"))
                    .withMethodParameter(ANY)
                    .buildForContext(new KeyAgreementContext(Map.of("algorithm", "ECDH")))
                    .inBundle(() -> NodeCryptoTypes.BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<Tree> ECDH_GENERATE_KEYS =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes(NodeCryptoTypes.ECDH)
                    .forMethods("generateKeys")
                    .shouldBeDetectedAs(new KeyActionFactory<>(KeyAction.Action.GENERATION))
                    .withAnyParameters()
                    .buildForContext(new KeyAgreementContext(Map.of("algorithm", "ECDH")))
                    .inBundle(() -> NodeCryptoTypes.BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<Tree> CREATE_ECDH =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes(NodeCryptoTypes.CRYPTO, NodeCryptoTypes.NODE_CRYPTO)
                    .forMethods("createECDH")
                    .withMethodParameter("string")
                    .shouldBeDetectedAs(new CurveFactory<>())
                    .buildForContext(new KeyAgreementContext(Map.of("algorithm", "ECDH")))
                    .inBundle(() -> NodeCryptoTypes.BUNDLE)
                    .withDependingDetectionRules(List.of(ECDH_COMPUTE_SECRET, ECDH_GENERATE_KEYS));

    private static final Supplier<List<IDetectionRule<Tree>>> RULES =
            Memoize.of(NodeCryptoKeyAgreement::buildRules);

    @Nonnull
    public static List<IDetectionRule<Tree>> rules() {
        return RULES.get();
    }

    @Nonnull
    private static List<IDetectionRule<Tree>> buildRules() {
        return List.of(CREATE_DIFFIE_HELLMAN, CREATE_ECDH);
    }
}
