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
package com.ibm.plugin.rules.detection.bc.derivationfunction;

import com.ibm.engine.model.context.KeyContext;
import com.ibm.engine.model.factory.OperationModeFactory;
import com.ibm.engine.model.factory.ValueActionFactory;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import com.ibm.plugin.rules.detection.Memoize;
import com.ibm.plugin.rules.detection.bc.BouncyCastleInfoMap;
import com.ibm.plugin.rules.detection.bc.digest.BcDigests;
import com.ibm.plugin.rules.detection.bc.mac.BcMac;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.function.Supplier;
import java.util.stream.Stream;
import javax.annotation.Nonnull;
import org.sonar.plugins.java.api.tree.Tree;

public final class BcDerivationFunction {

    private BcDerivationFunction() {
        // nothing
    }

    private static BouncyCastleInfoMap digestDerivationFunctionMap = new BouncyCastleInfoMap();
    private static BouncyCastleInfoMap macDerivationFunctionMap = new BouncyCastleInfoMap();

    static {
        /*
         * When no name is explicitly defined, it is because I haven't
         * found a "good" standardized name for the algorithm
         */
        digestDerivationFunctionMap
                .putKey("BrokenKDF2BytesGenerator")
                .putType("org.bouncycastle.jce.provider.");
        digestDerivationFunctionMap
                .putKey("ConcatenationKDFGenerator")
                .putType("org.bouncycastle.crypto.agreement.kdf.");
        digestDerivationFunctionMap
                .putKey("DHKEKGenerator")
                .putType("org.bouncycastle.crypto.agreement.kdf.");
        digestDerivationFunctionMap
                .putKey("ECDHKEKGenerator")
                .putType("org.bouncycastle.crypto.agreement.kdf.");
        digestDerivationFunctionMap
                .putKey("GSKKFDGenerator")
                .putType("org.bouncycastle.crypto.agreement.kdf.");
        digestDerivationFunctionMap
                .putKey("HKDFBytesGenerator")
                .putType("org.bouncycastle.crypto.generators.");
        digestDerivationFunctionMap
                .putKey("KDF1BytesGenerator")
                .putType("org.bouncycastle.crypto.generators.");
        digestDerivationFunctionMap
                .putKey("KDF2BytesGenerator")
                .putType("org.bouncycastle.crypto.generators.");
        digestDerivationFunctionMap
                .putKey("MGF1BytesGenerator")
                .putType("org.bouncycastle.crypto.generators.");

        macDerivationFunctionMap.putKey("KDFCounterBytesGenerator");
        macDerivationFunctionMap.putKey("KDFDoublePipelineIterationBytesGenerator");
        macDerivationFunctionMap.putKey("KDFFeedbackBytesGenerator");
    }

    private static @Nonnull List<IDetectionRule<Tree>> simpleConstructors() {

        List<IDetectionRule<Tree>> constructorsList = new LinkedList<>();

        for (Map.Entry<String, BouncyCastleInfoMap.Info> entry :
                digestDerivationFunctionMap.entrySet()) {
            String generator = entry.getKey();
            String type = entry.getValue().getType();
            constructorsList.add(
                    new DetectionRuleBuilder<Tree>()
                            .createDetectionRule()
                            .forObjectTypes(type + generator)
                            .forConstructor()
                            .shouldBeDetectedAs(new ValueActionFactory<>(generator))
                            .withMethodParameter("org.bouncycastle.crypto.Digest")
                            .addDependingDetectionRules(BcDigests.rules())
                            .buildForContext(new KeyContext(Map.of("kind", "KDF")))
                            .inBundle(() -> "Bc")
                            .withoutDependingDetectionRules());
        }

        for (Map.Entry<String, BouncyCastleInfoMap.Info> entry :
                macDerivationFunctionMap.entrySet()) {
            String generator = entry.getKey();
            constructorsList.add(
                    new DetectionRuleBuilder<Tree>()
                            .createDetectionRule()
                            .forObjectTypes("org.bouncycastle.crypto.generators." + generator)
                            .forConstructor()
                            .shouldBeDetectedAs(new ValueActionFactory<>(generator))
                            .withMethodParameter("org.bouncycastle.crypto.Mac")
                            .addDependingDetectionRules(BcMac.rules())
                            .buildForContext(new KeyContext(Map.of("kind", "KDF")))
                            .inBundle(() -> "Bc")
                            .withoutDependingDetectionRules());
        }

        return constructorsList;
    }

    private static @Nonnull List<IDetectionRule<Tree>> specialConstructors() {
        List<IDetectionRule<Tree>> constructorsList = new LinkedList<>();

        constructorsList.add(
                new DetectionRuleBuilder<Tree>()
                        .createDetectionRule()
                        .forObjectTypes(
                                "org.bouncycastle.crypto.engines.EthereumIESEngine$HandshakeKDFFunction")
                        .forConstructor()
                        .withMethodParameter("int") /* this determines whether its KDF1 or KDF2 */
                        .shouldBeDetectedAs(new OperationModeFactory<>())
                        .withMethodParameter("org.bouncycastle.crypto.Digest")
                        .addDependingDetectionRules(BcDigests.rules())
                        .buildForContext(new KeyContext(Map.of("kind", "KDF")))
                        .inBundle(() -> "Bc")
                        .withoutDependingDetectionRules());

        return constructorsList;
    }

    private static final Supplier<List<IDetectionRule<Tree>>> RULES =
            Memoize.of(
                    () ->
                            Stream.of(simpleConstructors().stream(), specialConstructors().stream())
                                    .flatMap(i -> i)
                                    .toList());

    @Nonnull
    public static List<IDetectionRule<Tree>> rules() {
        return RULES.get();
    }
}
