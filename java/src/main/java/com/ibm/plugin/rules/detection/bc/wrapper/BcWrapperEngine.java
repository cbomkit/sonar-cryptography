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
package com.ibm.plugin.rules.detection.bc.wrapper;

import com.ibm.engine.model.Size;
import com.ibm.engine.model.context.CipherContext;
import com.ibm.engine.model.factory.BlockSizeFactory;
import com.ibm.engine.model.factory.ValueActionFactory;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import com.ibm.plugin.rules.detection.Memoize;
import com.ibm.plugin.rules.detection.bc.blockcipher.BcBlockCipherEngine;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.function.Supplier;
import java.util.stream.Stream;
import javax.annotation.Nonnull;
import org.sonar.plugins.java.api.tree.Tree;

public final class BcWrapperEngine {

    private BcWrapperEngine() {
        // nothing
    }

    private static final List<String> engines =
            Arrays.asList(
                    "AESWrapEngine",
                    "AESWrapPadEngine",
                    "ARIAWrapEngine",
                    "ARIAWrapPadEngine",
                    "CamelliaWrapEngine",
                    "CryptoProWrapEngine",
                    "DESedeWrapEngine",
                    "GOST28147WrapEngine",
                    "RC2WrapEngine",
                    "SEEDWrapEngine");

    private static @Nonnull List<IDetectionRule<Tree>> simpleConstructors() {
        List<IDetectionRule<Tree>> constructorsList = new LinkedList<>();

        for (String engine : engines) {

            constructorsList.add(
                    new DetectionRuleBuilder<Tree>()
                            .createDetectionRule()
                            .forObjectTypes("org.bouncycastle.crypto.engines." + engine)
                            .forConstructor()
                            .shouldBeDetectedAs(new ValueActionFactory<>(engine))
                            // We want to capture all possible constructors (some have arguments)
                            .withAnyParameters()
                            .buildForContext(new CipherContext(Map.of("kind", "WRAP")))
                            .inBundle(() -> "Bc")
                            .withDependingDetectionRules(BcWrapperInit.rules()));
        }

        return constructorsList;
    }

    private static @Nonnull List<IDetectionRule<Tree>> specialConstructors() {
        List<IDetectionRule<Tree>> constructorsList = new LinkedList<>();

        constructorsList.add(
                new DetectionRuleBuilder<Tree>()
                        .createDetectionRule()
                        .forObjectTypes("org.bouncycastle.crypto.engines.DSTU7624WrapEngine")
                        .forConstructor()
                        .shouldBeDetectedAs(new ValueActionFactory<>("DSTU7624WrapEngine"))
                        .withMethodParameter("int")
                        .shouldBeDetectedAs(new BlockSizeFactory<>(Size.UnitType.BIT))
                        .asChildOfParameterWithId(-1)
                        .buildForContext(new CipherContext(Map.of("kind", "WRAP")))
                        .inBundle(() -> "Bc")
                        .withDependingDetectionRules(BcWrapperInit.rules()));

        constructorsList.add(
                new DetectionRuleBuilder<Tree>()
                        .createDetectionRule()
                        .forObjectTypes("org.bouncycastle.crypto.engines.RFC5649WrapEngine")
                        .forConstructor()
                        .shouldBeDetectedAs(new ValueActionFactory<>("RFC5649WrapEngine"))
                        .withMethodParameter("org.bouncycastle.crypto.BlockCipher")
                        .addDependingDetectionRules(BcBlockCipherEngine.rules())
                        .buildForContext(new CipherContext(Map.of("kind", "WRAP")))
                        .inBundle(() -> "Bc")
                        .withDependingDetectionRules(BcWrapperInit.rules()));

        constructorsList.add(
                new DetectionRuleBuilder<Tree>()
                        .createDetectionRule()
                        .forObjectTypes("org.bouncycastle.crypto.engines.RFC3394WrapEngine")
                        .forConstructor()
                        .shouldBeDetectedAs(new ValueActionFactory<>("RFC3394WrapEngine"))
                        .withMethodParameter("org.bouncycastle.crypto.BlockCipher")
                        .addDependingDetectionRules(BcBlockCipherEngine.rules())
                        .buildForContext(new CipherContext(Map.of("kind", "WRAP")))
                        .inBundle(() -> "Bc")
                        .withDependingDetectionRules(BcWrapperInit.rules()));

        constructorsList.add(
                new DetectionRuleBuilder<Tree>()
                        .createDetectionRule()
                        .forObjectTypes("org.bouncycastle.crypto.engines.RFC3394WrapEngine")
                        .forConstructor()
                        .shouldBeDetectedAs(new ValueActionFactory<>("RFC3394WrapEngine"))
                        .withMethodParameter("org.bouncycastle.crypto.BlockCipher")
                        .addDependingDetectionRules(BcBlockCipherEngine.rules())
                        .withMethodParameter("boolean")
                        .buildForContext(new CipherContext(Map.of("kind", "WRAP")))
                        .inBundle(() -> "Bc")
                        .withDependingDetectionRules(BcWrapperInit.rules()));

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
