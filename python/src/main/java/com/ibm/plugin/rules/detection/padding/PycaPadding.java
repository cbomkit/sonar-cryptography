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
package com.ibm.plugin.rules.detection.padding;

import com.ibm.engine.model.Size;
import com.ibm.engine.model.context.CipherContext;
import com.ibm.engine.model.factory.BlockSizeFactory;
import com.ibm.engine.model.factory.ValueActionFactory;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import com.ibm.plugin.rules.detection.Memoize;
import com.ibm.plugin.rules.detection.symmetric.PycaCipher;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.function.Supplier;
import javax.annotation.Nonnull;
import org.sonar.plugins.python.api.tree.Tree;

@SuppressWarnings("java:S1192")
public final class PycaPadding {

    private PycaPadding() {
        // private
    }

    private static final List<String> paddings = Arrays.asList("PKCS7", "ANSIX923");

    private static @Nonnull List<IDetectionRule<Tree>> newPadding() {
        final LinkedList<IDetectionRule<Tree>> rules = new LinkedList<>();

        for (String padding : paddings) {
            rules.add(
                    new DetectionRuleBuilder<Tree>()
                            .createDetectionRule()
                            .forObjectTypes("cryptography.hazmat.primitives.padding")
                            .forMethods(padding)
                            .shouldBeDetectedAs(new ValueActionFactory<>(padding))
                            .withMethodParameter("int")
                            .shouldBeDetectedAs(new BlockSizeFactory<>(Size.UnitType.BIT))
                            .asChildOfParameterWithId(0)
                            .buildForContext(new CipherContext(Map.of("kind", "padding")))
                            .inBundle(() -> "Pyca")
                            .withoutDependingDetectionRules());
        }
        // When the block size is specified using a `block_size` attribute
        for (String padding : paddings) {
            for (String cipherAlgorithm : PycaCipher.blockCiphers) {
                rules.add(
                        new DetectionRuleBuilder<Tree>()
                                .createDetectionRule()
                                .forObjectTypes("cryptography.hazmat.primitives.padding")
                                .forMethods(padding)
                                .shouldBeDetectedAs(new ValueActionFactory<>(padding))
                                .withMethodParameter(
                                        "cryptography.hazmat.primitives.ciphers.algorithms."
                                                + cipherAlgorithm
                                                + ".block_size")
                                .shouldBeDetectedAs(new BlockSizeFactory<>(Size.UnitType.BIT))
                                .asChildOfParameterWithId(0)
                                .buildForContext(new CipherContext(Map.of("kind", "padding")))
                                .inBundle(() -> "Pyca")
                                .withoutDependingDetectionRules());
            }
        }
        return rules;
    }

    // It should be better to only detect Padding when it actually gets implied (i.e. there is
    // `padder.update` function call). However, it does not bring much, and creates problems
    // because the type handler may not distinguish an `encryptor.update` from `padder.update`.

    private static final Supplier<List<IDetectionRule<Tree>>> RULES =
            Memoize.of(PycaPadding::buildRules);

    @Nonnull
    public static List<IDetectionRule<Tree>> rules() {
        return RULES.get();
    }

    @Nonnull
    private static List<IDetectionRule<Tree>> buildRules() {
        return newPadding();
    }
}
