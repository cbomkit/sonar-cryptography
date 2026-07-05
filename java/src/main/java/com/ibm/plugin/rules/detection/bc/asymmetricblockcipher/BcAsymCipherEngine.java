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
package com.ibm.plugin.rules.detection.bc.asymmetricblockcipher;

import com.ibm.engine.model.context.CipherContext;
import com.ibm.engine.model.context.IDetectionContext;
import com.ibm.engine.model.factory.ValueActionFactory;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import com.ibm.plugin.rules.detection.Memoize;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.function.Supplier;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import org.sonar.plugins.java.api.tree.Tree;

public final class BcAsymCipherEngine {

    private BcAsymCipherEngine() {
        // nothing
    }

    public static final List<String> blockCiphers =
            List.of(
                    "ElGamalEngine",
                    "NaccacheSternEngine",
                    "NTRUEngine",
                    "RSABlindedEngine",
                    "RSABlindingEngine",
                    "RSAEngine");

    private static @Nonnull List<IDetectionRule<Tree>> constructors(
            @Nullable IDetectionContext detectionValueContext) {
        List<IDetectionRule<Tree>> constructorsList = new LinkedList<>();
        IDetectionContext context =
                detectionValueContext != null
                        ? detectionValueContext
                        : new CipherContext(Map.of("kind", "ASYMMETRIC_CIPHER_ENGINE"));

        for (String engine : blockCiphers) {
            constructorsList.add(
                    new DetectionRuleBuilder<Tree>()
                            .createDetectionRule()
                            .forObjectTypes("org.bouncycastle.crypto.engines." + engine)
                            .forConstructor()
                            .shouldBeDetectedAs(new ValueActionFactory<>(engine))
                            .withoutParameters()
                            .buildForContext(context)
                            .inBundle(() -> "Bc")
                            .withDependingDetectionRules(BcAsymCipherInit.rules()));
        }
        return constructorsList;
    }

    private static final Supplier<List<IDetectionRule<Tree>>> RULES =
            Memoize.of(() -> constructors(null));

    @Nonnull
    public static List<IDetectionRule<Tree>> rules() {
        return RULES.get();
    }

    @Nonnull
    public static List<IDetectionRule<Tree>> rules(
            @Nullable IDetectionContext detectionValueContext) {
        return detectionValueContext == null ? RULES.get() : constructors(detectionValueContext);
    }
}
