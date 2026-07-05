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
package com.ibm.plugin.rules.detection.bc.aeadcipher;

import com.ibm.engine.model.AlgorithmParameter;
import com.ibm.engine.model.context.CipherContext;
import com.ibm.engine.model.factory.AlgorithmParameterFactory;
import com.ibm.engine.model.factory.ValueActionFactory;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import com.ibm.plugin.rules.detection.Memoize;
import com.ibm.plugin.rules.detection.bc.BouncyCastleInfoMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.function.Supplier;
import javax.annotation.Nonnull;
import org.sonar.plugins.java.api.tree.Tree;

public final class BcAEADCipherEngine {

    private BcAEADCipherEngine() {
        // nothing
    }

    private static final BouncyCastleInfoMap infoMap = new BouncyCastleInfoMap();

    static {
        infoMap.putKey("AsconEngine").putParameterClass("AsconParameters");
        infoMap.putKey("ElephantEngine").putParameterClass("ElephantParameters");
        infoMap.putKey("Grain128AEADEngine");
        infoMap.putKey("IsapEngine").putParameterClass("IsapType");
        infoMap.putKey("PhotonBeetleEngine").putParameterClass("PhotonBeetleParameters");
        infoMap.putKey("SparkleEngine").putParameterClass("SparkleParameters");
        infoMap.putKey("XoodyakEngine");
    }

    // Because these AEAD engines are not used as engines for other classes, we assume that they are
    // only used alone. It is then safe to add them "init" as depending detection rule.
    private static @Nonnull List<IDetectionRule<Tree>> constructors() {
        List<IDetectionRule<Tree>> constructorsList = new LinkedList<>();

        for (Map.Entry<String, BouncyCastleInfoMap.Info> entry : infoMap.entrySet()) {
            final String engine = entry.getKey();
            final String parameters = entry.getValue().getParameterClass();

            if (parameters == null) {
                constructorsList.add(
                        new DetectionRuleBuilder<Tree>()
                                .createDetectionRule()
                                .forObjectTypes("org.bouncycastle.crypto.engines." + engine)
                                .forConstructor()
                                .shouldBeDetectedAs(new ValueActionFactory<>(engine))
                                .withoutParameters()
                                .buildForContext(new CipherContext(Map.of("kind", "AEAD_ENGINE")))
                                .inBundle(() -> "Bc")
                                .withDependingDetectionRules(BcAEADCipherInit.rules()));
            } else {
                constructorsList.add(
                        new DetectionRuleBuilder<Tree>()
                                .createDetectionRule()
                                .forObjectTypes("org.bouncycastle.crypto.engines." + engine)
                                .forConstructor()
                                .shouldBeDetectedAs(new ValueActionFactory<>(engine))
                                .withMethodParameter(
                                        "org.bouncycastle.crypto.engines."
                                                + engine
                                                + "$"
                                                + parameters)
                                .shouldBeDetectedAs(
                                        new AlgorithmParameterFactory<>(
                                                AlgorithmParameter.Kind.ANY))
                                .asChildOfParameterWithId(-1)
                                .buildForContext(new CipherContext(Map.of("kind", "AEAD_ENGINE")))
                                .inBundle(() -> "Bc")
                                .withDependingDetectionRules(BcAEADCipherInit.rules()));
            }
        }
        return constructorsList;
    }

    private static final Supplier<List<IDetectionRule<Tree>>> RULES =
            Memoize.of(() -> constructors());

    @Nonnull
    public static List<IDetectionRule<Tree>> rules() {
        return RULES.get();
    }
}
