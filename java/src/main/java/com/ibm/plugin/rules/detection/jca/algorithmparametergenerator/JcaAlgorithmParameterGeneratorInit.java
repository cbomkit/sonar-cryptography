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
package com.ibm.plugin.rules.detection.jca.algorithmparametergenerator;

import com.ibm.engine.model.Size;
import com.ibm.engine.model.context.AlgorithmParameterContext;
import com.ibm.engine.model.factory.KeySizeFactory;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import com.ibm.plugin.rules.detection.Memoize;
import com.ibm.plugin.rules.detection.jca.algorithmspec.JcaAlgorithmParameterSpec;
import java.util.List;
import java.util.function.Supplier;
import javax.annotation.Nonnull;
import org.sonar.plugins.java.api.tree.Tree;

public final class JcaAlgorithmParameterGeneratorInit {

    private static final IDetectionRule<Tree> PARAMETER_INIT_1 =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("java.security.AlgorithmParameterGenerator")
                    .forMethods("init")
                    .withMethodParameter("java.security.spec.AlgorithmParameterSpec")
                    .addDependingDetectionRules(JcaAlgorithmParameterSpec.rules())
                    .buildForContext(new AlgorithmParameterContext())
                    .inBundle(() -> "Jca")
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<Tree> PARAMETER_INIT_2 =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("java.security.AlgorithmParameterGenerator")
                    .forMethods("init")
                    .withMethodParameter("java.security.spec.AlgorithmParameterSpec")
                    .addDependingDetectionRules(JcaAlgorithmParameterSpec.rules())
                    .withMethodParameter("java.security.SecureRandom")
                    .buildForContext(new AlgorithmParameterContext())
                    .inBundle(() -> "Jca")
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<Tree> PARAMETER_INIT_3 =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("java.security.AlgorithmParameterGenerator")
                    .forMethods("init")
                    .withMethodParameter("int")
                    .shouldBeDetectedAs(new KeySizeFactory<>(Size.UnitType.BIT))
                    .buildForContext(new AlgorithmParameterContext())
                    .inBundle(() -> "Jca")
                    .withoutDependingDetectionRules();
    private static final IDetectionRule<Tree> PARAMETER_INIT_4 =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("java.security.AlgorithmParameterGenerator")
                    .forMethods("init")
                    .withMethodParameter("int")
                    .shouldBeDetectedAs(new KeySizeFactory<>(Size.UnitType.BIT))
                    .withMethodParameter("java.security.SecureRandom")
                    .buildForContext(new AlgorithmParameterContext())
                    .inBundle(() -> "Jca")
                    .withoutDependingDetectionRules();

    private JcaAlgorithmParameterGeneratorInit() {
        // nothing
    }

    private static final Supplier<List<IDetectionRule<Tree>>> RULES =
            Memoize.of(JcaAlgorithmParameterGeneratorInit::buildRules);

    @Nonnull
    public static List<IDetectionRule<Tree>> rules() {
        return RULES.get();
    }

    @Nonnull
    private static List<IDetectionRule<Tree>> buildRules() {
        return List.of(PARAMETER_INIT_1, PARAMETER_INIT_2, PARAMETER_INIT_3, PARAMETER_INIT_4);
    }
}
