/*
 * Sonar Cryptography Plugin
 * Copyright (C) 2025 PQCA
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
package com.ibm.plugin.rules.detection.jca.algorithmspec;

import com.ibm.engine.model.Mode;
import com.ibm.engine.model.Size;
import com.ibm.engine.model.context.AlgorithmParameterContext;
import com.ibm.engine.model.factory.InitializationVectorSizeFactory;
import com.ibm.engine.model.factory.TagSizeFactory;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import com.ibm.plugin.rules.detection.Memoize;
import java.util.List;
import java.util.Optional;
import java.util.function.Supplier;
import javax.annotation.Nonnull;
import org.sonar.plugins.java.api.tree.Tree;

public final class JcaGCMParameterSpec {

    private static final IDetectionRule<Tree> GCM_PARAMETER_SPEC1 =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("javax.crypto.spec.GCMParameterSpec")
                    .forConstructor()
                    .shouldBeDetectedAs(tree -> Optional.of(new Mode<>("GCM", tree)))
                    .withMethodParameter("int")
                    .shouldBeDetectedAs(new TagSizeFactory<>(Size.UnitType.BIT))
                    .withMethodParameter("byte[]")
                    .shouldBeDetectedAs(new InitializationVectorSizeFactory<>(Size.UnitType.BYTE))
                    .buildForContext(new AlgorithmParameterContext())
                    .inBundle(() -> "Jca")
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<Tree> GCM_PARAMETER_SPEC2 =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("javax.crypto.spec.GCMParameterSpec")
                    .forConstructor()
                    .shouldBeDetectedAs(tree -> Optional.of(new Mode<>("GCM", tree)))
                    .withMethodParameter("int")
                    .shouldBeDetectedAs(new TagSizeFactory<>(Size.UnitType.BIT))
                    .withMethodParameter("byte[]")
                    .withMethodParameter("int")
                    .withMethodParameter("int")
                    .shouldBeDetectedAs(new InitializationVectorSizeFactory<>(Size.UnitType.BYTE))
                    .buildForContext(new AlgorithmParameterContext())
                    .inBundle(() -> "Jca")
                    .withoutDependingDetectionRules();

    private JcaGCMParameterSpec() {
        // nothing
    }

    private static final Supplier<List<IDetectionRule<Tree>>> RULES =
            Memoize.of(JcaGCMParameterSpec::buildRules);

    @Nonnull
    public static List<IDetectionRule<Tree>> rules() {
        return RULES.get();
    }

    @Nonnull
    private static List<IDetectionRule<Tree>> buildRules() {
        return List.of(GCM_PARAMETER_SPEC1, GCM_PARAMETER_SPEC2);
    }
}
