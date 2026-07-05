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
package com.ibm.plugin.rules.detection.jca.mac;

import static com.ibm.plugin.rules.detection.TypeShortcuts.STRING_TYPE;

import com.ibm.engine.model.context.MacContext;
import com.ibm.engine.model.factory.AlgorithmFactory;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import com.ibm.plugin.rules.detection.Memoize;
import java.util.List;
import java.util.function.Supplier;
import javax.annotation.Nonnull;
import org.sonar.plugins.java.api.tree.Tree;

public final class JcaMacGetInstance {

    private static final IDetectionRule<Tree> MAC_GET_INSTANCE_1 =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("javax.crypto.Mac")
                    .forMethods("getInstance")
                    .withMethodParameter(STRING_TYPE)
                    .shouldBeDetectedAs(new AlgorithmFactory<>())
                    .buildForContext(new MacContext())
                    .inBundle(() -> "Jca")
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<Tree> MAC_GET_INSTANCE_2 =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("javax.crypto.Mac")
                    .forMethods("getInstance")
                    .withMethodParameter(STRING_TYPE)
                    .shouldBeDetectedAs(new AlgorithmFactory<>())
                    .withMethodParameter(STRING_TYPE)
                    .buildForContext(new MacContext())
                    .inBundle(() -> "Jca")
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<Tree> MAC_GET_INSTANCE_3 =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("javax.crypto.Mac")
                    .forMethods("getInstance")
                    .withMethodParameter(STRING_TYPE)
                    .shouldBeDetectedAs(new AlgorithmFactory<>())
                    .withMethodParameter(STRING_TYPE)
                    .withMethodParameter("java.security.Provider")
                    .buildForContext(new MacContext())
                    .inBundle(() -> "Jca")
                    .withoutDependingDetectionRules();

    private JcaMacGetInstance() {
        // nothing
    }

    private static final Supplier<List<IDetectionRule<Tree>>> RULES =
            Memoize.of(JcaMacGetInstance::buildRules);

    @Nonnull
    public static List<IDetectionRule<Tree>> rules() {
        return RULES.get();
    }

    @Nonnull
    private static List<IDetectionRule<Tree>> buildRules() {
        return List.of(MAC_GET_INSTANCE_1, MAC_GET_INSTANCE_2, MAC_GET_INSTANCE_3);
    }
}
