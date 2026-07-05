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
package com.ibm.plugin.rules.detection.keyagreement;

import com.ibm.engine.model.KeyAction;
import com.ibm.engine.model.context.KeyAgreementContext;
import com.ibm.engine.model.factory.KeyActionFactory;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import com.ibm.plugin.rules.detection.Memoize;
import java.util.List;
import java.util.Map;
import java.util.function.Supplier;
import javax.annotation.Nonnull;
import org.sonar.plugins.python.api.tree.Tree;

@SuppressWarnings("java:S1192")
public final class PycaKeyAgreement {

    private PycaKeyAgreement() {
        // private
    }

    private static final IDetectionRule<Tree> GENERATION_X25519 =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes(
                            "cryptography.hazmat.primitives.asymmetric.x25519.X25519PrivateKey")
                    .forMethods("generate")
                    .shouldBeDetectedAs(new KeyActionFactory<>(KeyAction.Action.GENERATION))
                    .withoutParameters()
                    .buildForContext(new KeyAgreementContext(Map.of("algorithm", "x25519")))
                    .inBundle(() -> "Pyca")
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<Tree> GENERATION_X448 =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("cryptography.hazmat.primitives.asymmetric.x448.X448PrivateKey")
                    .forMethods("generate")
                    .shouldBeDetectedAs(new KeyActionFactory<>(KeyAction.Action.GENERATION))
                    .withoutParameters()
                    .buildForContext(new KeyAgreementContext(Map.of("algorithm", "x448")))
                    .inBundle(() -> "Pyca")
                    .withoutDependingDetectionRules();

    private static final Supplier<List<IDetectionRule<Tree>>> RULES =
            Memoize.of(PycaKeyAgreement::buildRules);

    @Nonnull
    public static List<IDetectionRule<Tree>> rules() {
        return RULES.get();
    }

    @Nonnull
    private static List<IDetectionRule<Tree>> buildRules() {
        return List.of(GENERATION_X25519, GENERATION_X448);
    }
}
