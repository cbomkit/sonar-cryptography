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
package com.ibm.plugin.rules.detection.mac;

import static com.ibm.engine.detection.MethodMatcher.ANY;

import com.ibm.engine.model.context.MacContext;
import com.ibm.engine.model.factory.AlgorithmFactory;
import com.ibm.engine.model.factory.ValueActionFactory;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import com.ibm.plugin.rules.detection.Memoize;
import java.util.List;
import java.util.Map;
import java.util.function.Supplier;
import javax.annotation.Nonnull;
import org.sonar.plugins.python.api.tree.Tree;

@SuppressWarnings("java:S1192")
public final class PycaMAC {

    private PycaMAC() {
        // private
    }

    private static final IDetectionRule<Tree> NEW_CMAC =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("cryptography.hazmat.primitives.cmac")
                    .forMethods("CMAC")
                    .withMethodParameter("cryptography.hazmat.primitives.ciphers.algorithms.*")
                    .shouldBeDetectedAs(new AlgorithmFactory<>())
                    .buildForContext(new MacContext(Map.of("kind", "cmac")))
                    .inBundle(() -> "Pyca")
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<Tree> NEW_HMAC =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("cryptography.hazmat.primitives.hmac")
                    .forMethods("HMAC")
                    .withMethodParameter(ANY)
                    .withMethodParameter(
                            "cryptography.hazmat.primitives.hashes.*") // Accepts only hashes (not
                    // pre-hashes)
                    .shouldBeDetectedAs(new AlgorithmFactory<>())
                    .buildForContext(new MacContext(Map.of("kind", "hmac")))
                    .inBundle(() -> "Pyca")
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<Tree> NEW_POLY1305 =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("cryptography.hazmat.primitives.poly1305")
                    .forMethods("Poly1305")
                    .shouldBeDetectedAs(new ValueActionFactory<>("Poly1305"))
                    .withAnyParameters()
                    .buildForContext(new MacContext())
                    .inBundle(() -> "Pyca")
                    .withoutDependingDetectionRules();

    private static final Supplier<List<IDetectionRule<Tree>>> RULES =
            Memoize.of(PycaMAC::buildRules);

    @Nonnull
    public static List<IDetectionRule<Tree>> rules() {
        return RULES.get();
    }

    @Nonnull
    private static List<IDetectionRule<Tree>> buildRules() {
        return List.of(NEW_CMAC, NEW_HMAC, NEW_POLY1305);
    }
}
