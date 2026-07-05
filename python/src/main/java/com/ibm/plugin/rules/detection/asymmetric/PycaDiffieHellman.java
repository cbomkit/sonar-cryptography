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
package com.ibm.plugin.rules.detection.asymmetric;

import static com.ibm.engine.detection.MethodMatcher.ANY;

import com.ibm.engine.model.KeyAction;
import com.ibm.engine.model.Size;
import com.ibm.engine.model.context.PrivateKeyContext;
import com.ibm.engine.model.context.PublicKeyContext;
import com.ibm.engine.model.factory.KeyActionFactory;
import com.ibm.engine.model.factory.KeySizeFactory;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import com.ibm.plugin.rules.detection.Memoize;
import java.util.List;
import java.util.Map;
import java.util.function.Supplier;
import javax.annotation.Nonnull;
import org.sonar.plugins.python.api.tree.Tree;

@SuppressWarnings("java:S1192")
public final class PycaDiffieHellman {

    private PycaDiffieHellman() {
        // private
    }

    private static final String TYPE = "cryptography.hazmat.primitives.asymmetric.dh";

    // The key size does not yet appear in PycaDiffieHellmanGenerateTestFile because
    //  of the TraceSymbol problem documented on the Github issue
    private static final IDetectionRule<Tree> GENERATE_PARAMETERS_DH =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes(TYPE)
                    .forMethods("generate_parameters")
                    .withMethodParameter(ANY)
                    .withMethodParameter("int")
                    .shouldBeDetectedAs(new KeySizeFactory<>(Size.UnitType.BIT))
                    .buildForContext(new PrivateKeyContext(Map.of("algorithm", "DH")))
                    .inBundle(() -> "Pyca")
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<Tree> GENERATION_DH =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes(TYPE + ".generate_parameters")
                    .forMethods("generate_private_key")
                    .shouldBeDetectedAs(new KeyActionFactory<>(KeyAction.Action.GENERATION))
                    .withAnyParameters()
                    .buildForContext(
                            new PrivateKeyContext(
                                    Map.of(
                                            "algorithm", "DH",
                                            "includePublicKey", "true")))
                    .inBundle(() -> "Pyca")
                    .withDependingDetectionRules(List.of(GENERATE_PARAMETERS_DH));

    private static final IDetectionRule<Tree> PUBLIC_NUMBERS_DH =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes(TYPE)
                    .forMethods("DHPublicNumbers")
                    .shouldBeDetectedAs(new KeyActionFactory<>(KeyAction.Action.GENERATION))
                    .withAnyParameters()
                    .buildForContext(new PublicKeyContext(Map.of("algorithm", "DH")))
                    .inBundle(() -> "Pyca")
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<Tree> PRIVATE_NUMBERS_DH =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes(TYPE)
                    .forMethods("DHPrivateNumbers")
                    .shouldBeDetectedAs(new KeyActionFactory<>(KeyAction.Action.GENERATION))
                    .withAnyParameters()
                    .buildForContext(new PublicKeyContext(Map.of("algorithm", "DH")))
                    .inBundle(() -> "CryptographyDiffieHellman")
                    .withoutDependingDetectionRules();

    private static final Supplier<List<IDetectionRule<Tree>>> RULES =
            Memoize.of(PycaDiffieHellman::buildRules);

    @Nonnull
    public static List<IDetectionRule<Tree>> rules() {
        return RULES.get();
    }

    @Nonnull
    private static List<IDetectionRule<Tree>> buildRules() {
        return List.of(GENERATION_DH, PUBLIC_NUMBERS_DH, PRIVATE_NUMBERS_DH);
    }
}
