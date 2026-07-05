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
package com.ibm.plugin.rules.detection.bc.keygenerationparameters;

import com.ibm.engine.model.Size;
import com.ibm.engine.model.context.KeyContext;
import com.ibm.engine.model.factory.KeySizeFactory;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import com.ibm.plugin.rules.detection.Memoize;
import java.util.List;
import java.util.Map;
import java.util.function.Supplier;
import javax.annotation.Nonnull;
import org.sonar.plugins.java.api.tree.Tree;

public final class BcRSAKeyGenerationParameters {

    private BcRSAKeyGenerationParameters() {
        // nothing
    }

    private static final String CLASS = "RSAKeyGenerationParameters";

    private static final IDetectionRule<Tree> CONSTRUCTOR =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("org.bouncycastle.crypto.params." + CLASS)
                    .forConstructor()
                    .withMethodParameter("java.math.BigInteger")
                    .withMethodParameter("java.security.SecureRandom")
                    .withMethodParameter("int")
                    .shouldBeDetectedAs(new KeySizeFactory<>(Size.UnitType.BIT))
                    .asChildOfParameterWithId(-1)
                    .withMethodParameter("int")
                    .buildForContext(new KeyContext(Map.of("kind", "PKE")))
                    .inBundle(() -> "Bc")
                    .withoutDependingDetectionRules();

    private static final Supplier<List<IDetectionRule<Tree>>> RULES =
            Memoize.of(() -> List.of(CONSTRUCTOR));

    @Nonnull
    public static List<IDetectionRule<Tree>> rules() {
        return RULES.get();
    }
}
