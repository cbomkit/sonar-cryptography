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
package com.ibm.plugin.rules.detection.jca.keyspec;

import static com.ibm.plugin.rules.detection.TypeShortcuts.BIGINTEGER_TYPE;

import com.ibm.engine.model.Size;
import com.ibm.engine.model.context.KeyContext;
import com.ibm.engine.model.factory.KeySizeFactory;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import com.ibm.plugin.rules.detection.Memoize;
import java.util.List;
import java.util.function.Supplier;
import javax.annotation.Nonnull;
import org.sonar.plugins.java.api.tree.Tree;

public final class JcaDSAPrivateKeySpec {

    private static final IDetectionRule<Tree> DSA_PRIVATE_KEY_SPEC =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("java.security.spec.DSAPrivateKeySpec")
                    .forConstructor()
                    .withMethodParameter(BIGINTEGER_TYPE)
                    .withMethodParameter(BIGINTEGER_TYPE)
                    .shouldBeDetectedAs(new KeySizeFactory<>(Size.UnitType.PRIME_P))
                    .withMethodParameter(BIGINTEGER_TYPE)
                    .withMethodParameter(BIGINTEGER_TYPE)
                    .buildForContext(new KeyContext(KeyContext.Kind.DSA))
                    .inBundle(() -> "Jca")
                    .withoutDependingDetectionRules();

    private JcaDSAPrivateKeySpec() {
        // nothing
    }

    private static final Supplier<List<IDetectionRule<Tree>>> RULES =
            Memoize.of(JcaDSAPrivateKeySpec::buildRules);

    @Nonnull
    public static List<IDetectionRule<Tree>> rules() {
        return RULES.get();
    }

    @Nonnull
    private static List<IDetectionRule<Tree>> buildRules() {
        return List.of(DSA_PRIVATE_KEY_SPEC);
    }
}
