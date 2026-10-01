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
package com.ibm.plugin.rules.resolve;

import com.ibm.engine.model.context.PrivateKeyContext;
import com.ibm.engine.model.factory.AlgorithmFactory;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import java.util.List;
import java.util.Map;
import javax.annotation.Nonnull;
import org.sonar.plugins.python.api.tree.Tree;

@SuppressWarnings("java:S1192")
public final class ResolveAliasImport {
    // This class of rules is not made private for testing purposes: it is accessed directly by the
    // test class to test *only* these rules

    private static final IDetectionRule<Tree> TEST_1 =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("cryptography.hazmat.primitives.asymmetric.ec")
                    .forMethods("generate_private_key")
                    .withMethodParameter("cryptography.hazmat.primitives.asymmetric.ec.*")
                    .shouldBeDetectedAs(new AlgorithmFactory<>())
                    .buildForContext(new PrivateKeyContext(Map.of("kind", "UNKNOWN")))
                    .inBundle(() -> "ResolveAliasImport")
                    .withoutDependingDetectionRules();

    private ResolveAliasImport() {
        // nothing
    }

    @Nonnull
    public static List<IDetectionRule<Tree>> rules() {
        return List.of(TEST_1);
    }
}
