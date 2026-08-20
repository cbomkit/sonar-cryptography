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
package com.ibm.plugin.rules.detection.bc.asymmetricblockcipher;

import com.ibm.engine.model.context.IDetectionContext;
import com.ibm.engine.rule.ContextualDetectionRuleSet;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.RuleSets;
import java.util.List;
import java.util.stream.Stream;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import org.sonar.plugins.java.api.tree.Tree;

public final class BcAsymmetricBlockCipher extends ContextualDetectionRuleSet<Tree> {

    @Nonnull
    @Override
    protected List<IDetectionRule<Tree>> buildRules(@Nonnull List<IDetectionContext> contexts) {
        return constructors(contextAt(contexts, 0), contextAt(contexts, 1));
    }

    @Nonnull
    private static List<IDetectionRule<Tree>> constructors(
            @Nullable IDetectionContext encodingDetectionValueContext,
            @Nullable IDetectionContext engineDetectionValueContext) {
        return Stream.of(
                        RuleSets.rulesOf(
                                BcPKCS1Encoding.class,
                                encodingDetectionValueContext,
                                engineDetectionValueContext)
                                .stream(),
                        RuleSets.rulesOf(
                                BcOAEPEncoding.class,
                                encodingDetectionValueContext,
                                engineDetectionValueContext)
                                .stream(),
                        RuleSets.rulesOf(
                                BcISO9796d1Encoding.class,
                                encodingDetectionValueContext,
                                engineDetectionValueContext)
                                .stream(),
                        RuleSets.rulesOf(BcAsymCipherEngine.class, engineDetectionValueContext)
                                .stream())
                .flatMap(i -> i)
                .toList();
    }
}
