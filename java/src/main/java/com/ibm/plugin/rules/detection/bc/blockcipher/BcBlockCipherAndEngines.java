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
package com.ibm.plugin.rules.detection.bc.blockcipher;

import com.ibm.engine.model.context.IDetectionContext;
import com.ibm.engine.rule.ContextualDetectionRuleSet;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.RuleSet;
import java.util.List;
import java.util.stream.Stream;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import org.sonar.plugins.java.api.tree.Tree;

/**
 * Combines block-cipher mode and engine rules for callers that accept either form. The same context
 * override is passed to both rule sets. This replaces the former {@code BcBlockCipher.all()}
 * accessor.
 */
public final class BcBlockCipherAndEngines
        extends ContextualDetectionRuleSet<Tree, IDetectionContext> {

    @Nonnull
    @Override
    protected List<IDetectionRule<Tree>> buildRules(@Nullable IDetectionContext context) {
        return Stream.of(
                        RuleSet.of(BcBlockCipher.class).withOverrides(context).stream(),
                        RuleSet.of(BcBlockCipherEngine.class).withOverrides(context).stream())
                .flatMap(i -> i)
                .toList();
    }
}
