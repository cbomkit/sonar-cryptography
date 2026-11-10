/*
 * Sonar Cryptography Plugin
 * Copyright (C) 2026 PQCA
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
package com.ibm.plugin.rules;

import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.RuleSets;
import com.ibm.mapper.model.INode;
import com.ibm.plugin.javascript.tree.JavaScriptTree;
import com.ibm.plugin.rules.detection.JavaScriptBaseDetectionRule;
import com.ibm.plugin.rules.detection.JavaScriptDetectionRules;
import com.ibm.plugin.translation.reorganizer.JavaScriptReorganizerRules;
import com.ibm.rules.InventoryRule;
import com.ibm.rules.issue.Issue;
import java.util.List;
import javax.annotation.Nonnull;
import org.sonar.check.Rule;
import org.sonar.java.annotations.VisibleForTesting;

/** The single JavaScript/TypeScript cryptographic inventory rule. */
@Rule(key = "Inventory")
public class JavaScriptInventoryRule extends JavaScriptBaseDetectionRule {

    public JavaScriptInventoryRule() {
        super(
                true,
                RuleSets.rulesOf(JavaScriptDetectionRules.class),
                JavaScriptReorganizerRules.rules());
    }

    @VisibleForTesting
    protected JavaScriptInventoryRule(
            @Nonnull List<IDetectionRule<JavaScriptTree>> detectionRules) {
        super(true, detectionRules, JavaScriptReorganizerRules.rules());
    }

    @Override
    public @Nonnull List<Issue<JavaScriptTree>> report(
            @Nonnull JavaScriptTree markerTree, @Nonnull List<INode> translatedNodes) {
        return new InventoryRule<JavaScriptTree>().report(markerTree, translatedNodes);
    }
}
