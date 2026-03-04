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
package com.ibm.plugin.rules;

import com.ibm.engine.language.csharp.tree.CSharpTree;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.mapper.model.INode;
import com.ibm.plugin.rules.detection.CSharpBaseDetectionRule;
import com.ibm.plugin.rules.detection.CSharpDetectionRules;
import com.ibm.plugin.translation.reorganizer.CSharpReorganizerRules;
import com.ibm.rules.InventoryRule;
import com.ibm.rules.issue.Issue;
import java.util.List;
import javax.annotation.Nonnull;
import org.sonar.check.Rule;
import org.sonar.java.annotations.VisibleForTesting;

/** The single C# cryptographic inventory rule — detects all known crypto API usage. */
@Rule(key = "Inventory")
public class CSharpInventoryRule extends CSharpBaseDetectionRule {

    public CSharpInventoryRule() {
        super(true, CSharpDetectionRules.rules(), CSharpReorganizerRules.rules());
    }

    @VisibleForTesting
    protected CSharpInventoryRule(@Nonnull List<IDetectionRule<CSharpTree>> detectionRules) {
        super(true, detectionRules, CSharpReorganizerRules.rules());
    }

    @Override
    public @Nonnull List<Issue<CSharpTree>> report(
            @Nonnull CSharpTree markerTree, @Nonnull List<INode> translatedNodes) {
        return new InventoryRule<CSharpTree>().report(markerTree, translatedNodes);
    }
}
