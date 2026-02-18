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

import com.ibm.engine.rule.IDetectionRule;
import com.ibm.mapper.model.INode;
import com.ibm.plugin.rules.detection.CxxBaseDetectionRule;
import com.ibm.plugin.rules.detection.CxxDetectionRules;
import com.ibm.plugin.translation.reorganizer.CxxReorganizerRules;
import com.ibm.rules.InventoryRule;
import com.ibm.rules.issue.Issue;
import com.sonar.cxx.sslr.api.AstNode;
import java.util.List;
import javax.annotation.Nonnull;
import org.sonar.check.Rule;

/**
 * C++ Inventory Rule for detecting cryptographic assets.
 *
 * <p>This rule scans C++ source files for cryptographic API usage and reports findings for
 * inventory purposes. Detected assets are exported to the Cryptographic Bill of Materials (CBOM)
 * output.
 */
@Rule(key = "Inventory")
public class CxxInventoryRule extends CxxBaseDetectionRule {

    public CxxInventoryRule() {
        super(true, CxxDetectionRules.rules(), CxxReorganizerRules.rules());
    }

    protected CxxInventoryRule(@Nonnull List<IDetectionRule<AstNode>> detectionRules) {
        super(true, detectionRules, CxxReorganizerRules.rules());
    }

    @Override
    @Nonnull
    public List<Issue<AstNode>> report(
            @Nonnull AstNode markerTree, @Nonnull List<INode> translatedNodes) {
        return new InventoryRule<AstNode>().report(markerTree, translatedNodes);
    }
}
