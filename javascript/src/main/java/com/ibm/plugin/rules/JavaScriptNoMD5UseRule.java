/*
 * Sonar Cryptography Plugin
 * Copyright (C) 2024 IBM
 *
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
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

import com.ibm.mapper.model.INode;
import com.ibm.plugin.javascript.api.Tree;
import com.ibm.plugin.rules.detection.JavaScriptBaseDetectionRule;
import com.ibm.plugin.rules.detection.JavaScriptDetectionRules;
import com.ibm.plugin.translation.reorganizer.JavaScriptReorganizerRules;
import com.ibm.rules.NoMD5UseForMessageDigestRule;
import com.ibm.rules.issue.Issue;
import java.util.List;
import javax.annotation.Nonnull;
import org.sonar.check.Rule;

@Rule(key = "JavaScriptNoMD5use")
public final class JavaScriptNoMD5UseRule extends JavaScriptBaseDetectionRule {

    public JavaScriptNoMD5UseRule() {
        super(false, JavaScriptDetectionRules.rules(), JavaScriptReorganizerRules.rules());
    }

    @Override
    @Nonnull
    public List<Issue<Tree>> report(
            @Nonnull Tree markerTree, @Nonnull List<INode> translatedNodes) {
        return new NoMD5UseForMessageDigestRule<Tree>().report(markerTree, translatedNodes);
    }
}
