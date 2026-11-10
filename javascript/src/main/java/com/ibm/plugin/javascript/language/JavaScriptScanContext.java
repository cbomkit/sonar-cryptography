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
package com.ibm.plugin.javascript.language;

import com.ibm.engine.language.IScanContext;
import com.ibm.plugin.javascript.tree.JavaScriptTree;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import org.sonar.api.batch.fs.InputFile;
import org.sonar.api.batch.sensor.SensorContext;
import org.sonar.api.batch.sensor.issue.NewIssue;
import org.sonar.api.batch.sensor.issue.NewIssueLocation;
import org.sonar.api.rule.RuleKey;
import org.sonar.check.Rule;

/**
 * JavaScript scan context wrapping the SonarQube {@link SensorContext}. Like C#, there is no
 * language-analyzer framework to delegate to, so issues are reported through the sensor API.
 */
public record JavaScriptScanContext(
        @Nonnull SensorContext sensorContext,
        @Nonnull InputFile inputFile,
        @Nonnull String repositoryKey)
        implements IScanContext<JavaScriptCheck, JavaScriptTree> {

    @Override
    public void reportIssue(
            @Nonnull JavaScriptCheck currentRule,
            @Nonnull JavaScriptTree tree,
            @Nonnull String message) {
        String ruleKey = getRuleKey(currentRule);
        if (ruleKey == null) {
            return;
        }
        NewIssue issue = sensorContext.newIssue();
        NewIssueLocation location =
                issue.newLocation()
                        .on(inputFile)
                        .at(inputFile.selectLine(Math.max(1, tree.getLine())))
                        .message(message);
        issue.forRule(RuleKey.of(repositoryKey, ruleKey)).at(location).save();
    }

    @Nullable private static String getRuleKey(@Nonnull JavaScriptCheck rule) {
        Rule annotation = rule.getClass().getAnnotation(Rule.class);
        return annotation != null ? annotation.key() : null;
    }

    @Nonnull
    @Override
    public InputFile getInputFile() {
        return inputFile;
    }

    @Nonnull
    @Override
    public String getFilePath() {
        return inputFile.uri().getPath();
    }
}
