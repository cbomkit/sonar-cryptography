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
package com.ibm.engine.language.cpp;

import com.ibm.engine.language.IScanContext;
import com.ibm.engine.language.cpp.tree.CppTree;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import org.sonar.api.batch.fs.InputFile;
import org.sonar.api.batch.sensor.SensorContext;
import org.sonar.api.batch.sensor.issue.NewIssue;
import org.sonar.api.batch.sensor.issue.NewIssueLocation;
import org.sonar.api.rule.RuleKey;
import org.sonar.check.Rule;

/**
 * C/C++ scan context wrapping the SonarQube {@link SensorContext}.
 *
 * <p>Mirrors {@link com.ibm.engine.language.csharp.CSharpScanContext}: since there is no
 * sonar-cxx framework integration, we hold the raw {@link SensorContext} and {@link InputFile}
 * and report issues directly via the SonarQube sensor API.
 *
 * <p>This class fills the {@code P} (Publisher) generic type parameter used throughout the engine.
 *
 * @param sensorContext the SonarQube sensor context for the current analysis run
 * @param inputFile the C/C++ source file currently being analysed
 * @param repositoryKey the rule repository key (e.g. {@code "sonar-cpp-crypto"})
 */
public record CppScanContext(
        @Nonnull SensorContext sensorContext,
        @Nonnull InputFile inputFile,
        @Nonnull String repositoryKey)
        implements IScanContext<CppCheck, CppTree> {

    @Override
    public void reportIssue(
            @Nonnull CppCheck currentRule,
            @Nonnull CppTree tree,
            @Nonnull String message) {
        String ruleKey = getRuleKey(currentRule);
        if (ruleKey == null) {
            return;
        }
        int line = Math.max(1, tree.line());
        NewIssue issue = sensorContext.newIssue();
        NewIssueLocation location =
                issue.newLocation().on(inputFile).at(inputFile.selectLine(line)).message(message);
        issue.forRule(RuleKey.of(repositoryKey, ruleKey)).at(location).save();
    }

    @Nullable
    private static String getRuleKey(@Nonnull CppCheck rule) {
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
