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
package com.ibm.plugin.javascript.language;

import com.ibm.engine.language.IScanContext;
import com.ibm.plugin.JavaScriptRulesDefinition;
import com.ibm.plugin.javascript.api.HasLocation;
import com.ibm.plugin.javascript.api.JavaScriptCheck;
import com.ibm.plugin.javascript.api.Tree;
import javax.annotation.Nonnull;
import org.sonar.api.batch.fs.InputFile;
import org.sonar.api.batch.sensor.issue.NewIssue;
import org.sonar.api.batch.sensor.issue.NewIssueLocation;
import org.sonar.api.rule.RuleKey;

/** Scan context for JavaScript detection, wrapping SonarQube sensor APIs. */
public final class JavaScriptScanContext implements IScanContext<JavaScriptCheck, Tree> {

    @Nonnull private final InputFile inputFile;
    @Nonnull private final IssueReporter issueReporter;

    public JavaScriptScanContext(
            @Nonnull InputFile inputFile, @Nonnull IssueReporter issueReporter) {
        this.inputFile = inputFile;
        this.issueReporter = issueReporter;
    }

    @Override
    public void reportIssue(
            @Nonnull JavaScriptCheck currentRule, @Nonnull Tree tree, @Nonnull String message) {
        if (!(tree instanceof HasLocation hasLocation)) {
            return;
        }
        issueReporter.report(
                inputFile, hasLocation.location().line(), hasLocation.location().column(), message);
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

    /** Functional interface abstracting issue creation for testability. */
    public interface IssueReporter {
        void report(@Nonnull InputFile inputFile, int line, int column, @Nonnull String message);
    }

    /** Default issue reporter using SonarQube sensor context. */
    public static final class SensorIssueReporter implements IssueReporter {

        @Nonnull private final org.sonar.api.batch.sensor.SensorContext sensorContext;

        public SensorIssueReporter(
                @Nonnull org.sonar.api.batch.sensor.SensorContext sensorContext) {
            this.sensorContext = sensorContext;
        }

        @Override
        public void report(
                @Nonnull InputFile inputFile, int line, int column, @Nonnull String message) {
            RuleKey ruleKey =
                    RuleKey.of(
                            JavaScriptRulesDefinition.repositoryKeyForLanguage(
                                    inputFile.language()),
                            JavaScriptRulesDefinition.INVENTORY_RULE_KEY);
            NewIssue issue = sensorContext.newIssue().forRule(ruleKey);
            NewIssueLocation location =
                    issue.newLocation()
                            .on(inputFile)
                            .at(inputFile.selectLine(line))
                            .message(message);
            issue.at(location);
            issue.save();
        }
    }
}
