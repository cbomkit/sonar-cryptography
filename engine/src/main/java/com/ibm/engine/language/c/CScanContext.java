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
package com.ibm.engine.language.c;

import com.ibm.engine.language.IScanContext;
import com.ibm.engine.language.c.tree.CTree;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import org.sonar.api.batch.fs.InputFile;
import org.sonar.api.batch.sensor.SensorContext;
import org.sonar.api.batch.sensor.issue.NewIssue;
import org.sonar.api.batch.sensor.issue.NewIssueLocation;
import org.sonar.api.rule.RuleKey;
import org.sonar.check.Rule;

/**
 * C/C++ scan context wrapping the SonarQube SensorContext.
 *
 * <p>Since there is no sonar-c framework, this record holds the raw {@link SensorContext} and
 * {@link InputFile} and reports issues directly via the sensor API.
 *
 * @param sensorContext the SonarQube sensor context for the current analysis
 * @param inputFile the file currently being analysed
 * @param repositoryKey the rule repository key (e.g. {@code "sonar-c-crypto"})
 */
public record CScanContext(
        @Nonnull SensorContext sensorContext,
        @Nonnull InputFile inputFile,
        @Nonnull String repositoryKey)
        implements IScanContext<CCheck, CTree> {

    @Override
    public void reportIssue(
            @Nonnull CCheck currentRule, @Nonnull CTree tree, @Nonnull String message) {
        String ruleKey = getRuleKey(currentRule);
        if (ruleKey == null) {
            return;
        }
        int line = Math.max(1, tree.getLine());
        NewIssue issue = sensorContext.newIssue();
        NewIssueLocation location =
                issue.newLocation().on(inputFile).at(inputFile.selectLine(line)).message(message);
        issue.forRule(RuleKey.of(repositoryKey, ruleKey)).at(location).save();
    }

    @Nullable private static String getRuleKey(@Nonnull CCheck rule) {
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
