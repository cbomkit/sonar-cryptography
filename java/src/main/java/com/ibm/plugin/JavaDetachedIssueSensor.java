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
package com.ibm.plugin;

import com.ibm.engine.callstack.DetachedSyntaxToken;
import com.ibm.engine.language.java.JavaDetachedIssueQueue;
import java.util.List;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.sonar.api.batch.DependsUpon;
import org.sonar.api.batch.fs.InputFile;
import org.sonar.api.batch.fs.TextRange;
import org.sonar.api.batch.sensor.SensorContext;
import org.sonar.api.batch.sensor.SensorDescriptor;
import org.sonar.api.batch.sensor.issue.NewIssue;
import org.sonar.api.rule.RuleKey;
import org.sonar.api.scanner.sensor.ProjectSensor;
import org.sonar.api.utils.AnnotationUtils;
import org.sonar.check.Rule;

/**
 * Saves the issues of detached (tree-free) cross-file Java detections queued in {@link
 * JavaDetachedIssueQueue}, using only the public sensor API.
 *
 * <p>It must run after sonar-java has scanned every file, since detached issues are queued while
 * sonar-java analyses later files. Both the SonarQube scanner and SonarLint order sensors by {@link
 * DependsUpon}; on SonarQube project sensors additionally run after all module sensors.
 */
@DependsUpon(JavaDetachedIssueSensor.SONAR_JAVA_SENSOR)
public final class JavaDetachedIssueSensor implements ProjectSensor {

    /** Name published by sonar-java's {@code JavaSensor} through {@code @DependedUpon}. */
    static final String SONAR_JAVA_SENSOR = "org.sonar.plugins.java.JavaSensor";

    private static final Logger LOGGER = LoggerFactory.getLogger(JavaDetachedIssueSensor.class);

    @Override
    public void describe(@Nonnull SensorDescriptor descriptor) {
        descriptor
                .name("Cryptography cross-file issues for Java")
                .onlyOnLanguage("java")
                .createIssuesForRuleRepository(JavaScannerRuleDefinition.REPOSITORY_KEY);
    }

    @Override
    public void execute(@Nonnull SensorContext context) {
        final List<JavaDetachedIssueQueue.Issue> issues = JavaDetachedIssueQueue.drain();
        int saved = 0;
        for (JavaDetachedIssueQueue.Issue issue : issues) {
            if (save(context, issue)) {
                saved++;
            }
        }
        LOGGER.debug("Saved {} of {} detached cross-file issues", saved, issues.size());
    }

    private static boolean save(
            @Nonnull SensorContext context, @Nonnull JavaDetachedIssueQueue.Issue issue) {
        final RuleKey ruleKey = ruleKey(issue);
        if (ruleKey == null) {
            LOGGER.debug("Skipping detached issue without @Rule key: {}", issue.message());
            return false;
        }
        final TextRange range = range(issue.inputFile(), issue.location());
        if (range == null) {
            LOGGER.debug(
                    "Skipping detached issue with invalid location in {}: {}",
                    issue.inputFile(),
                    issue.message());
            return false;
        }
        final NewIssue newIssue = context.newIssue().forRule(ruleKey);
        newIssue.at(newIssue.newLocation().on(issue.inputFile()).at(range).message(issue.message()))
                .save();
        return true;
    }

    @Nullable private static RuleKey ruleKey(@Nonnull JavaDetachedIssueQueue.Issue issue) {
        final Rule rule = AnnotationUtils.getAnnotation(issue.rule().getClass(), Rule.class);
        if (rule == null || rule.key().isEmpty()) {
            return null;
        }
        return RuleKey.of(JavaScannerRuleDefinition.REPOSITORY_KEY, rule.key());
    }

    /** The captured range, or its first line if the range no longer fits the file. */
    @Nullable private static TextRange range(
            @Nonnull InputFile inputFile, @Nonnull DetachedSyntaxToken location) {
        try {
            return inputFile.newRange(
                    location.line(), location.offset(), location.endLine(), location.endOffset());
        } catch (IllegalArgumentException invalidRange) {
            try {
                return inputFile.selectLine(location.line());
            } catch (IllegalArgumentException invalidLine) {
                return null;
            }
        }
    }
}
