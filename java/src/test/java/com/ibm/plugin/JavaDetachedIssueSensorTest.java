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

import static org.assertj.core.api.Assertions.assertThat;

import com.ibm.engine.callstack.DetachedSyntaxToken;
import com.ibm.engine.language.java.JavaDetachedIssueQueue;
import com.ibm.engine.language.java.JavaDetachedIssueReporter;
import java.io.File;
import java.util.List;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.sonar.api.batch.DependsUpon;
import org.sonar.api.batch.fs.InputFile;
import org.sonar.api.batch.fs.TextRange;
import org.sonar.api.batch.fs.internal.TestInputFileBuilder;
import org.sonar.api.batch.sensor.internal.DefaultSensorDescriptor;
import org.sonar.api.batch.sensor.internal.SensorContextTester;
import org.sonar.api.batch.sensor.issue.Issue;
import org.sonar.check.Rule;
import org.sonar.plugins.java.api.JavaCheck;

class JavaDetachedIssueSensorTest {

    @Rule(key = "Inventory")
    static final class InventoryCheck implements JavaCheck {}

    static final class UnannotatedCheck implements JavaCheck {}

    private final InputFile file =
            TestInputFileBuilder.create("module", "src/Caller.java")
                    .setLanguage("java")
                    .setContents("class Caller {\n  void call() { generate(\"AES\"); }\n}\n")
                    .build();

    @BeforeEach
    @AfterEach
    void clearQueue() {
        JavaDetachedIssueQueue.reset();
    }

    private static List<Issue> runSensor() {
        final SensorContextTester context = SensorContextTester.create(new File("."));
        new JavaDetachedIssueSensor().execute(context);
        return List.copyOf(context.allIssues());
    }

    private void report(JavaCheck check, int line, int offset, int endLine, int endOffset) {
        new JavaDetachedIssueReporter(file)
                .report(
                        check,
                        new DetachedSyntaxToken(line, offset, endLine, endOffset, "AES", List.of()),
                        "(SecretKey) AES");
    }

    @Test
    void runsAfterSonarJavaOnlyForJavaAndOurRepository() {
        final DependsUpon dependsUpon =
                JavaDetachedIssueSensor.class.getAnnotation(DependsUpon.class);
        assertThat(dependsUpon).isNotNull();
        assertThat(dependsUpon.value()).containsExactly("org.sonar.plugins.java.JavaSensor");

        final DefaultSensorDescriptor descriptor = new DefaultSensorDescriptor();
        new JavaDetachedIssueSensor().describe(descriptor);
        assertThat(descriptor.languages()).containsExactly("java");
        assertThat(descriptor.ruleRepositories())
                .containsExactly(JavaScannerRuleDefinition.REPOSITORY_KEY);
    }

    @Test
    void savesQueuedIssueAtCapturedRange() {
        report(new InventoryCheck(), 2, 25, 2, 30);

        final List<Issue> issues = runSensor();

        assertThat(issues).hasSize(1);
        final Issue issue = issues.get(0);
        assertThat(issue.ruleKey().repository())
                .isEqualTo(JavaScannerRuleDefinition.REPOSITORY_KEY);
        assertThat(issue.ruleKey().rule()).isEqualTo("Inventory");
        assertThat(issue.primaryLocation().inputComponent()).isEqualTo(file);
        assertThat(issue.primaryLocation().message()).isEqualTo("(SecretKey) AES");
        final TextRange range = issue.primaryLocation().textRange();
        assertThat(range).isNotNull();
        assertThat(range.start().line()).isEqualTo(2);
        assertThat(range.start().lineOffset()).isEqualTo(25);
        assertThat(range.end().line()).isEqualTo(2);
        assertThat(range.end().lineOffset()).isEqualTo(30);
    }

    @Test
    void drainsQueue() {
        report(new InventoryCheck(), 2, 25, 2, 30);

        assertThat(runSensor()).hasSize(1);
        assertThat(runSensor()).isEmpty();
    }

    @Test
    void fallsBackToLineWhenOffsetsNoLongerFit() {
        report(new InventoryCheck(), 2, 25, 2, 500);

        final List<Issue> issues = runSensor();

        assertThat(issues).hasSize(1);
        final TextRange range = issues.get(0).primaryLocation().textRange();
        assertThat(range).isNotNull();
        assertThat(range.start().line()).isEqualTo(2);
        assertThat(range.start().lineOffset()).isZero();
    }

    @Test
    void skipsIssueOutsideFile() {
        report(new InventoryCheck(), 99, 0, 99, 5);

        assertThat(runSensor()).isEmpty();
    }

    @Test
    void skipsCheckWithoutRuleKey() {
        report(new UnannotatedCheck(), 2, 25, 2, 30);

        assertThat(runSensor()).isEmpty();
    }
}
