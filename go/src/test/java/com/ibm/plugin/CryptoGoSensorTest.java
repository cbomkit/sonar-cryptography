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
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.sonar.api.batch.fs.InputFile;
import org.sonar.api.batch.fs.internal.TestInputFileBuilder;
import org.sonar.api.batch.sensor.internal.SensorContextTester;
import org.sonar.go.converter.GoConverter;
import org.sonar.go.plugin.DurationStatistics;
import org.sonar.go.plugin.GoChecks;
import org.sonar.go.plugin.GoModFileDataStore;
import org.sonar.go.plugin.GoSensor;
import org.sonar.go.plugin.InputFileContext;
import org.sonar.go.report.GoProgressReport;
import org.sonar.go.visitors.TreeVisitor;
import org.sonar.plugins.go.api.ASTConverter;
import org.sonar.plugins.go.api.Tree;
import org.sonar.plugins.go.api.TreeOrError;
import org.sonar.plugins.go.api.checks.GoCheck;
import org.sonar.plugins.go.api.checks.GoModFileData;

class CryptoGoSensorTest {
    @TempDir Path directory;
    private SensorContextTester context;
    private final ASTConverter converter = mock(ASTConverter.class);
    private final GoProgressReport progress = mock(GoProgressReport.class);
    private DurationStatistics statistics;

    @BeforeEach
    void setUp() {
        context = SensorContextTester.create(directory);
        statistics = new DurationStatistics(context.config());
    }

    private InputFile file(String name, String content) {
        var file =
                new TestInputFileBuilder("test", name)
                        .setModuleBaseDir(directory)
                        .setProjectBaseDir(directory)
                        .setLanguage("go")
                        .setType(InputFile.Type.MAIN)
                        .setContents(content)
                        .build();
        context.fileSystem().add(file);
        return file;
    }

    @Test
    void groupsPackageFilesTogetherAndPreservesOrderWithinEachPackage() {
        var first = file("pkg/first.go", "package pkg");
        var second = file("pkg/second.go", "package pkg");
        var other = file("other/third.go", "package other");
        var folders = CryptoGoSensor.groupFilesByDirectory(List.of(first, other, second));
        assertThat(folders).hasSize(2);
        assertThat(
                        folders.stream()
                                .filter(f -> f.name().equals(directory.resolve("pkg").toString()))
                                .findFirst()
                                .orElseThrow()
                                .files())
                .containsExactly(first, second);
    }

    @Test
    void parsesWholePackageWithModuleNameButOmitsWhitespaceOnlyFiles() throws IOException {
        var first = file("pkg/first.go", "package pkg");
        var second = file("pkg/second.go", "package pkg\nvar key = 1");
        var blank = file("pkg/blank.go", " \t\r\n\f\u000b");
        when(converter.parse(any(), anyString())).thenReturn(Map.of());
        analyse(List.of(first, second, blank), List.of(), "example.org/pkg");
        verify(converter)
                .parse(
                        Map.of(
                                first.toString(),
                                first.contents(),
                                second.toString(),
                                second.contents()),
                        "example.org/pkg");
    }

    @Test
    void skipsConverterForEmptyPackages() throws IOException {
        analyse(List.of(file("blank.go", " \n\t")), List.of(), "example.org/pkg");
        verifyNoInteractions(converter);
    }

    @Test
    void reportsParseErrorsAndStillVisitsSuccessfullyParsedFiles() throws IOException {
        var good = file("pkg/good.go", "package pkg");
        var bad = file("pkg/bad.go", "broken");
        var tree = mock(Tree.class);
        var visitor = visitor();
        when(converter.parse(any(), anyString()))
                .thenReturn(
                        Map.of(
                                good.toString(),
                                TreeOrError.of(tree),
                                bad.toString(),
                                TreeOrError.of("syntax error")));
        analyse(List.of(good, bad), List.of(visitor), "example.org/pkg");
        assertThat(context.allAnalysisErrors()).hasSize(1);
        verify(visitor).scan(any(InputFileContext.class), org.mockito.ArgumentMatchers.eq(tree));
    }

    @Test
    void failFastReportsEveryParseErrorBeforeRejectingThePackage() {
        context.settings().setProperty(GoSensor.FAIL_FAST_PROPERTY_NAME, true);
        var first = file("pkg/first.go", "broken");
        var second = file("pkg/second.go", "broken");
        var good = file("pkg/good.go", "package pkg");
        var visitor = visitor();
        when(converter.parse(any(), anyString()))
                .thenReturn(
                        Map.of(
                                first.toString(),
                                TreeOrError.of("first error"),
                                second.toString(),
                                TreeOrError.of("second error"),
                                good.toString(),
                                TreeOrError.of(mock(Tree.class))));
        assertThatThrownBy(
                        () ->
                                analyse(
                                        List.of(first, second, good),
                                        List.of(visitor),
                                        "example.org/pkg"))
                .isInstanceOf(IllegalStateException.class);
        assertThat(context.allAnalysisErrors()).hasSize(2);
        verifyNoInteractions(visitor);
    }

    @Test
    void visitorFailureIsReportedAndRemainingVisitorsStillRun() throws IOException {
        var file = file("pkg/good.go", "package pkg");
        var tree = mock(Tree.class);
        var failing = visitor();
        var succeeding = visitor();
        doThrow(new IllegalStateException("check failure")).when(failing).scan(any(), any());
        when(converter.parse(any(), anyString()))
                .thenReturn(Map.of(file.toString(), TreeOrError.of(tree)));
        analyse(List.of(file), List.of(failing, succeeding), "example.org/pkg");
        assertThat(context.allAnalysisErrors()).hasSize(1);
        verify(succeeding).scan(any(), org.mockito.ArgumentMatchers.eq(tree));
    }

    @Test
    void cancellationPreventsPackageParsing() {
        context.setCancelled(true);
        var input = file("pkg/source.go", "package pkg");
        assertThat(
                        CryptoGoSensor.analyseFiles(
                                converter,
                                context,
                                List.of(input),
                                progress,
                                List.of(),
                                statistics,
                                new GoModFileDataStore()))
                .isFalse();
        verifyNoInteractions(converter);
        verify(progress, never()).nextFolder();
    }

    @Test
    void resolvesModuleNamesAndContinuesAfterPackageIoFailure() throws IOException {
        var bad = mock(InputFile.class);
        when(bad.uri()).thenReturn(directory.resolve("bad/source.go").toUri());
        when(bad.contents()).thenThrow(new IOException("unreadable"));
        var good = file("good/source.go", "package good");
        var modules = mock(GoModFileDataStore.class);
        when(modules.retrieveClosestGoModFileData(anyString()))
                .thenReturn(new GoModFileData("example.org/project", null, List.of(), "go.mod"));
        when(converter.parse(any(), anyString())).thenReturn(Map.of());
        assertThat(
                        CryptoGoSensor.analyseFiles(
                                converter,
                                context,
                                List.of(bad, good),
                                progress,
                                List.of(),
                                statistics,
                                modules))
                .isTrue();
        verify(converter).parse(Map.of(good.toString(), good.contents()), "example.org/project");
        verify(progress, org.mockito.Mockito.times(2)).nextFolder();
    }

    @Test
    void converterIsNotStartedWhenNoChecksAreActive() {
        var converter = mock(GoConverter.class);
        var checks = mock(GoChecks.class);
        when(checks.all()).thenReturn(List.of());
        CryptoGoSensor.execute(context, converter, checks);
        verifyNoInteractions(converter);
    }

    @Test
    void converterIsTerminatedWhenFailFastAbortsAnalysis() {
        context.settings().setProperty(GoSensor.FAIL_FAST_PROPERTY_NAME, true);
        file("pkg/source.go", "package pkg");
        var converter = mock(GoConverter.class);
        var checks = mock(GoChecks.class);
        when(checks.all()).thenReturn(List.of(mock(GoCheck.class)));
        when(checks.ruleKey(any())).thenReturn(org.sonar.api.rule.RuleKey.of("test", "crypto"));
        when(converter.parse(any(), anyString()))
                .thenThrow(new IllegalStateException("converter failure"));
        assertThatThrownBy(() -> CryptoGoSensor.execute(context, converter, checks))
                .isInstanceOf(RuntimeException.class)
                .hasMessageContaining("converter failure");
        verify(converter).terminate();
    }

    @Test
    void executionSelectsOnlyMainGoFilesAndTerminatesTheConverter() throws IOException {
        var main = file("pkg/main.go", "package pkg");
        var test =
                new TestInputFileBuilder("test", "pkg/main_test.go")
                        .setModuleBaseDir(directory)
                        .setProjectBaseDir(directory)
                        .setLanguage("go")
                        .setType(InputFile.Type.TEST)
                        .setContents("package pkg")
                        .build();
        var java =
                new TestInputFileBuilder("test", "Other.java")
                        .setModuleBaseDir(directory)
                        .setProjectBaseDir(directory)
                        .setLanguage("java")
                        .setType(InputFile.Type.MAIN)
                        .setContents("class Other {}")
                        .build();
        context.fileSystem().add(test).add(java);
        var nativeConverter = mock(GoConverter.class);
        var checks = mock(GoChecks.class);
        when(checks.all()).thenReturn(List.of(mock(GoCheck.class)));
        when(checks.ruleKey(any())).thenReturn(org.sonar.api.rule.RuleKey.of("test", "crypto"));
        when(nativeConverter.parse(any(), anyString())).thenReturn(Map.of());

        CryptoGoSensor.execute(context, nativeConverter, checks);

        verify(nativeConverter)
                .parse(
                        org.mockito.ArgumentMatchers.eq(Map.of(main.toString(), main.contents())),
                        anyString());
        verify(nativeConverter).terminate();
    }

    @Test
    void cancellationAfterAParsedPackageSkipsTheRemainingPackages() {
        var first = file("first/source.go", "package first");
        var second = file("second/source.go", "package second");
        when(converter.parse(any(), anyString()))
                .thenAnswer(
                        invocation -> {
                            context.setCancelled(true);
                            return Map.of();
                        });
        assertThat(
                        CryptoGoSensor.analyseFiles(
                                converter,
                                context,
                                List.of(first, second),
                                progress,
                                List.of(),
                                statistics,
                                new GoModFileDataStore()))
                .isFalse();
        verify(converter).parse(any(), anyString());
        verify(progress).nextFolder();
    }

    private void analyse(
            List<InputFile> files, List<TreeVisitor<InputFileContext>> visitors, String module)
            throws IOException {
        CryptoGoSensor.analyseDirectory(
                converter,
                files.stream().map(f -> new InputFileContext(context, f)).toList(),
                visitors,
                progress,
                statistics,
                context,
                module);
    }

    @SuppressWarnings("unchecked")
    private TreeVisitor<InputFileContext> visitor() {
        return mock(TreeVisitor.class);
    }
}
