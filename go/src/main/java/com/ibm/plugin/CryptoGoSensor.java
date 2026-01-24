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

import java.io.IOException;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import java.util.stream.StreamSupport;
import javax.annotation.Nonnull;
import org.checkerframework.checker.nullness.qual.NonNull;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.sonar.api.batch.fs.FileSystem;
import org.sonar.api.batch.fs.InputFile;
import org.sonar.api.batch.rule.CheckFactory;
import org.sonar.api.batch.sensor.Sensor;
import org.sonar.api.batch.sensor.SensorContext;
import org.sonar.api.batch.sensor.SensorDescriptor;
import org.sonar.api.utils.TempFolder;
import org.sonar.go.converter.GoConverter;
import org.sonar.go.plugin.ChecksVisitor;
import org.sonar.go.plugin.DurationStatistics;
import org.sonar.go.plugin.GoChecks;
import org.sonar.go.plugin.GoFolder;
import org.sonar.go.plugin.GoModFileAnalyzer;
import org.sonar.go.plugin.GoModFileDataStore;
import org.sonar.go.plugin.GoSensor;
import org.sonar.go.plugin.InputFileContext;
import org.sonar.go.plugin.MemoryMonitor;
import org.sonar.go.plugin.converter.ASTConverterValidation;
import org.sonar.go.report.GoProgressReport;
import org.sonar.go.visitors.TreeVisitor;
import org.sonar.plugins.go.api.ASTConverter;
import org.sonar.plugins.go.api.Tree;
import org.sonar.plugins.go.api.TreeOrError;
import org.sonar.plugins.go.api.checks.GoCheck;

/**
 * Custom sensor for executing cryptography detection rules on Go source files. Implements Sensor
 * directly (rather than extending SlangSensor) to avoid classloader conflicts with the sonar-go
 * plugin and to avoid duplicate metric computation.
 *
 * <p>The sonar-go plugin does not expose a custom rule repository interface (unlike Java's
 * CheckRegistrar or Python's PythonCustomRuleRepository), so this sensor handles parsing and check
 * execution independently.
 *
 * <p>This implementation is heavily inspired by:
 *
 * <ul>
 *   <li><a
 *       href="https://github.com/SonarSource/sonar-go/blob/master/sonar-go-plugin/src/main/java/org/sonar/go/plugin/SlangSensor.java">SlangSensor.java</a>
 *   <li><a
 *       href="https://github.com/SonarSource/sonar-go/blob/master/sonar-go-plugin/src/main/java/org/sonar/go/plugin/GoSensor.java">GoSensor.java</a>
 * </ul>
 */
public class CryptoGoSensor implements Sensor {

    private static final Logger LOG = LoggerFactory.getLogger(CryptoGoSensor.class);

    protected DurationStatistics durationStatistics;
    protected MemoryMonitor memoryMonitor;

    private final GoChecks checks;
    private final GoConverter goConverter;

    public CryptoGoSensor(CheckFactory checkFactory, TempFolder tempFolder) {
        this.checks =
                new GoChecks(checkFactory)
                        .addChecks(GoScannerRuleDefinition.REPOSITORY_KEY, GoRuleList.getChecks());
        this.goConverter = new GoConverter(tempFolder.newDir());
    }

    @Override
    public void describe(SensorDescriptor descriptor) {
        descriptor.onlyOnLanguage("go").name("Cryptography for Go");
    }

    @Override
    public void execute(@NonNull SensorContext context) {
        durationStatistics = new DurationStatistics(context.config());
        memoryMonitor = new MemoryMonitor(context.config());

        Collection<GoCheck> activeChecks = checks.all();
        if (activeChecks.isEmpty()) {
            return;
        }

        // Find and group Go files by directory (Go packages span directories)
        FileSystem fs = context.fileSystem();
        List<InputFile> inputFiles =
                StreamSupport.stream(
                                fs.inputFiles(
                                                fs.predicates()
                                                        .and(
                                                                fs.predicates().hasLanguage("go"),
                                                                fs.predicates()
                                                                        .hasType(
                                                                                InputFile.Type
                                                                                        .MAIN)))
                                        .spliterator(),
                                false)
                        .toList();

        var goProgressReport =
                new GoProgressReport(
                        "Progress of the Golang analysis", TimeUnit.SECONDS.toMillis(10));

        var converter = ASTConverterValidation.wrap(goConverter, context.config());
        var goModFileDataStore = new GoModFileAnalyzer(context).analyzeGoModFiles();

        boolean success = false;
        try {
            var visitors = visitors(durationStatistics, goModFileDataStore);
            success =
                    analyseFiles(
                            converter,
                            context,
                            inputFiles,
                            goProgressReport,
                            visitors,
                            durationStatistics,
                            goModFileDataStore);
        } finally {
            if (success) {
                goProgressReport.stop();
            } else {
                goProgressReport.cancel();
            }
            converter.terminate();
        }
    }

    @Nonnull
    private List<TreeVisitor<InputFileContext>> visitors(
            DurationStatistics statistics, GoModFileDataStore goModFileDataStore) {
        // Only run ChecksVisitor with our crypto checks.
        // Other visitors (SymbolVisitor, CpdVisitor, SyntaxHighlighter, IssueSuppressionVisitor)
        // are handled by the official sonar-go sensor and would cause NoSuchMethodError due to
        // shading conflicts between internal types and API types.
        return List.of(new ChecksVisitor(checks, statistics, goModFileDataStore));
    }

    protected boolean analyseFiles(
            ASTConverter converter,
            @Nonnull SensorContext sensorContext,
            @Nonnull List<InputFile> inputFiles,
            GoProgressReport goProgressReport,
            List<TreeVisitor<InputFileContext>> visitors,
            DurationStatistics statistics,
            GoModFileDataStore goModFileDataStore) {
        var filesByDirectory = groupFilesByDirectory(inputFiles);
        goProgressReport.start(filesByDirectory);

        for (var goFolder : filesByDirectory) {
            if (sensorContext.isCancelled()) {
                return false;
            }

            var filesToAnalyse =
                    goFolder.files().stream()
                            .map(inputFile -> new InputFileContext(sensorContext, inputFile))
                            .toList();

            var moduleName =
                    goModFileDataStore.retrieveClosestGoModFileData(goFolder.name()).moduleName();
            LOG.debug(
                    "Parse directory '{}', number of files: {}, nodule name: '{}'",
                    goFolder.name(),
                    filesToAnalyse.size(),
                    moduleName);

            try {
                analyseDirectory(
                        converter,
                        filesToAnalyse,
                        visitors,
                        goProgressReport,
                        statistics,
                        sensorContext,
                        moduleName);
            } catch (RuntimeException | IOException e) {
                LOG.warn("Unable to parse directory '{}'.", goFolder.name(), e);
                if (GoSensor.isFailFast(sensorContext)) {
                    throw new RuntimeException(e);
                }
            }
            goProgressReport.nextFolder();
        }
        return true;
    }

    @Nonnull
    static List<GoFolder> groupFilesByDirectory(@Nonnull List<InputFile> inputFiles) {
        Map<String, List<InputFile>> filesByDirectory =
                inputFiles.stream()
                        .collect(
                                Collectors.groupingBy(
                                        (InputFile inputFile) -> {
                                            var path = inputFile.uri().getPath();
                                            int lastSeparatorIndex = path.lastIndexOf("/");
                                            if (lastSeparatorIndex == -1) {
                                                return "";
                                            }
                                            return path.substring(0, lastSeparatorIndex);
                                        }));

        return filesByDirectory.entrySet().stream()
                .map(entry -> new GoFolder(entry.getKey(), entry.getValue()))
                .toList();
    }

    static void analyseDirectory(
            ASTConverter converter,
            List<InputFileContext> inputFileContextList,
            List<TreeVisitor<InputFileContext>> visitors,
            @Nonnull GoProgressReport goProgressReport,
            DurationStatistics statistics,
            SensorContext sensorContext,
            String moduleName)
            throws IOException {

        final Pattern emptyFilePattern = Pattern.compile("\\s*+");
        Map<String, InputFileContext> filenameToContext = new HashMap<>();
        Map<String, String> filenameToContentMap = new HashMap<>();

        for (InputFileContext inputFileContext : inputFileContextList) {
            String fileName = inputFileContext.inputFile.toString();
            String content = inputFileContext.inputFile.contents();
            if (!emptyFilePattern.matcher(content).matches()) {
                filenameToContext.put(fileName, inputFileContext);
                filenameToContentMap.put(fileName, content);
            }
        }

        if (filenameToContentMap.isEmpty()) {
            return;
        }

        goProgressReport.setStep(GoProgressReport.Step.PARSING);
        Map<String, TreeOrError> treeOrErrorMap = converter.parse(filenameToContentMap, moduleName);

        goProgressReport.setStep(GoProgressReport.Step.HANDLING_PARSE_ERRORS);
        handleParsingErrors(sensorContext, treeOrErrorMap, filenameToContext);

        goProgressReport.setStep(GoProgressReport.Step.ANALYZING);
        visitTrees(visitors, statistics, treeOrErrorMap, filenameToContext);
    }

    private static void handleParsingErrors(
            SensorContext sensorContext,
            Map<String, TreeOrError> treeOrErrorMap,
            Map<String, InputFileContext> filenameToContext) {
        var isAnyError = false;
        for (Map.Entry<String, TreeOrError> filenameToTree : treeOrErrorMap.entrySet()) {
            var treeOrError = filenameToTree.getValue();
            if (treeOrError.isError() && treeOrError.error() != null) {
                isAnyError = true;
                String fileName = filenameToTree.getKey();
                LOG.warn("Unable to parse file: {}. {}", fileName, treeOrError.error());
                filenameToContext
                        .get(fileName)
                        .reportAnalysisParseError(
                                GoScannerRuleDefinition.REPOSITORY_KEY, treeOrError.error());
            }
        }
        if (isAnyError && GoSensor.isFailFast(sensorContext)) {
            throw new IllegalStateException(
                    "Exception when analyzing files. See logs above for details.");
        }
    }

    private static void visitTrees(
            List<TreeVisitor<InputFileContext>> visitors,
            DurationStatistics statistics,
            Map<String, TreeOrError> treeOrErrorMap,
            Map<String, InputFileContext> filenameToContext) {
        for (Map.Entry<String, TreeOrError> filenameToTree : treeOrErrorMap.entrySet()) {
            var treeOrError = filenameToTree.getValue();
            if (treeOrError.isTree()) {
                var filename = filenameToTree.getKey();
                var inputFileContext = filenameToContext.get(filename);
                visitTree(visitors, statistics, inputFileContext, treeOrError.tree());
            }
        }
    }

    private static void visitTree(
            List<TreeVisitor<InputFileContext>> visitors,
            DurationStatistics statistics,
            InputFileContext inputFileContext,
            Tree tree) {
        for (TreeVisitor<InputFileContext> visitor : visitors) {
            try {
                String visitorId = visitor.getClass().getSimpleName();
                statistics.time(visitorId, () -> visitor.scan(inputFileContext, tree));
            } catch (RuntimeException e) {
                inputFileContext.reportAnalysisError(e.getMessage(), null);
                var message =
                        "Cannot analyse '" + inputFileContext.inputFile + "': " + e.getMessage();
                LOG.warn(message, e);
            }
        }
    }
}
