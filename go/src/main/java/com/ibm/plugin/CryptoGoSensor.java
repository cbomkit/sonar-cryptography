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
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.regex.Pattern;
import javax.annotation.Nonnull;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
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
import org.sonar.plugins.go.api.TreeOrError;

/**
 * Runs cryptography checks on Go packages through the analyzer's converter and visitor APIs.
 * Package parsing keeps cross-file type information available to our checks. The official Go sensor
 * remains responsible for metrics, highlighting and its own rule repositories.
 */
public class CryptoGoSensor implements Sensor {
    private static final Logger LOG = LoggerFactory.getLogger(CryptoGoSensor.class);
    private static final Pattern BLANK_SOURCE = Pattern.compile("[ \\t\\r\\n\\f\\x0B]*");

    protected DurationStatistics durationStatistics;
    protected MemoryMonitor memoryMonitor;

    private final GoChecks checks;
    private final GoConverter goConverter;

    public CryptoGoSensor(@Nonnull CheckFactory checkFactory, @Nonnull TempFolder tempFolder) {
        goConverter = new GoConverter(tempFolder.newDir());
        checks = new GoChecks(checkFactory);
        checks.addChecks(GoScannerRuleDefinition.REPOSITORY_KEY, GoRuleList.getChecks());
    }

    @Override
    public void describe(@Nonnull SensorDescriptor descriptor) {
        descriptor.name("Cryptography for Go").onlyOnLanguage("go");
    }

    @Override
    public void execute(@Nonnull SensorContext context) {
        execute(context, goConverter, checks);
    }

    public static void execute(
            @Nonnull SensorContext context, GoConverter goConverter, GoChecks checks) {
        if (checks.all().isEmpty()) {
            return;
        }
        var statistics = new DurationStatistics(context.config());
        var fs = context.fileSystem();
        var selection = fs.predicates();
        List<InputFile> files = new ArrayList<>();
        fs.inputFiles(
                        selection.and(
                                selection.hasType(InputFile.Type.MAIN),
                                selection.hasLanguage("go")))
                .forEach(files::add);
        var folders = groupFilesByDirectory(files);
        ASTConverter converter = ASTConverterValidation.wrap(goConverter, context.config());
        var progress =
                new GoProgressReport(
                        "Progress of the Golang analysis", TimeUnit.SECONDS.toMillis(10));
        boolean started = false;
        boolean completed = false;
        try {
            progress.start(folders);
            started = true;
            var modules = new GoModFileAnalyzer(context).analyzeGoModFiles();
            List<TreeVisitor<InputFileContext>> visitors =
                    List.of(new ChecksVisitor(checks, statistics, modules));
            completed =
                    new PackageAnalysis(context, converter, visitors, statistics, progress)
                            .run(folders, modules);
        } finally {
            try {
                if (started) {
                    if (completed) {
                        progress.stop();
                    } else {
                        progress.cancel();
                    }
                }
            } finally {
                converter.terminate();
            }
        }
    }

    @Nonnull
    static List<GoFolder> groupFilesByDirectory(@Nonnull List<InputFile> files) {
        Map<String, List<InputFile>> packages = new LinkedHashMap<>();
        for (InputFile file : files) {
            // URI paths are slash-separated on every scanner platform.
            String parent = file.uri().getPath().replaceFirst("[^/]*$", "").replaceFirst("/$", "");
            packages.computeIfAbsent(parent, unused -> new ArrayList<>()).add(file);
        }
        List<GoFolder> folders = new ArrayList<>(packages.size());
        packages.forEach((parent, members) -> folders.add(new GoFolder(parent, members)));
        return folders;
    }

    static boolean analyseFiles(
            ASTConverter converter,
            @Nonnull SensorContext context,
            @Nonnull List<InputFile> files,
            GoProgressReport progress,
            List<TreeVisitor<InputFileContext>> visitors,
            DurationStatistics statistics,
            GoModFileDataStore modules) {
        var folders = groupFilesByDirectory(files);
        progress.start(folders);
        return new PackageAnalysis(context, converter, visitors, statistics, progress)
                .run(folders, modules);
    }

    static void analyseDirectory(
            ASTConverter converter,
            List<InputFileContext> files,
            List<TreeVisitor<InputFileContext>> visitors,
            @Nonnull GoProgressReport progress,
            DurationStatistics statistics,
            SensorContext context,
            String module)
            throws IOException {
        new PackageAnalysis(context, converter, visitors, statistics, progress)
                .parsePackage(files, module);
    }

    private record SourceFile(InputFileContext context, String content) {}

    private record ParsedFile(InputFileContext context, TreeOrError result) {}

    private static final class PackageAnalysis {
        private final SensorContext context;
        private final ASTConverter converter;
        private final List<TreeVisitor<InputFileContext>> visitors;
        private final DurationStatistics statistics;
        private final GoProgressReport progress;

        private PackageAnalysis(
                SensorContext context,
                ASTConverter converter,
                List<TreeVisitor<InputFileContext>> visitors,
                DurationStatistics statistics,
                GoProgressReport progress) {
            this.context = context;
            this.converter = converter;
            this.visitors = visitors;
            this.statistics = statistics;
            this.progress = progress;
        }

        private boolean run(List<GoFolder> folders, GoModFileDataStore modules) {
            for (GoFolder folder : folders) {
                if (context.isCancelled()) {
                    return false;
                }
                String module = modules.retrieveClosestGoModFileData(folder.name()).moduleName();
                LOG.debug(
                        "Cryptography package '{}': {} files, module '{}'",
                        folder.name(),
                        folder.files().size(),
                        module);
                try {
                    List<InputFileContext> inputs = new ArrayList<>(folder.files().size());
                    folder.files().forEach(file -> inputs.add(new InputFileContext(context, file)));
                    parsePackage(inputs, module);
                } catch (IOException | RuntimeException failure) {
                    LOG.warn(
                            "Cryptography analysis failed for package '{}'.",
                            folder.name(),
                            failure);
                    if (GoSensor.isFailFast(context)) {
                        throw new RuntimeException(failure);
                    }
                }
                progress.nextFolder();
            }
            return true;
        }

        private void parsePackage(List<InputFileContext> inputs, String module) throws IOException {
            Map<String, SourceFile> sources = new LinkedHashMap<>();
            for (InputFileContext input : inputs) {
                String text = input.inputFile.contents();
                if (BLANK_SOURCE.matcher(text).matches()) {
                    continue;
                }
                sources.put(input.inputFile.toString(), new SourceFile(input, text));
            }
            if (sources.isEmpty()) {
                return;
            }
            Map<String, String> request = new LinkedHashMap<>();
            sources.forEach((name, source) -> request.put(name, source.content()));
            progress.setStep(GoProgressReport.Step.PARSING);
            List<ParsedFile> parsed =
                    converter.parse(request, module).entrySet().stream()
                            .map(
                                    entry ->
                                            new ParsedFile(
                                                    sources.get(entry.getKey()).context(),
                                                    entry.getValue()))
                            .toList();
            progress.setStep(GoProgressReport.Step.HANDLING_PARSE_ERRORS);
            reportSyntaxErrors(parsed);
            progress.setStep(GoProgressReport.Step.ANALYZING);
            parsed.stream().filter(file -> file.result().isTree()).forEach(this::runChecks);
        }

        private void reportSyntaxErrors(List<ParsedFile> parsed) {
            List<ParsedFile> failures =
                    parsed.stream()
                            .filter(
                                    file ->
                                            file.result().isError()
                                                    && file.result().error() != null)
                            .toList();
            failures.forEach(
                    file -> {
                        String detail = file.result().error();
                        LOG.warn("Go syntax error in '{}': {}", file.context().inputFile, detail);
                        file.context()
                                .reportAnalysisParseError(
                                        GoScannerRuleDefinition.REPOSITORY_KEY, detail);
                    });
            if (!failures.isEmpty() && GoSensor.isFailFast(context)) {
                throw new IllegalStateException(
                        "Cryptography analysis stopped after Go syntax errors.");
            }
        }

        private void runChecks(ParsedFile file) {
            visitors.forEach(
                    visitor -> {
                        try {
                            statistics.time(
                                    visitor.getClass().getSimpleName(),
                                    () -> visitor.scan(file.context(), file.result().tree()));
                        } catch (RuntimeException failure) {
                            file.context().reportAnalysisError(failure.getMessage(), null);
                            LOG.warn(
                                    "Cryptography check failed in '{}'.",
                                    file.context().inputFile,
                                    failure);
                        }
                    });
        }
    }
}
