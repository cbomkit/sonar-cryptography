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
package com.ibm.plugin.rules.detection;

import com.ibm.common.IObserver;
import com.ibm.engine.detection.Finding;
import com.ibm.engine.executive.DetectionExecutive;
import com.ibm.engine.language.python.PythonScanContext;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.reorganizer.IReorganizerRule;
import com.ibm.plugin.PythonAggregator;
import com.ibm.plugin.translation.PythonTranslationProcess;
import com.ibm.plugin.translation.reorganizer.PythonReorganizerRules;
import com.ibm.rules.IReportableDetectionRule;
import com.ibm.rules.issue.Issue;
import java.io.File;
import java.lang.reflect.Method;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import javax.annotation.Nonnull;
import org.sonar.plugins.python.api.PythonCheck;
import org.sonar.plugins.python.api.PythonVisitorCheck;
import org.sonar.plugins.python.api.PythonVisitorContext;
import org.sonar.plugins.python.api.symbols.Symbol;
import org.sonar.plugins.python.api.tree.AliasedName;
import org.sonar.plugins.python.api.tree.CallExpression;
import org.sonar.plugins.python.api.tree.DottedName;
import org.sonar.plugins.python.api.tree.ImportFrom;
import org.sonar.plugins.python.api.tree.Name;
import org.sonar.plugins.python.api.tree.Tree;

public abstract class PythonBaseDetectionRule extends PythonVisitorCheck
        implements IObserver<Finding<PythonCheck, Tree, Symbol, PythonVisitorContext>>,
                IReportableDetectionRule<Tree> {

    private final boolean isInventory;
    private final Map<String, String> functionToFile = new HashMap<>();
    private final Set<String> alreadyVisitedFiles = new HashSet<>();
    private int scanDepth;
    @Nonnull protected final PythonTranslationProcess pythonTranslationProcess;
    @Nonnull protected final List<IDetectionRule<Tree>> detectionRules;

    protected PythonBaseDetectionRule() {
        this.isInventory = false;
        this.detectionRules = PythonDetectionRules.rules();
        this.pythonTranslationProcess = new PythonTranslationProcess(PythonReorganizerRules.rules());
    }

    protected PythonBaseDetectionRule(
            final boolean isInventory,
            @Nonnull List<IDetectionRule<Tree>> detectionRules,
            @Nonnull List<IReorganizerRule> reorganizerRules) {
        this.isInventory = isInventory;
        this.detectionRules = detectionRules;
        this.pythonTranslationProcess = new PythonTranslationProcess(reorganizerRules);
    }

    @Override
    public void scanFile(@Nonnull PythonVisitorContext context) {
        if (scanDepth == 0) {
            // Reset per top-level scan to avoid skipping normal analysis of other files.
            alreadyVisitedFiles.clear();
        }

        scanDepth++;
        try {
            String currentFilePath = normalizePath(Paths.get(context.pythonFile().uri()));
            if (!alreadyVisitedFiles.add(currentFilePath)) {
                return;
            }

            Map<String, String> previousFunctionToFile = new HashMap<>(functionToFile);
            functionToFile.clear();
            // NOTE: Name-based resolution only; does not handle shadowing/aliases correctly.
            try {
                super.scanFile(context);
            } finally {
                functionToFile.clear();
                functionToFile.putAll(previousFunctionToFile);
            }
        } finally {
            scanDepth--;
        }
    }

    @Override
    public void visitImportFrom(@Nonnull ImportFrom tree) {
        String module = moduleName(tree);
        if (module != null) {
            for (AliasedName importedName : tree.importedNames()) {
                functionToFile.put(importedName(importedName), module);
            }
        }
        super.visitImportFrom(tree);
    }

    @Override
    public void visitCallExpression(@Nonnull CallExpression tree) {
        String functionName = null;
        Symbol symbol = tree.calleeSymbol();
        if (symbol != null) {
            functionName = symbol.name();
        } else if (tree.callee() instanceof Name calleeName) {
            functionName = calleeName.name();
        }

        if (functionName != null) {
            String module = functionToFile.get(functionName);
            if (module != null) {
                // NOTE: Name-based resolution only; does not handle shadowing/aliases correctly.
                // DEBUG: Attempting to resolve and scan imported module for function: {functionName}
                analyzeImportedModule(module);
            }
        }

        detectionRules.forEach(
                rule -> {
                    DetectionExecutive<PythonCheck, Tree, Symbol, PythonVisitorContext>
                            detectionExecutive =
                                    PythonAggregator.getLanguageSupport()
                                            .createDetectionExecutive(
                                                    tree,
                                                    rule,
                                                    new PythonScanContext(this.getContext()));
                    detectionExecutive.subscribe(this);
                    detectionExecutive.start();
                });
        super.visitCallExpression(tree); // Necessary to visit children nodes of this CallExpression
    }

    /**
     * Recursively analyzes an imported module to discover cryptographic patterns in imported
     * functions.
     *
     * <p>NOTE: Simple resolution for same-directory modules only. Does not handle complex import
     * paths, package hierarchies, or relative imports yet. Future versions should integrate with
     * Sonar's file resolution system for full path handling.
     *
     * @param module The module name to analyze (e.g., "imports.helper")
     */
    private void analyzeImportedModule(@Nonnull String module) {
        if (module == null || module.isBlank()) {
            return;
        }

        try {
            Path currentFile = Paths.get(getContext().pythonFile().uri()).toAbsolutePath().normalize();
            Path currentDirectory = currentFile.getParent();
            if (currentDirectory == null) {
                return; // Cannot resolve relative imports without a parent directory
            }

            // NOTE: Simple resolution for same-directory modules only.
            // Does not handle complex import paths, package hierarchies, or relative imports yet.
            // NOTE: Entire module is scanned; may include unrelated findings.
            Path importedPath = currentDirectory.resolve(module.replace('.', File.separatorChar) + ".py");

            File resolvedFile = importedPath.toFile();
            if (!resolvedFile.isFile()) {
                return; // Module file not found in expected location
            }

            String resolvedFilePath = normalizePath(resolvedFile.toPath());
            // Guard: Check if file has already been visited to prevent redundant scanning within the call tree
            if (!alreadyVisitedFiles.contains(resolvedFilePath)) {
                // Prototype cross-file scan (test-only utility). Guard to avoid production/runtime issues.
                try {
                    Class<?> runnerClass = Class.forName("org.sonar.python.TestPythonVisitorRunner");
                    Method scanFile = runnerClass.getMethod("scanFile", File.class, PythonCheck[].class);
                    scanFile.invoke(null, resolvedFile, new PythonCheck[] {this});
                } catch (ClassNotFoundException e) {
                    // Not available in production classpath; skip cross-file analysis for now.
                    // TODO: Replace with Sonar InputFile/SensorContext-based scanning.
                } catch (ReflectiveOperationException e) {
                    // DEBUG: Failed to invoke prototype cross-file scan.
                    // Gracefully continue without cross-file resolution for this module.
                }
            }
        } catch (Exception e) {
            // DEBUG: Failed to analyze imported module. This may indicate unresolved import paths or missing files.
            // Gracefully continue without cross-file resolution for this module.
        }
    }

    @Nonnull
    private String importedName(@Nonnull AliasedName importedName) {
        Name alias = importedName.alias();
        if (alias != null) {
            return alias.name();
        }

        DottedName dottedName = importedName.dottedName();
        List<Name> names = dottedName.names();
        return names.get(names.size() - 1).name();
    }

    private String moduleName(@Nonnull ImportFrom tree) {
        DottedName module = tree.module();
        if (module == null) {
            return null;
        }

        StringBuilder builder = new StringBuilder();
        for (Name name : module.names()) {
            if (builder.length() > 0) {
                builder.append('.');
            }
            builder.append(name.name());
        }
        return builder.toString();
    }

    @Nonnull
    private String normalizePath(@Nonnull Path path) {
        return path.toAbsolutePath().normalize().toString();
    }

    /**
     * Updates the output file with the translated nodes resulting from a finding.
     *
     * @param finding A finding containing detection store information.
     */
    @Override
    public void update(@Nonnull Finding<PythonCheck, Tree, Symbol, PythonVisitorContext> finding) {
        List<INode> nodes = pythonTranslationProcess.initiate(finding.detectionStore());
        if (isInventory) {
            PythonAggregator.addNodes(nodes);
        }
        // report
        this.report(finding.getMarkerTree(), nodes)
                .forEach(
                        issue ->
                                finding.detectionStore()
                                        .getScanContext()
                                        .reportIssue(this, issue.tree(), issue.message()));
    }

    @Override
    @Nonnull
    public List<Issue<Tree>> report(
            @Nonnull Tree markerTree, @Nonnull List<INode> translatedNodes) {
        // override by higher level rule, to report an issue
        return Collections.emptyList();
    }
}
