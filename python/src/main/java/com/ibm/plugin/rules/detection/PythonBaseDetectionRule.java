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
import java.util.ArrayList;
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
import org.sonar.plugins.python.api.tree.FunctionDef;
import org.sonar.plugins.python.api.tree.Tree;

public abstract class PythonBaseDetectionRule extends PythonVisitorCheck
        implements IObserver<Finding<PythonCheck, Tree, Symbol, PythonVisitorContext>>,
                IReportableDetectionRule<Tree> {

    private final boolean isInventory;
    private final Map<String, String> functionToFile = new HashMap<>();
    private final Set<String> alreadyVisitedFiles = new HashSet<>();
    private int scanDepth;
    // NOTE:
    // Prototype registry for cross-file function resolution.
    // Currently static and not scoped per analysis context.
    // Cleared per top-level scan to avoid state leakage.
    // Future work should move this into a context-aware component.
    private final Set<Tree> visitedFunctions = new HashSet<>();
    private static final Map<String, List<Tree>> functionDefinitions = new HashMap<>();
    // Feature flag to keep behavior disabled by default.
    // Ensures no regression in existing rules/tests while validating approach.
    private static final boolean ENABLE_REGISTRY = false;
    
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
            if (ENABLE_REGISTRY) {
                visitedFunctions.clear();
                functionDefinitions.clear(); // Prevent registry leak across scans
            }
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
    public void visitFunctionDef(@Nonnull FunctionDef tree) {
        String functionName = tree.name().name();

        if (ENABLE_REGISTRY) {
            functionDefinitions.computeIfAbsent(functionName, k -> new ArrayList<>());
            List<Tree> list = functionDefinitions.get(functionName);
            if (!list.contains(tree)) {
                list.add(tree);
            }
        }

        // Preserve default behavior: always traverse function body so detections are discovered
        // during normal file scanning.
        super.visitFunctionDef(tree);
        if (ENABLE_REGISTRY) {
            // Mark as visited so call-resolution does not re-traverse the same body.
            visitedFunctions.add(tree);
        }
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
            // NOTE:
            // Resolution is name-based only.
            // Does not handle shadowing, aliases, or imports across packages.
            // Resolution may depend on analysis order (definitions must be visited before calls).
            // First try local registry of function definitions (same-project, name-based)
            if (ENABLE_REGISTRY) {
                List<Tree> defs = functionDefinitions.get(functionName);
                if (defs != null) {
                    for (Tree functionTree : new ArrayList<>(defs)) {
                        if (!visitedFunctions.contains(functionTree)) {
                            visitedFunctions.add(functionTree);
                            // Traverse the function body in-place using the same visitor
                            functionTree.accept(this);
                        }
                    }
                }
            } else {
                // Fallback: attempt to resolve via imports (legacy behavior)
                String module = functionToFile.get(functionName);
                if (module != null) {
                    // NOTE: Name-based resolution only; does not handle shadowing/aliases correctly.
                    // Previously this would scan the imported file; that behavior is removed
                    // in favor of same-project function resolution.
                }
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
    // analyzeImportedModule removed: cross-file scanning via test utilities was replaced by
    // same-project function resolution using a global registry. See visitFunctionDef and
    // visitCallExpression for the new behavior.

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
