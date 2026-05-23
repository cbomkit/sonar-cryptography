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
package com.ibm.engine.language.java;

import com.ibm.engine.language.IScanContext;
import javax.annotation.Nonnull;
import org.sonar.api.batch.fs.InputFile;
import org.sonar.plugins.java.api.JavaCheck;
import org.sonar.plugins.java.api.JavaFileScannerContext;
import org.sonar.plugins.java.api.tree.MethodInvocationTree;
import org.sonar.plugins.java.api.tree.NewClassTree;
import org.sonar.plugins.java.api.tree.SyntaxToken;
import org.sonar.plugins.java.api.tree.Tree;

public record JavaScanContext(@Nonnull JavaFileScannerContext javaFileScannerContext)
        implements IScanContext<JavaCheck, Tree> {

    /**
     * Reports an issue at the most precise location within the given tree. <br>
     * Rather than passing the entire tree to Sonar (which computes the location via {@code
     * tree.firstToken()} and may include trivia such as javadoc comments), we extract a specific
     * sub-token that accurately represents where the detection occurs:
     *
     * <ul>
     *   <li>For {@code NEW_CLASS} trees, we use the identifier's first token (e.g. {@code
     *       SecretKeySpec} in {@code new SecretKeySpec(...)}).
     *   <li>For {@code METHOD_INVOCATION} trees, we use the method-select's first token (e.g.
     *       {@code hmacMd5} in {@code hmacMd5(...)}).
     *   <li>For all other tree kinds, we fall back to the tree's own first token.
     * </ul>
     *
     * <p>This mirrors the token-selection logic in {@code JavaTranslator.getDetectionContextFrom()}
     * and fixes the SonarQube UI issue location for cases like #339, where findings were reported
     * at the closing comment end marker of the <em>next</em> method's javadoc rather than at the
     * actual call site.
     */
    @Override
    public void reportIssue(
            @Nonnull JavaCheck currentRule, @Nonnull Tree tree, @Nonnull String message) {
        Tree preciseTree = extractPreciseTree(tree);
        this.javaFileScannerContext.reportIssue(currentRule, preciseTree, message);
    }

    /**
     * Returns the most specific sub-tree (or token) that accurately locates the given tree node.
     * Falls back to the original tree's first token when no finer-grained token is available.
     */
    @Nonnull
    private static Tree extractPreciseTree(@Nonnull Tree tree) {
        switch (tree.kind()) {
            case NEW_CLASS -> {
                NewClassTree newClassTree = (NewClassTree) tree;
                SyntaxToken identifierToken = newClassTree.identifier().firstToken();
                if (identifierToken != null) {
                    return identifierToken;
                }
            }
            case METHOD_INVOCATION -> {
                MethodInvocationTree methodInvocationTree = (MethodInvocationTree) tree;
                SyntaxToken methodSelectToken = methodInvocationTree.methodSelect().firstToken();
                if (methodSelectToken != null) {
                    return methodSelectToken;
                }
            }
            default -> {
                // fall through to generic firstToken() below
            }
        }
        SyntaxToken firstToken = tree.firstToken();
        return firstToken != null ? firstToken : tree;
    }

    @Nonnull
    @Override
    public InputFile getInputFile() {
        return this.javaFileScannerContext.getInputFile();
    }

    @Nonnull
    @Override
    public String getFilePath() {
        return this.javaFileScannerContext.getInputFile().uri().getPath();
    }
}
