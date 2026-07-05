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
package com.ibm.plugin.rules.detection.crossfile;

import static org.assertj.core.api.Assertions.assertThat;

import com.ibm.engine.language.java.JavaLanguageSupport;
import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import javax.tools.JavaCompiler;
import javax.tools.ToolProvider;
import org.junit.jupiter.api.Test;
import org.sonar.java.checks.verifier.CheckVerifier;
import org.sonar.plugins.java.api.IssuableSubscriptionVisitor;
import org.sonar.plugins.java.api.tree.MethodInvocationTree;
import org.sonar.plugins.java.api.tree.Tree;

/**
 * Verifies {@link JavaLanguageSupport#isDetachableCall} on real, semantically-resolved cross-file
 * calls. The fixtures are compiled to a classpath so the callee types resolve (mimicking {@code
 * sonar.java.binaries}); crucially the callee's {@code declaration()} is then {@code null}, and the
 * predicate must still treat a plain-argument call as detachable.
 */
class IsDetachableCallTest extends IssuableSubscriptionVisitor {

    private static final String WRAPPER =
            "src/test/files/rules/detection/crossfile/KeyGeneratorWrapper.java";
    private static final String CALLER =
            "src/test/files/rules/detection/crossfile/KeyGeneratorCaller.java";

    private static final JavaLanguageSupport LANGUAGE_SUPPORT = new JavaLanguageSupport();
    private static final Map<String, Boolean> detachableByCallee = new HashMap<>();

    @Test
    void plainArgsDetachableAcrossFilesButArrayArgIsNot() throws Exception {
        detachableByCallee.clear();
        File classes = compileToClasspath(WRAPPER, CALLER);
        CheckVerifier.newVerifier()
                .onFiles(CALLER, WRAPPER)
                .withClassPath(List.of(classes))
                .withChecks(this)
                .verifyNoIssues();

        // Cross-file literal / field-constant call (declaration() is null via the classpath
        // binary):
        assertThat(detachableByCallee).containsEntry("generate", true);
        // Call carrying a NEW_ARRAY argument must stay on the retained-tree path:
        assertThat(detachableByCallee).containsEntry("generateWithIv", false);
    }

    @Override
    public List<Tree.Kind> nodesToVisit() {
        return List.of(Tree.Kind.METHOD_INVOCATION);
    }

    @Override
    public void visitNode(Tree tree) {
        MethodInvocationTree invocation = (MethodInvocationTree) tree;
        String callee = invocation.methodSymbol().name();
        if (callee.equals("generate") || callee.equals("generateWithIv")) {
            detachableByCallee.put(callee, LANGUAGE_SUPPORT.isDetachableCall(tree));
        }
    }

    private static File compileToClasspath(String... sources) throws Exception {
        Path out = Files.createTempDirectory("xfile-detachable");
        JavaCompiler compiler = ToolProvider.getSystemJavaCompiler();
        List<String> args = new ArrayList<>(List.of("-d", out.toString()));
        for (String s : sources) {
            args.add(new File(s).getAbsolutePath());
        }
        int rc = compiler.run(null, null, null, args.toArray(new String[0]));
        if (rc != 0) {
            throw new IllegalStateException("fixture compilation failed rc=" + rc);
        }
        return out.toFile();
    }
}
