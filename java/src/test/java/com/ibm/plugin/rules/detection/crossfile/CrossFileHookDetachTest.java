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

import com.ibm.engine.detection.DetectionStore;
import com.ibm.mapper.model.INode;
import com.ibm.plugin.TestBase;
import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import javax.annotation.Nonnull;
import javax.tools.JavaCompiler;
import javax.tools.ToolProvider;
import org.junit.jupiter.api.Test;
import org.sonar.java.checks.verifier.CheckVerifier;
import org.sonar.plugins.java.api.JavaCheck;
import org.sonar.plugins.java.api.JavaFileScannerContext;
import org.sonar.plugins.java.api.semantic.Symbol;
import org.sonar.plugins.java.api.tree.Tree;

/**
 * First true cross-file detection test in the suite. A hook created while analyzing {@code
 * KeyGeneratorWrapper.java} must resolve a call recorded while analyzing {@code
 * KeyGeneratorCaller.java}.
 *
 * <p>Cross-file resolution requires the callee's type to resolve at the call site. Production
 * achieves this via {@code sonar.java.binaries} (the project is compiled first). CheckVerifier does
 * not put sibling sources on the semantic classpath, so we reproduce production by compiling the
 * fixtures to {@code .class} and passing the output directory to {@link CheckVerifier#withClassPath}.
 * The {@code // Noncompliant} marker in the caller fixture asserts the cross-file detection fired.
 */
class CrossFileHookDetachTest extends TestBase {

    private static final String WRAPPER =
            "src/test/files/rules/detection/crossfile/KeyGeneratorWrapper.java";
    private static final String CALLER =
            "src/test/files/rules/detection/crossfile/KeyGeneratorCaller.java";

    @Test
    void crossFileLiteralResolves() throws Exception {
        File classes = compileToClasspath(WRAPPER, CALLER);
        CheckVerifier.newVerifier()
                .onFiles(CALLER, WRAPPER)
                .withClassPath(List.of(classes))
                .withChecks(this)
                .verifyIssues();
    }

    /** Compiles the fixtures to a temp dir so their types resolve across files (mimics binaries). */
    private static File compileToClasspath(String... sources) throws Exception {
        Path out = Files.createTempDirectory("xfile-classes");
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

    @Override
    public void asserts(
            int findingId,
            @Nonnull DetectionStore<JavaCheck, Tree, Symbol, JavaFileScannerContext> detectionStore,
            @Nonnull List<INode> nodes) {
        // Cross-file resolution is asserted by the Noncompliant marker in KeyGeneratorCaller.java.
    }
}
