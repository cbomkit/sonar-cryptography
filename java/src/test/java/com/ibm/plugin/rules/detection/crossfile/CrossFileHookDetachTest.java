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
import static org.assertj.core.api.Assertions.tuple;

import com.ibm.engine.detection.DetectionStore;
import com.ibm.engine.language.java.JavaDetachedIssueQueue;
import com.ibm.engine.model.IValue;
import com.ibm.mapper.model.INode;
import com.ibm.plugin.TestBase;
import java.io.File;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Proxy;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import javax.tools.JavaCompiler;
import javax.tools.ToolProvider;
import org.junit.jupiter.api.Test;
import org.sonar.java.checks.verifier.CheckVerifier;
import org.sonar.plugins.java.api.JavaCheck;
import org.sonar.plugins.java.api.JavaFileScannerContext;
import org.sonar.plugins.java.api.semantic.Symbol;
import org.sonar.plugins.java.api.tree.Tree;

/**
 * First true cross-file detection test in the suite: a hook created while analyzing {@code
 * KeyGeneratorWrapper.java} resolves calls recorded while analyzing {@code
 * KeyGeneratorCaller.java}.
 *
 * <p>Cross-file resolution requires the callee's type to resolve at the call site; production does
 * this via {@code sonar.java.binaries} (the project is compiled first). CheckVerifier does not put
 * sibling sources on the semantic classpath, so we reproduce production by compiling the fixtures
 * to {@code .class} and passing the output directory to {@link CheckVerifier#withClassPath}.
 *
 * <p>This guards the AST-detach work across its three branches: a literal argument and a
 * field-constant argument are detached (asserted via the resolved CBOM values, since a detached
 * cross-file detection produces a node but no tree-based SonarQube issue), while a {@code new
 * byte[]} argument stays on the retained-tree path (asserted via its issue on the caller).
 *
 * <p>The test does not depend on how the sonar-java test kit collects issues across files (8.6
 * checks only the last analysed file, 8.22 all of them): the rule's file context is wrapped so that
 * its issues are recorded here instead of reaching the verifier, which therefore sees none.
 */
class CrossFileHookDetachTest extends TestBase {

    private static final String WRAPPER =
            "src/test/files/rules/detection/crossfile/KeyGeneratorWrapper.java";
    private static final String CALLER =
            "src/test/files/rules/detection/crossfile/KeyGeneratorCaller.java";

    private static final List<String> resolvedValues = new ArrayList<>();

    /** An issue reported directly on a file context: file name, line and message. */
    private record ReportedIssue(@Nonnull String file, int line, @Nonnull String message) {}

    private final List<ReportedIssue> reportedIssues = new ArrayList<>();

    @Test
    void crossFileDetectionAcrossDetachedAndRetainedPaths() throws Exception {
        resolvedValues.clear();
        reportedIssues.clear();
        File classes = compileToClasspath(WRAPPER, CALLER);
        CheckVerifier.newVerifier()
                .onFiles(CALLER, WRAPPER)
                .withClassPath(List.of(classes))
                .withChecks(this)
                .verifyNoIssues();

        // All three algorithms resolve cross-file into the CBOM, regardless of detach vs retain:
        assertThat(resolvedValues).contains("AES", "Blowfish", "DES");

        // Only the retained-tree call (new byte[]) reports directly, at its call site.
        assertThat(reportedIssues)
                .extracting(ReportedIssue::file, ReportedIssue::line, ReportedIssue::message)
                .containsExactly(tuple("KeyGeneratorCaller.java", 25, "(SecretKey) DES"));

        // The detached (AES, Blowfish) issues are queued on the caller for JavaDetachedIssueSensor
        // (covered by JavaDetachedIssueSensorTest; CheckVerifier's InputFile cannot be saved
        // through SensorContextTester). The retained DES call reports directly.
        final List<JavaDetachedIssueQueue.Issue> queued = JavaDetachedIssueQueue.drain();
        assertThat(queued)
                .extracting(JavaDetachedIssueQueue.Issue::message)
                .anySatisfy(message -> assertThat(message).contains("AES"))
                .anySatisfy(message -> assertThat(message).contains("Blowfish"))
                .noneSatisfy(message -> assertThat(message).contains("DES"));
        assertThat(queued)
                .allSatisfy(
                        issue -> {
                            assertThat(issue.rule()).isSameAs(this);
                            assertThat(issue.inputFile().filename())
                                    .isEqualTo("KeyGeneratorCaller.java");
                        });
    }

    @Override
    public void setContext(@Nullable JavaFileScannerContext context) {
        super.setContext(context == null ? null : recording(context));
    }

    /** Wraps {@code delegate} so that its {@code reportIssue*} calls are recorded, not reported. */
    @Nonnull
    private JavaFileScannerContext recording(@Nonnull JavaFileScannerContext delegate) {
        return (JavaFileScannerContext)
                Proxy.newProxyInstance(
                        JavaFileScannerContext.class.getClassLoader(),
                        new Class<?>[] {JavaFileScannerContext.class},
                        (proxy, method, args) -> {
                            if (method.getName().startsWith("reportIssue")) {
                                reportedIssues.add(issueOf(delegate, args));
                                return null;
                            }
                            try {
                                return method.invoke(delegate, args);
                            } catch (InvocationTargetException e) {
                                throw e.getCause();
                            }
                        });
    }

    @Nonnull
    private static ReportedIssue issueOf(
            @Nonnull JavaFileScannerContext context, @Nonnull Object[] args) {
        final int line =
                args[1] instanceof Tree tree && tree.firstToken() != null
                        ? tree.firstToken().range().start().line()
                        : -1;
        final String message =
                Arrays.stream(args)
                        .filter(String.class::isInstance)
                        .map(String.class::cast)
                        .findFirst()
                        .orElse("");
        return new ReportedIssue(context.getInputFile().filename(), line, message);
    }

    @Override
    public void asserts(
            int findingId,
            @Nonnull DetectionStore<JavaCheck, Tree, Symbol, JavaFileScannerContext> detectionStore,
            @Nonnull List<INode> nodes) {
        collectAlgorithmValues(detectionStore);
    }

    private void collectAlgorithmValues(
            @Nonnull DetectionStore<JavaCheck, Tree, Symbol, JavaFileScannerContext> store) {
        for (IValue<Tree> value : store.getDetectionValues()) {
            resolvedValues.add(value.asString());
        }
        store.getChildren().forEach(this::collectAlgorithmValues);
    }

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
}
