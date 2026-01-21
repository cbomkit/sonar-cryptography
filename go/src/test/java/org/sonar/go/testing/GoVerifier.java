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
package org.sonar.go.testing;

import org.sonar.api.batch.fs.InputFile;
import org.sonar.go.visitors.SymbolVisitor;
import org.sonar.go.visitors.TreeContext;
import org.sonar.go.visitors.TreeVisitor;
import org.sonar.plugins.go.api.HasTextRange;
import org.sonar.plugins.go.api.TextPointer;
import org.sonar.plugins.go.api.TextRange;
import org.sonar.plugins.go.api.TopLevelTree;
import org.sonar.plugins.go.api.Tree;
import org.sonar.plugins.go.api.checks.CheckContext;
import org.sonar.plugins.go.api.checks.GoCheck;
import org.sonar.plugins.go.api.checks.GoModFileData;
import org.sonar.plugins.go.api.checks.InitContext;
import org.sonar.plugins.go.api.checks.SecondaryLocation;
import org.sonarsource.analyzer.commons.checks.verifier.SingleFileVerifier;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.function.BiConsumer;
import java.util.function.Consumer;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Test verifier for Go checks. Adapted from SonarSource sonar-go GoVerifier.
 *
 * <p>This version works without the native Go parser by using mock-based testing or integration
 * with the detection engine. For full AST-based testing, use TestBase with the detection rules
 * infrastructure.
 *
 * <p>Usage with expected issues in comments:
 *
 * <pre>
 * // In test file:
 * block, _ := aes.NewCipher(key) // Noncompliant {{Expected message}}
 *
 * // In test:
 * GoVerifier.verify("path/to/test.go", check);
 * </pre>
 */
public class GoVerifier {
    private static final Path BASE_DIR = Paths.get("src", "test", "files");
    public static final File CONVERTER_DIR = Paths.get("build", "test-tmp").toFile();

    public static final GoConverter GO_CONVERTER_DEBUG_TYPE_CHECK = createConverter();

    private GoVerifier() {
        // Utility class
    }

    private static GoConverter createConverter() {
        return new GoConverter(new GoParseWithExistingBinaryCommand(CONVERTER_DIR, "-debug_type_check"));
    }

    /**
     * Verifies that the check reports one or more issues on the given file. Issues are expected to
     * be marked with "// Noncompliant" comments.
     */
    public static void verify(String fileName, GoCheck check) {
        SingleFileVerifier verifier = createVerifier(BASE_DIR.resolve(fileName), check);
        verifier.assertOneOrMoreIssues();
    }

    /** Verifies that the check reports no issues on the given file. */
    public static void verifyNoIssue(String fileName, GoCheck check) {
        SingleFileVerifier verifier = createVerifier(BASE_DIR.resolve(fileName), check);
        verifier.assertNoIssues();
    }

    /**
     * Creates a verifier for the given path and check. Since we don't have access to GoConverter,
     * this uses a mock-based approach that focuses on validating the comment-based issue
     * expectations.
     */
    protected static @Nonnull SingleFileVerifier createVerifier(Path path, GoCheck check) {
        SingleFileVerifier verifier = SingleFileVerifier.create(path, UTF_8);

        String testFileContent = readFile(path);
        GoModFileData goModFileData = GoModFileData.UNKNOWN_DATA;
        Tree root =
                GO_CONVERTER_DEBUG_TYPE_CHECK
                        .parse(Map.of("foo.go", testFileContent), goModFileData.moduleName())
                        .get("foo.go")
                        .tree();
        if (root instanceof TopLevelTree topLevelTree) {
            topLevelTree
                    .allComments()
                    .forEach(
                            comment -> {
                                TextPointer start = comment.textRange().start();
                                verifier.addComment(
                                        start.line(), start.lineOffset() + 1, comment.text(), 2, 0);
                            });
        }

        TestContext ctx =
                new TestContext(
                        verifier,
                        createMockInputFile(path),
                        path.getFileName().toString(),
                        testFileContent);
        new SymbolVisitor<>().scan(ctx, root);
        check.initialize(ctx);
        ctx.scan(root);

        return verifier;
    }

    protected static String readFile(Path path) {
        try {
            return Files.readString(path);
        } catch (IOException e) {
            throw new IllegalStateException("Cannot read " + path, e);
        }
    }

    private static InputFile createMockInputFile(Path path) {
        InputFile inputFile = mock(InputFile.class);
        when(inputFile.filename()).thenReturn(path.getFileName().toString());
        when(inputFile.uri()).thenReturn(path.toUri());
        return inputFile;
    }

    /**
     * Test context that implements both InitContext and CheckContext. This allows checks to
     * register handlers and report issues.
     */
    public static class TestContext extends TreeContext implements InitContext, CheckContext {

        private final TreeVisitor<TestContext> visitor;
        private final SingleFileVerifier verifier;
        private final InputFile inputFile;
        private final String filename;
        private final String testFileContent;
        private final List<ReportedIssue> reportedIssues = new ArrayList<>();
        private Consumer<Tree> onLeave;

        public TestContext(
                SingleFileVerifier verifier,
                InputFile inputFile,
                String filename,
                String testFileContent) {
            this.verifier = verifier;
            this.inputFile = inputFile;
            this.filename = filename;
            this.testFileContent = testFileContent;
            this.visitor = new TreeVisitor<>();
        }

        public void scan(@Nullable Tree root) {
            visitor.scan(this, root);
            if (onLeave != null) {
                onLeave.accept(root);
            }
        }

        @Override
        public <T extends Tree> void register(
                @Nonnull Class<T> cls, @Nonnull BiConsumer<CheckContext, T> consumer) {
            visitor.register(cls, (ctx, node) -> consumer.accept(this, node));
        }

        @Override
        public void registerOnLeave(@Nonnull BiConsumer<CheckContext, Tree> visitor) {
            this.onLeave = tree -> visitor.accept(this, tree);
        }

        @Override
        public void reportIssue(@Nonnull HasTextRange toHighlight, @Nonnull String message) {
            reportIssue(toHighlight, message, Collections.emptyList());
        }

        @Override
        public void reportIssue(
                @Nonnull HasTextRange toHighlight,
                @Nonnull String message,
                @Nonnull SecondaryLocation secondaryLocation) {
            reportIssue(toHighlight, message, Collections.singletonList(secondaryLocation));
        }

        @Override
        public String filename() {
            return filename;
        }

        @Override
        public InputFile inputFile() {
            return inputFile;
        }

        @Override
        public String fileContent() {
            return testFileContent;
        }

        @Override
        public GoModFileData goModFileData() {
            return GoModFileData.UNKNOWN_DATA;
        }

        @Override
        public void reportIssue(@Nonnull TextRange textRange, @Nonnull String message) {
            reportIssue(textRange, message, Collections.emptyList(), null);
        }

        @Override
        public void reportIssue(
                @Nonnull HasTextRange toHighlight,
                @Nonnull String message,
                @Nonnull List<SecondaryLocation> secondaryLocations) {
            reportIssue(toHighlight, message, secondaryLocations, null);
        }

        @Override
        public void reportIssue(
                @Nonnull HasTextRange toHighlight,
                @Nonnull String message,
                @Nonnull List<SecondaryLocation> secondaryLocations,
                @Nullable Double gap) {
            reportIssue(toHighlight.textRange(), message, secondaryLocations, gap);
        }

        @Override
        public void reportFileIssue(@Nonnull String message) {
            reportFileIssue(message, null);
        }

        @Override
        public void reportFileIssue(@Nonnull String message, @Nullable Double gap) {
            verifier.reportIssue(message).onFile().withGap(gap);
            reportedIssues.add(new ReportedIssue(0, message));
        }

        private void reportIssue(
                TextRange textRange,
                String message,
                List<SecondaryLocation> secondaryLocations,
                @Nullable Double gap) {
            TextPointer start = textRange.start();
            TextPointer end = textRange.end();
            SingleFileVerifier.Issue issue =
                    verifier.reportIssue(message)
                            .onRange(
                                    start.line(),
                                    start.lineOffset() + 1,
                                    end.line(),
                                    end.lineOffset())
                            .withGap(gap);
            secondaryLocations.forEach(
                    secondary ->
                            issue.addSecondary(
                                    secondary.textRange.start().line(),
                                    secondary.textRange.start().lineOffset() + 1,
                                    secondary.textRange.end().line(),
                                    secondary.textRange.end().lineOffset(),
                                    secondary.message));
            reportedIssues.add(new ReportedIssue(start.line(), message));
        }

        public List<ReportedIssue> getReportedIssues() {
            return Collections.unmodifiableList(reportedIssues);
        }
    }

    /** Simple record to track reported issues. */
    public record ReportedIssue(int line, String message) {}
}
