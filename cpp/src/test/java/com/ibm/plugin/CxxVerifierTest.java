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

import com.ibm.engine.detection.DetectionStore;
import com.ibm.mapper.model.INode;
import com.sonar.cxx.sslr.api.AstNode;
import com.sonar.cxx.sslr.api.Grammar;
import java.util.List;
import javax.annotation.Nonnull;
import org.junit.jupiter.api.Test;
import org.sonar.cxx.squidbridge.SquidAstVisitorContext;
import org.sonar.cxx.squidbridge.api.Symbol;
import org.sonar.cxx.squidbridge.checks.SquidCheck;

class CxxVerifierTest {

    @Test
    void lineCommentsSkipStringsCharactersAndBlockComments() {
        String content =
                """
                f("// not a comment"); // first
                g('/'); /* // inside a block comment */ h(); // second
                /* a block comment
                   // still inside it
                */ i(); // third
                """;

        assertThat(CxxVerifier.lineComments(content))
                .containsExactly(
                        new CxxVerifier.LineComment(1, 24, "// first"),
                        new CxxVerifier.LineComment(2, 46, "// second"),
                        new CxxVerifier.LineComment(5, 9, "// third"));
    }

    @Test
    void anIssueWithoutMarkerFails() {
        assertThatThrownBy(
                        () ->
                                CxxVerifier.verify(
                                        "verifier/IssueWithoutMarkerTestFile.cc",
                                        new AcceptAnyFinding()))
                .isInstanceOf(AssertionError.class)
                .hasMessageContaining("(MessageDigest) SHA-256");
    }

    @Test
    void aMarkerWithoutIssueFails() {
        assertThatThrownBy(
                        () ->
                                CxxVerifier.verify(
                                        "verifier/MarkerWithoutIssueTestFile.cc",
                                        new AcceptAnyFinding()))
                .isInstanceOf(AssertionError.class);
    }

    /** Reports every finding without asserting on it. */
    private static final class AcceptAnyFinding extends TestBase {
        @Override
        public void asserts(
                int findingId,
                @Nonnull
                        DetectionStore<
                                        SquidCheck<?>,
                                        AstNode,
                                        Symbol,
                                        SquidAstVisitorContext<? extends Grammar>>
                                detectionStore,
                @Nonnull List<INode> nodes) {
            // the verifier checks the reported issues
        }
    }
}
