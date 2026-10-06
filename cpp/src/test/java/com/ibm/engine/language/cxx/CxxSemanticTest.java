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
package com.ibm.engine.language.cxx;

import static org.assertj.core.api.Assertions.assertThat;

import com.ibm.engine.detection.ResolvedValue;
import com.sonar.cxx.sslr.api.AstNode;
import com.sonar.cxx.sslr.api.Grammar;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;
import javax.annotation.Nonnull;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.sonar.api.batch.fs.internal.TestInputFileBuilder;
import org.sonar.cxx.CxxAstScanner;
import org.sonar.cxx.config.CxxSquidConfiguration;
import org.sonar.cxx.squidbridge.SquidAstVisitor;
import org.sonar.cxx.utils.CxxAstNodeHelper;

/**
 * {@link CxxSemantic} resolves an expression to the values it has as C and C++ give them: string
 * literals with their prefixes and adjacent literals joined, character and number literals of every
 * base and suffix, the boolean and null literals, parenthesized expressions, the branches of a
 * conditional, casts, constant arithmetic, the name of an undeclared macro, the value of an
 * assignment, enumerators with an explicit or an implicit value, and a variable's initial and
 * assigned values. A field or a parameter has no value of its own.
 */
class CxxSemanticTest {

    private static final String FILE = "src/test/files/language/CxxSemanticTestFile.cc";

    /** The argument of the call {@code v(...)} of each line. */
    private static final Map<Integer, AstNode> ARGUMENTS = new HashMap<>();

    @BeforeAll
    static void scan() throws IOException {
        final SquidAstVisitor<Grammar> visitor =
                new SquidAstVisitor<>() {
                    @Override
                    public void leaveFile(AstNode root) {
                        // the symbols are resolved during the walk of the file
                        collect(root);
                    }
                };
        CxxAstScanner.create(new CxxSquidConfiguration(), visitor)
                .scanInputFiles(
                        List.of(
                                TestInputFileBuilder.create("", FILE)
                                        .setCharset(StandardCharsets.UTF_8)
                                        .setContents(Files.readString(Path.of(FILE)))
                                        .build()));
    }

    private static void collect(@Nonnull AstNode node) {
        if (CxxAstNodeHelper.isFunctionCall(node)
                && "v".equals(CxxAstNodeHelper.getFunctionCallName(node))) {
            ARGUMENTS.put(
                    node.getTokenLine(), CxxAstNodeHelper.getFunctionCallArguments(node).get(0));
        }
        node.getChildren().forEach(CxxSemanticTest::collect);
    }

    static Stream<Arguments> values() {
        return Stream.of(
                Arguments.of(12, List.of("plain")),
                Arguments.of(13, List.of("wide")),
                Arguments.of(14, List.of("utf16")),
                Arguments.of(15, List.of("utf32")),
                Arguments.of(16, List.of("utf8")),
                Arguments.of(17, List.of("raw")),
                Arguments.of(18, List.of("concat")),
                Arguments.of(19, List.of("c")),
                Arguments.of(20, List.of(42)),
                Arguments.of(21, List.of(42)),
                Arguments.of(22, List.of(16)),
                Arguments.of(23, List.of(2147483648L)),
                Arguments.of(24, List.of(5)),
                Arguments.of(25, List.of(8)),
                Arguments.of(26, List.of(1.5)),
                Arguments.of(27, List.of(1000)),
                Arguments.of(28, List.of(5000000000L)),
                Arguments.of(29, List.of(0.0)),
                Arguments.of(30, List.of(true)),
                Arguments.of(31, List.of(false)),
                Arguments.of(32, List.of("nullptr")),
                Arguments.of(33, List.of(24)),
                Arguments.of(34, List.of("either", "or")),
                Arguments.of(35, List.of("chosen")),
                Arguments.of(36, List.of("cast")),
                Arguments.of(37, List.of(7)),
                Arguments.of(38, List.of(2048)),
                Arguments.of(39, List.of("TLS1_2_VERSION")),
                Arguments.of(40, List.of("assigned")),
                Arguments.of(41, List.of(3)),
                Arguments.of(42, List.of(4)),
                Arguments.of(43, List.of(1)),
                Arguments.of(44, List.of("initial", "reassigned")),
                Arguments.of(45, List.of()),
                Arguments.of(46, List.of()));
    }

    @ParameterizedTest(name = "line {0}")
    @MethodSource("values")
    void resolvesTheValuesOfAnExpression(int line, List<Object> expected) {
        final AstNode argument = ARGUMENTS.get(line);
        assertThat(argument).as("argument of line %d", line).isNotNull();
        assertThat(
                        CxxSemantic.resolveValues(
                                        Object.class,
                                        argument,
                                        new LinkedList<>(),
                                        null,
                                        false,
                                        null)
                                .stream()
                                .map(ResolvedValue::value)
                                .toList())
                .as("values of line %d", line)
                .isEqualTo(expected);
    }
}
