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

import com.sonar.cxx.sslr.api.AstNode;
import com.sonar.cxx.sslr.api.Grammar;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;
import javax.annotation.Nonnull;
import org.junit.jupiter.api.Test;
import org.sonar.api.batch.fs.internal.TestInputFileBuilder;
import org.sonar.cxx.CxxAstScanner;
import org.sonar.cxx.config.CxxSquidConfiguration;
import org.sonar.cxx.parser.CxxGrammarImpl;
import org.sonar.cxx.squidbridge.SquidAstVisitor;

/**
 * {@link CxxConstructorCalls} finds the calls of a constructor, with the class and the arguments:
 * the declaration of an object with arguments in parentheses or braces, also when it reads as a
 * function declaration whose parameters name values, an explicit type conversion and a
 * new-expression, of a class in a namespace or not. The declaration of an object without arguments,
 * copied from another object, of an array, of a built-in type, or of a function whose parameters
 * name types calls no constructor, nor does a member function call.
 */
class CxxConstructorCallsTest {

    private static final String FILE = "src/test/files/language/CxxConstructorCallsTestFile.cc";

    @Test
    void findsTheConstructorCallsWithTheirClassAndArguments() throws IOException {
        assertThat(constructorCalls())
                .containsExactly(
                        "Hasher(\"SHA224\")",
                        "Hasher(\"SHA384\")",
                        "Hasher(\"SHA256\",32)",
                        "Hasher(\"SHA512\")",
                        "Hasher(\"SHA1\",32)",
                        "Hasher(name,size)",
                        "crypto::Digest(\"MD5\")",
                        "Hasher(\"SHA3-256\")",
                        "Hasher(\"SHA3-384\")",
                        "crypto::Digest(\"SHA3-512\")",
                        "Hasher(\"SHAKE128\",16)");
    }

    /** The constructor calls of the file, in order, each as its class and its arguments. */
    @Nonnull
    private static List<String> constructorCalls() throws IOException {
        final List<String> calls = new ArrayList<>();
        final SquidAstVisitor<Grammar> visitor =
                new SquidAstVisitor<>() {
                    @Override
                    public void leaveFile(AstNode root) {
                        // the symbols are resolved during the walk of the file
                        collect(root, calls);
                    }
                };
        CxxAstScanner.create(new CxxSquidConfiguration(), visitor)
                .scanInputFiles(
                        List.of(
                                TestInputFileBuilder.create("", FILE)
                                        .setCharset(StandardCharsets.UTF_8)
                                        .setContents(Files.readString(Path.of(FILE)))
                                        .build()));
        return calls;
    }

    private static void collect(@Nonnull AstNode node, @Nonnull List<String> calls) {
        if (node.is(
                        CxxGrammarImpl.initDeclarator,
                        CxxGrammarImpl.postfixExpression,
                        CxxGrammarImpl.newExpression)
                && CxxConstructorCalls.isConstructorCall(node)) {
            calls.add(
                    CxxConstructorCalls.getClassName(node)
                            + CxxConstructorCalls.getArguments(node).stream()
                                    .map(CxxConstructorCalls::textOf)
                                    .collect(Collectors.joining(",", "(", ")")));
        }
        node.getChildren().forEach(child -> collect(child, calls));
    }
}
