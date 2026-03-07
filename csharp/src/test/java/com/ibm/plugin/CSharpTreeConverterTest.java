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

import com.ibm.engine.language.csharp.CSharpTreeConverter;
import com.ibm.engine.language.csharp.antlr.CSharpLexer;
import com.ibm.engine.language.csharp.antlr.CSharpParser;
import com.ibm.engine.language.csharp.tree.CSharpBlockTree;
import com.ibm.engine.language.csharp.tree.CSharpMethodInvocationTree;
import com.ibm.engine.language.csharp.tree.CSharpObjectCreationTree;
import com.ibm.engine.language.csharp.tree.CSharpTree;
import java.util.List;
import org.antlr.v4.runtime.CharStreams;
import org.antlr.v4.runtime.CommonTokenStream;
import org.junit.jupiter.api.Test;

/**
 * Verifies that {@link CSharpTreeConverter} correctly extracts the {@code assignedIdentifier} from
 * variable declarations ({@code var x = Expr.Create()}) and leaves it null for bare expressions.
 */
class CSharpTreeConverterTest {

    private List<CSharpBlockTree> parse(String code) {
        CSharpLexer lexer = new CSharpLexer(CharStreams.fromString(code));
        lexer.removeErrorListeners();
        CommonTokenStream tokens = new CommonTokenStream(lexer);
        CSharpParser parser = new CSharpParser(tokens);
        parser.removeErrorListeners();
        CSharpParser.Compilation_unitContext tree = parser.compilation_unit();
        return new CSharpTreeConverter().extractMethodBodies(tree);
    }

    @Test
    void assignedIdentifierIsSetForVarDeclaration() {
        // var aes = Aes.Create(); — result is assigned to "aes"
        String code =
                """
                class Foo {
                    void Bar() {
                        var aes = Aes.Create();
                    }
                }
                """;

        List<CSharpBlockTree> blocks = parse(code);
        List<CSharpTree> statements =
                blocks.stream()
                        .flatMap(b -> b.getStatements().stream())
                        .filter(s -> s instanceof CSharpMethodInvocationTree)
                        .toList();

        assertThat(statements).hasSize(1);
        CSharpMethodInvocationTree invocation = (CSharpMethodInvocationTree) statements.get(0);
        assertThat(invocation.getObjectTypeName()).isEqualTo("Aes");
        assertThat(invocation.getMethodName()).isEqualTo("Create");
        assertThat(invocation.getAssignedIdentifier()).isEqualTo("aes");
    }

    @Test
    void assignedIdentifierIsNullForBareExpression() {
        // Aes.Create(); — not assigned to any variable
        String code =
                """
                class Foo {
                    void Bar() {
                        Aes.Create();
                    }
                }
                """;

        List<CSharpBlockTree> blocks = parse(code);
        List<CSharpTree> statements =
                blocks.stream()
                        .flatMap(b -> b.getStatements().stream())
                        .filter(s -> s instanceof CSharpMethodInvocationTree)
                        .toList();

        assertThat(statements).hasSize(1);
        CSharpMethodInvocationTree invocation = (CSharpMethodInvocationTree) statements.get(0);
        assertThat(invocation.getAssignedIdentifier()).isNull();
    }

    @Test
    void assignedIdentifierIsSetForConstructor() {
        // var gcm = new AesGcm(key); — constructor result assigned to "gcm"
        String code =
                """
                class Foo {
                    void Bar() {
                        var gcm = new AesGcm(key);
                    }
                }
                """;

        List<CSharpBlockTree> blocks = parse(code);
        List<CSharpTree> statements =
                blocks.stream()
                        .flatMap(b -> b.getStatements().stream())
                        .filter(s -> s instanceof CSharpObjectCreationTree)
                        .toList();

        assertThat(statements).hasSize(1);
        CSharpObjectCreationTree creation = (CSharpObjectCreationTree) statements.get(0);
        assertThat(creation.getTypeName()).isEqualTo("AesGcm");
        assertThat(creation.getAssignedIdentifier()).isEqualTo("gcm");
    }

    @Test
    void assignedIdentifierIsNullForBareConstructor() {
        // new AesGcm(key); — no assignment
        String code =
                """
                class Foo {
                    void Bar() {
                        new AesGcm(key);
                    }
                }
                """;

        List<CSharpBlockTree> blocks = parse(code);
        List<CSharpTree> statements =
                blocks.stream()
                        .flatMap(b -> b.getStatements().stream())
                        .filter(s -> s instanceof CSharpObjectCreationTree)
                        .toList();

        assertThat(statements).hasSize(1);
        CSharpObjectCreationTree creation = (CSharpObjectCreationTree) statements.get(0);
        assertThat(creation.getAssignedIdentifier()).isNull();
    }

    @Test
    void multipleDeclarationsGetSeparateIdentifiers() {
        // Two declarations in the same block — each gets its own identifier
        String code =
                """
                class Foo {
                    void Bar() {
                        var aes = Aes.Create();
                        var rsa = RSA.Create(2048);
                    }
                }
                """;

        List<CSharpBlockTree> blocks = parse(code);
        List<CSharpMethodInvocationTree> invocations =
                blocks.stream()
                        .flatMap(b -> b.getStatements().stream())
                        .filter(s -> s instanceof CSharpMethodInvocationTree)
                        .map(s -> (CSharpMethodInvocationTree) s)
                        .toList();

        assertThat(invocations).hasSize(2);

        CSharpMethodInvocationTree aesCall =
                invocations.stream()
                        .filter(i -> "Aes".equals(i.getObjectTypeName()))
                        .findFirst()
                        .orElseThrow();
        assertThat(aesCall.getAssignedIdentifier()).isEqualTo("aes");

        CSharpMethodInvocationTree rsaCall =
                invocations.stream()
                        .filter(i -> "RSA".equals(i.getObjectTypeName()))
                        .findFirst()
                        .orElseThrow();
        assertThat(rsaCall.getAssignedIdentifier()).isEqualTo("rsa");
    }
}
