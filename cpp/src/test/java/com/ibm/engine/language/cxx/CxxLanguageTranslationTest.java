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

import com.ibm.engine.detection.IType;
import com.ibm.engine.detection.MatchContext;
import com.sonar.cxx.sslr.api.AstNode;
import com.sonar.cxx.sslr.api.GenericTokenType;
import com.sonar.cxx.sslr.api.Grammar;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import javax.annotation.Nonnull;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.sonar.api.batch.fs.internal.TestInputFileBuilder;
import org.sonar.cxx.CxxAstScanner;
import org.sonar.cxx.config.CxxSquidConfiguration;
import org.sonar.cxx.parser.CxxGrammarImpl;
import org.sonar.cxx.squidbridge.SquidAstVisitor;
import org.sonar.cxx.utils.CxxAstNodeHelper;

/**
 * {@link CxxLanguageTranslation} gives a call the name and the object type rules and hooks match it
 * by: a free function in the global scope, a member function in the class its object, pointer or
 * reference is declared with, a function pointer member as a free function, a static member
 * function in its class, a function named in a namespace by its qualified name, and a constructor
 * as {@code <init>} of its class. An argument that is a literal or a name has its text as its type.
 */
class CxxLanguageTranslationTest {

    private static final String FILE = "src/test/files/language/CxxLanguageTranslationTestFile.cc";
    private static final String GLOBAL = CxxLanguageTranslation.GLOBAL_SCOPE;

    private static final Map<Integer, AstNode> CALLS = new HashMap<>();
    private static AstNode enumSpecifier;

    private final CxxLanguageTranslation translation = new CxxLanguageTranslation();
    private final MatchContext hook = MatchContext.createForHookContext();

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

    /** The outermost call of each line, and the enum specifier. */
    private static void collect(@Nonnull AstNode node) {
        if ((CxxConstructorCalls.isConstructorCall(node) || CxxAstNodeHelper.isFunctionCall(node))
                && !CALLS.containsKey(node.getTokenLine())) {
            CALLS.put(node.getTokenLine(), node);
        }
        if (node.is(CxxGrammarImpl.enumSpecifier)) {
            enumSpecifier = node;
        }
        node.getChildren().forEach(CxxLanguageTranslationTest::collect);
    }

    @Test
    void aFreeFunctionIsInTheGlobalScope() {
        assertCall(19, "EVP_sha256", GLOBAL, "Hasher");
    }

    @Test
    void aMemberFunctionIsInTheClassItsObjectIsDeclaredWith() {
        assertCall(20, "reset", "Hasher", GLOBAL);
        assertCall(21, "reset", "Hasher", GLOBAL);
    }

    @Test
    void aFunctionPointerMemberCallsAFreeFunction() {
        assertThat(translation.getMethodName(hook, CALLS.get(22))).contains("digest");
        final IType type =
                translation.getInvokedObjectTypeString(hook, CALLS.get(22)).orElseThrow();
        assertThat(type.is(GLOBAL)).isTrue();
        assertThat(type.is("Api")).isTrue();
    }

    @Test
    void aStaticMemberFunctionIsInItsClass() {
        assertCall(23, "make", "Hasher", GLOBAL);
    }

    @Test
    void aFunctionOfANamespaceIsNamedWithItsNamespace() {
        assertCall(24, "crypto::helper", GLOBAL, "crypto");
    }

    @Test
    void aConstructorIsInitOfItsClass() {
        assertCall(25, "<init>", "Hasher", GLOBAL);
        assertThat(translation.getMethodParameterTypes(hook, CALLS.get(25)))
                .singleElement()
                .satisfies(type -> assertThat(type.is("\"SHA224\"")).isTrue());
    }

    @Test
    void anArgumentThatIsALiteralOrANameHasItsTextAsItsType() {
        final List<IType> types = translation.getMethodParameterTypes(hook, CALLS.get(26));
        assertThat(types).hasSize(6);
        assertThat(types.get(0).is("32")).isTrue();
        assertThat(types.get(1).is("\"digest\"")).isTrue();
        assertThat(types.get(2).is("'c'")).isTrue();
        assertThat(types.get(3).is("count")).isTrue();
        assertThat(types.get(4).is("count + 1")).isFalse();
        assertThat(types.get(4).is("count")).isFalse();
        assertThat(types.get(5).is("FAST")).isTrue();
    }

    @Test
    void namesOfIdentifiersAndEnums() {
        final AstNode name = enumSpecifier.getFirstDescendant(GenericTokenType.IDENTIFIER);
        assertThat(translation.resolveIdentifierAsString(hook, name)).contains("Mode");
        assertThat(translation.getEnumIdentifierName(hook, name)).contains("Mode");
        assertThat(translation.getEnumClassName(hook, enumSpecifier)).contains("Mode");
    }

    private void assertCall(int line, String name, String type, String otherType) {
        final AstNode call = CALLS.get(line);
        assertThat(translation.getMethodName(hook, call)).as("name").contains(name);
        final IType invokedType = translation.getInvokedObjectTypeString(hook, call).orElseThrow();
        assertThat(invokedType.is(type)).as("is %s", type).isTrue();
        assertThat(invokedType.is(otherType)).as("is not %s", otherType).isFalse();
    }
}
