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
import com.sonar.cxx.sslr.api.AstNodeType;
import java.lang.ref.WeakReference;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.sonar.cxx.squidbridge.api.Symbol;
import org.sonar.cxx.squidbridge.api.Type;

/**
 * Verifies that {@code createTypeFromCxxType}'s returned {@link IType} does not capture the
 * sonar-cxx {@link Type} it was built from. A {@code Type}'s {@code TypeSymbol} can hold a live
 * {@link AstNode} via {@code declaration()}, and any reachable {@code AstNode} keeps its whole
 * file's parse tree alive through parent/child/sibling links.
 *
 * <p>Builds a {@code Type} backed by a real {@code AstNode}, drops every strong reference except
 * the produced {@link IType}, forces GC, and asserts the node is collected.
 */
class CxxLanguageTranslationAstDetachTest {

    private final CxxLanguageTranslation translation = new CxxLanguageTranslation();

    @Test
    void hookContextTypeDoesNotPinTheDeclarationAstNode() {
        assertDeclarationNodeIsCollectable(MatchContext.createForHookContext());
    }

    @Test
    void exactMatchTypeDoesNotPinTheDeclarationAstNode() {
        assertDeclarationNodeIsCollectable(new MatchContext(false, true, List.of()));
    }

    @Test
    void subtypeMatchTypeDoesNotPinTheDeclarationAstNode() {
        assertDeclarationNodeIsCollectable(new MatchContext(false, false, List.of()));
    }

    private void assertDeclarationNodeIsCollectable(MatchContext matchContext) {
        Built built = buildTypeAndDropAstReferences(matchContext);

        assertThat(built.type.is("MyNamespace::MyClass")).isTrue();
        assertThat(built.type.is("Something::Else")).isFalse();

        forceGc();
        assertThat(built.declarationRef.get())
                .as(
                        "createTypeFromCxxType must not capture the sonar-cxx Type/TypeSymbol chain: "
                                + "doing so keeps the declaration AstNode - and via getParent(), its "
                                + "whole file's AST - reachable for as long as the IType survives")
                .isNull();
    }

    private Built buildTypeAndDropAstReferences(MatchContext matchContext) {
        AstNode wholeFileTree = new AstNode(new FakeAstNodeType(), "translationUnit", null);
        AstNode declarationNode = new AstNode(new FakeAstNodeType(), "classSpecifier", null);
        wholeFileTree.addChild(declarationNode);
        WeakReference<AstNode> declarationRef = new WeakReference<>(declarationNode);

        Symbol.TypeSymbol typeSymbol = new FakeTypeSymbol(declarationNode);
        Type cxxType = new Type.CxxType("MyNamespace::MyClass", typeSymbol);

        IType type = translation.createTypeFromCxxType(cxxType, matchContext);
        return new Built(type, declarationRef);
    }

    private record Built(IType type, WeakReference<AstNode> declarationRef) {}

    private static void forceGc() {
        for (int i = 0; i < 10; i++) {
            System.gc();
            byte[] pressure = new byte[4 * 1024 * 1024];
            assertThat(pressure).isNotNull();
        }
    }

    private static final class FakeAstNodeType implements AstNodeType {}

    /**
     * Minimal {@link Symbol.TypeSymbol} whose only real behavior is a fixed {@code declaration()}.
     */
    private static final class FakeTypeSymbol extends Symbol.UnknownTypeSymbol {
        private final AstNode declarationNode;

        FakeTypeSymbol(AstNode declarationNode) {
            this.declarationNode = declarationNode;
        }

        @Override
        public AstNode declaration() {
            return declarationNode;
        }

        @Override
        public String fullyQualifiedName() {
            return "MyNamespace::MyClass";
        }
    }
}
