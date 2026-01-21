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
package com.ibm.engine.language.go;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

import com.ibm.engine.detection.ResolvedValue;
import com.ibm.engine.detection.TraceSymbol;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.sonar.go.symbols.Symbol;
import org.sonar.plugins.go.api.FunctionDeclarationTree;
import org.sonar.plugins.go.api.FunctionInvocationTree;
import org.sonar.plugins.go.api.HasSymbol;
import org.sonar.plugins.go.api.IdentifierTree;
import org.sonar.plugins.go.api.LiteralTree;
import org.sonar.plugins.go.api.ParameterTree;
import org.sonar.plugins.go.api.Tree;

class GoDetectionEngineTest {

    @Test
    void shouldReturnEmptyForAssignedSymbolWhenNotHasSymbol() {
        GoDetectionEngine engine = createMinimalEngine();
        Tree tree = mock(Tree.class);
        assertThat(engine.getAssignedSymbol(tree)).isEmpty();
    }

    @Test
    void shouldReturnSymbolForAssignedSymbolWhenHasSymbol() {
        GoDetectionEngine engine = createMinimalEngine();
        // Create a mock that implements both Tree and HasSymbol
        IdentifierTree identifierTree = mock(IdentifierTree.class);
        // Use a real Symbol instance since Mockito can't mock it
        Symbol symbol = new Symbol("testType");
        when(identifierTree.symbol()).thenReturn(symbol);

        var result = engine.getAssignedSymbol(identifierTree);

        assertThat(result).isPresent();
        assertThat(result.get().getSymbol()).isSameAs(symbol);
    }

    @Test
    void shouldReturnEmptyForMethodInvocationParameterSymbolWhenNotFunctionInvocation() {
        GoDetectionEngine engine = createMinimalEngine();
        Tree tree = mock(Tree.class);
        assertThat(engine.getMethodInvocationParameterSymbol(tree, null)).isEmpty();
    }

    @Test
    void shouldReturnFalseForInvocationOnVariable() {
        GoDetectionEngine engine = createMinimalEngine();
        FunctionInvocationTree tree = mock(FunctionInvocationTree.class);
        TraceSymbol<Symbol> traceSymbol = TraceSymbol.createStart();
        assertThat(engine.isInvocationOnVariable(tree, traceSymbol)).isFalse();
    }

    @Test
    void shouldReturnFalseForInitForVariable() {
        GoDetectionEngine engine = createMinimalEngine();
        Tree tree = mock(Tree.class);
        TraceSymbol<Symbol> traceSymbol = TraceSymbol.createStart();
        assertThat(engine.isInitForVariable(tree, traceSymbol)).isFalse();
    }

    @Test
    void shouldResolveStringFromLiteralTree() {
        GoDetectionEngine engine = createMinimalEngine();
        LiteralTree literalTree = mock(LiteralTree.class);
        when(literalTree.value()).thenReturn("\"test-value\"");

        List<ResolvedValue<String, Tree>> result =
                engine.resolveValuesInInnerScope(String.class, literalTree, null);

        assertThat(result).hasSize(1);
        assertThat(result.get(0).value()).isEqualTo("\"test-value\"");
        assertThat(result.get(0).tree()).isSameAs(literalTree);
    }

    @Test
    void shouldResolveStringFromIdentifierTree() {
        GoDetectionEngine engine = createMinimalEngine();
        IdentifierTree identifierTree = mock(IdentifierTree.class);
        when(identifierTree.name()).thenReturn("variableName");

        List<ResolvedValue<String, Tree>> result =
                engine.resolveValuesInInnerScope(String.class, identifierTree, null);

        assertThat(result).hasSize(1);
        assertThat(result.get(0).value()).isEqualTo("variableName");
        assertThat(result.get(0).tree()).isSameAs(identifierTree);
    }

    @Test
    void shouldReturnEmptyListForUnknownTreeType() {
        GoDetectionEngine engine = createMinimalEngine();
        Tree unknownTree = mock(Tree.class);

        List<ResolvedValue<String, Tree>> result =
                engine.resolveValuesInInnerScope(String.class, unknownTree, null);

        assertThat(result).isEmpty();
    }

    @Test
    void shouldReturnNullForEnumValue() {
        GoDetectionEngine engine = createMinimalEngine();
        Tree tree = mock(Tree.class);
        assertThat(engine.resolveEnumValue(String.class, tree, null)).isNull();
    }

    @Test
    void shouldExtractArgumentFromFunctionInvocation() {
        GoDetectionEngine engine = createMinimalEngine();

        // Create function declaration with parameters
        FunctionDeclarationTree functionDecl = mock(FunctionDeclarationTree.class);
        ParameterTree param0 = mock(ParameterTree.class);
        ParameterTree param1 = mock(ParameterTree.class);
        IdentifierTree param0Id = mock(IdentifierTree.class);
        IdentifierTree param1Id = mock(IdentifierTree.class);
        when(param0.identifier()).thenReturn(param0Id);
        when(param1.identifier()).thenReturn(param1Id);
        when(param0Id.name()).thenReturn("key");
        when(param1Id.name()).thenReturn("plaintext");
        when(functionDecl.formalParameters()).thenReturn(List.of(param0, param1));

        // Create function invocation with arguments
        FunctionInvocationTree functionInvocation = mock(FunctionInvocationTree.class);
        Tree arg0 = mock(Tree.class);
        Tree arg1 = mock(Tree.class);
        when(functionInvocation.arguments()).thenReturn(List.of(arg0, arg1));

        // Create parameter identifier to look up
        IdentifierTree targetParam = mock(IdentifierTree.class);
        when(targetParam.name()).thenReturn("key");

        Tree result = engine.extractArgumentFromMethodCaller(functionDecl, functionInvocation, targetParam);
        assertThat(result).isSameAs(arg0);

        // Test second parameter
        when(targetParam.name()).thenReturn("plaintext");
        result = engine.extractArgumentFromMethodCaller(functionDecl, functionInvocation, targetParam);
        assertThat(result).isSameAs(arg1);
    }

    @Test
    void shouldReturnNullWhenParameterCountMismatch() {
        GoDetectionEngine engine = createMinimalEngine();

        FunctionDeclarationTree functionDecl = mock(FunctionDeclarationTree.class);
        when(functionDecl.formalParameters()).thenReturn(List.of(mock(Tree.class)));

        FunctionInvocationTree functionInvocation = mock(FunctionInvocationTree.class);
        when(functionInvocation.arguments()).thenReturn(List.of()); // Empty arguments

        IdentifierTree targetParam = mock(IdentifierTree.class);
        when(targetParam.name()).thenReturn("param");

        Tree result = engine.extractArgumentFromMethodCaller(functionDecl, functionInvocation, targetParam);
        assertThat(result).isNull();
    }

    @Test
    void shouldReturnNullWhenParameterNotFound() {
        GoDetectionEngine engine = createMinimalEngine();

        FunctionDeclarationTree functionDecl = mock(FunctionDeclarationTree.class);
        ParameterTree param = mock(ParameterTree.class);
        IdentifierTree paramId = mock(IdentifierTree.class);
        when(param.identifier()).thenReturn(paramId);
        when(paramId.name()).thenReturn("existingParam");
        when(functionDecl.formalParameters()).thenReturn(List.of(param));

        FunctionInvocationTree functionInvocation = mock(FunctionInvocationTree.class);
        when(functionInvocation.arguments()).thenReturn(List.of(mock(Tree.class)));

        IdentifierTree targetParam = mock(IdentifierTree.class);
        when(targetParam.name()).thenReturn("nonExistentParam");

        Tree result = engine.extractArgumentFromMethodCaller(functionDecl, functionInvocation, targetParam);
        assertThat(result).isNull();
    }

    @Test
    void shouldReturnNullForNonMatchingTypes() {
        GoDetectionEngine engine = createMinimalEngine();
        Tree tree = mock(Tree.class);
        Tree invocation = mock(Tree.class);
        Tree param = mock(Tree.class);

        Tree result = engine.extractArgumentFromMethodCaller(tree, invocation, param);
        assertThat(result).isNull();
    }

    /**
     * Creates a minimal GoDetectionEngine instance for testing methods that don't require
     * DetectionStore or Handler functionality.
     */
    private GoDetectionEngine createMinimalEngine() {
        // Pass null - tests only use methods that don't require these dependencies
        return new GoDetectionEngine(null, null);
    }
}
