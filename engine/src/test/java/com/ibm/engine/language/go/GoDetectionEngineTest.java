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
import org.sonar.plugins.go.api.FunctionInvocationTree;
import org.sonar.plugins.go.api.IdentifierTree;
import org.sonar.plugins.go.api.LiteralTree;
import org.sonar.plugins.go.api.Tree;

class GoDetectionEngineTest {

    @Test
    void shouldReturnEmptyForAssignedSymbol() {
        // Go doesn't expose symbols - test the static behavior
        GoDetectionEngine engine = createMinimalEngine();
        Tree tree = mock(Tree.class);
        assertThat(engine.getAssignedSymbol(tree)).isEmpty();
    }

    @Test
    void shouldReturnEmptyForMethodInvocationParameterSymbol() {
        // Go doesn't expose symbols
        GoDetectionEngine engine = createMinimalEngine();
        FunctionInvocationTree tree = mock(FunctionInvocationTree.class);
        assertThat(engine.getMethodInvocationParameterSymbol(tree, null)).isEmpty();
    }

    @Test
    void shouldReturnEmptyForNewClassParameterSymbol() {
        // Go doesn't have new class syntax
        GoDetectionEngine engine = createMinimalEngine();
        Tree tree = mock(Tree.class);
        assertThat(engine.getNewClassParameterSymbol(tree, null)).isEmpty();
    }

    @Test
    void shouldReturnFalseForInvocationOnVariable() {
        // Go doesn't expose symbols, so we can't track variable invocations
        GoDetectionEngine engine = createMinimalEngine();
        FunctionInvocationTree tree = mock(FunctionInvocationTree.class);
        TraceSymbol<Void> traceSymbol = TraceSymbol.createStart();
        assertThat(engine.isInvocationOnVariable(tree, traceSymbol)).isFalse();
    }

    @Test
    void shouldReturnFalseForInitForVariable() {
        // Go doesn't have new class syntax
        GoDetectionEngine engine = createMinimalEngine();
        Tree tree = mock(Tree.class);
        TraceSymbol<Void> traceSymbol = TraceSymbol.createStart();
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
        // Go doesn't have enums
        GoDetectionEngine engine = createMinimalEngine();
        Tree tree = mock(Tree.class);
        assertThat(engine.resolveEnumValue(String.class, tree, null)).isNull();
    }

    @Test
    void shouldExtractArgumentFromFunctionInvocation() {
        GoDetectionEngine engine = createMinimalEngine();
        FunctionInvocationTree functionInvocation = mock(FunctionInvocationTree.class);
        Tree arg0 = mock(Tree.class);
        Tree arg1 = mock(Tree.class);
        when(functionInvocation.arguments()).thenReturn(List.of(arg0, arg1));

        Tree result = engine.extractArgumentFromMethodCaller(null, functionInvocation, 0, null);
        assertThat(result).isSameAs(arg0);

        result = engine.extractArgumentFromMethodCaller(null, functionInvocation, 1, null);
        assertThat(result).isSameAs(arg1);
    }

    @Test
    void shouldReturnNullForInvalidArgumentIndex() {
        GoDetectionEngine engine = createMinimalEngine();
        FunctionInvocationTree functionInvocation = mock(FunctionInvocationTree.class);
        when(functionInvocation.arguments()).thenReturn(List.of());

        Tree result = engine.extractArgumentFromMethodCaller(null, functionInvocation, 0, null);
        assertThat(result).isNull();
    }

    @Test
    void shouldReturnNullForNegativeArgumentIndex() {
        GoDetectionEngine engine = createMinimalEngine();
        FunctionInvocationTree functionInvocation = mock(FunctionInvocationTree.class);
        Tree arg0 = mock(Tree.class);
        when(functionInvocation.arguments()).thenReturn(List.of(arg0));

        Tree result = engine.extractArgumentFromMethodCaller(null, functionInvocation, -1, null);
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
