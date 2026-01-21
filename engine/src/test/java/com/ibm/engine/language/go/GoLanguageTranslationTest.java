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

import com.ibm.engine.detection.IType;
import com.ibm.engine.detection.MatchContext;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.sonar.plugins.go.api.FunctionInvocationTree;
import org.sonar.plugins.go.api.IdentifierTree;
import org.sonar.plugins.go.api.MemberSelectTree;

class GoLanguageTranslationTest {

    private GoLanguageTranslation translation;
    private MatchContext matchContext;

    @BeforeEach
    void setUp() {
        translation = new GoLanguageTranslation();
        matchContext = new MatchContext(false, false, Collections.emptyList());
    }

    @Test
    void shouldCreateInstance() {
        assertThat(translation).isNotNull();
    }

    @Test
    void shouldGetMethodNameFromMemberSelect() {
        // Arrange: pkg.Function() pattern
        FunctionInvocationTree functionInvocation = mock(FunctionInvocationTree.class);
        MemberSelectTree memberSelect = mock(MemberSelectTree.class);
        IdentifierTree methodIdentifier = mock(IdentifierTree.class);

        when(functionInvocation.memberSelect()).thenReturn(memberSelect);
        when(memberSelect.identifier()).thenReturn(methodIdentifier);
        when(methodIdentifier.name()).thenReturn("NewCipher");

        // Act
        Optional<String> methodName = translation.getMethodName(matchContext, functionInvocation);

        // Assert
        assertThat(methodName).isPresent().hasValue("NewCipher");
    }

    @Test
    void shouldGetMethodNameFromDirectCall() {
        // Arrange: Function() pattern (direct call)
        FunctionInvocationTree functionInvocation = mock(FunctionInvocationTree.class);
        IdentifierTree identifierTree = mock(IdentifierTree.class);

        when(functionInvocation.memberSelect()).thenReturn(identifierTree);
        when(identifierTree.name()).thenReturn("println");

        // Act
        Optional<String> methodName = translation.getMethodName(matchContext, functionInvocation);

        // Assert
        assertThat(methodName).isPresent().hasValue("println");
    }

    @Test
    void shouldGetInvokedObjectTypeFromPackageCall() {
        // Arrange: aes.NewCipher() pattern
        FunctionInvocationTree functionInvocation = mock(FunctionInvocationTree.class);
        MemberSelectTree memberSelect = mock(MemberSelectTree.class);
        IdentifierTree packageIdentifier = mock(IdentifierTree.class);

        when(functionInvocation.memberSelect()).thenReturn(memberSelect);
        when(memberSelect.expression()).thenReturn(packageIdentifier);
        when(packageIdentifier.name()).thenReturn("aes");
        when(packageIdentifier.packageName()).thenReturn("crypto/aes");
        when(packageIdentifier.type()).thenReturn("");

        // Act
        Optional<IType> type = translation.getInvokedObjectTypeString(matchContext, functionInvocation);

        // Assert
        assertThat(type).isPresent();
        assertThat(type.get().is("crypto/aes")).isTrue();
        assertThat(type.get().is("aes")).isTrue();
    }

    @Test
    void shouldMatchGoPackagePatterns() {
        // Arrange: aes.NewCipher() with package alias matching full path
        FunctionInvocationTree functionInvocation = mock(FunctionInvocationTree.class);
        MemberSelectTree memberSelect = mock(MemberSelectTree.class);
        IdentifierTree packageIdentifier = mock(IdentifierTree.class);

        when(functionInvocation.memberSelect()).thenReturn(memberSelect);
        when(memberSelect.expression()).thenReturn(packageIdentifier);
        when(packageIdentifier.name()).thenReturn("aes");
        when(packageIdentifier.packageName()).thenReturn("");
        when(packageIdentifier.type()).thenReturn("");

        // Act
        Optional<IType> type = translation.getInvokedObjectTypeString(matchContext, functionInvocation);

        // Assert
        assertThat(type).isPresent();
        // "aes" should match "crypto/aes" pattern
        assertThat(type.get().is("crypto/aes")).isTrue();
    }

    @Test
    void shouldResolveIdentifierAsString() {
        // Arrange
        IdentifierTree identifierTree = mock(IdentifierTree.class);
        when(identifierTree.name()).thenReturn("myVariable");

        // Act
        Optional<String> result = translation.resolveIdentifierAsString(matchContext, identifierTree);

        // Assert
        assertThat(result).isPresent().hasValue("myVariable");
    }

    @Test
    void shouldGetEmptyMethodParameterTypesForNoArgs() {
        // Arrange
        FunctionInvocationTree functionInvocation = mock(FunctionInvocationTree.class);
        when(functionInvocation.arguments()).thenReturn(Collections.emptyList());

        // Act
        List<IType> types = translation.getMethodParameterTypes(matchContext, functionInvocation);

        // Assert
        assertThat(types).isEmpty();
    }

    @Test
    void shouldReturnEmptyForEnumClassName() {
        // Arrange
        IdentifierTree tree = mock(IdentifierTree.class);

        // Act
        Optional<String> result = translation.getEnumClassName(matchContext, tree);

        // Assert
        assertThat(result).isEmpty(); // Go doesn't have enum classes
    }
}
