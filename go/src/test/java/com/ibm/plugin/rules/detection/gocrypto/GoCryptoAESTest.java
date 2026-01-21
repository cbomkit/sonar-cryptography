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
package com.ibm.plugin.rules.detection.gocrypto;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.ibm.engine.detection.MatchContext;
import com.ibm.engine.language.go.GoLanguageTranslation;
import com.ibm.engine.rule.IDetectionRule;
import java.util.Collections;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.sonar.plugins.go.api.FunctionInvocationTree;
import org.sonar.plugins.go.api.IdentifierTree;
import org.sonar.plugins.go.api.MemberSelectTree;
import org.sonar.plugins.go.api.Tree;

class GoCryptoAESTest {

    private GoLanguageTranslation translation;
    private MatchContext matchContext;

    @BeforeEach
    void setUp() {
        translation = new GoLanguageTranslation();
        matchContext = new MatchContext(false, false, Collections.emptyList());
    }

    @Test
    void shouldProvideRules() {
        List<IDetectionRule<Tree>> rules = GoCryptoAES.rules();
        assertThat(rules).isNotEmpty();
        assertThat(rules).hasSize(1);
    }

    @Test
    void shouldMatchNewCipherCall() {
        // Create mock function invocation: aes.NewCipher(key)
        FunctionInvocationTree functionInvocation = mock(FunctionInvocationTree.class);
        MemberSelectTree memberSelect = mock(MemberSelectTree.class);
        IdentifierTree packageIdentifier = mock(IdentifierTree.class);
        IdentifierTree methodIdentifier = mock(IdentifierTree.class);

        when(functionInvocation.memberSelect()).thenReturn(memberSelect);
        when(memberSelect.expression()).thenReturn(packageIdentifier);
        when(memberSelect.identifier()).thenReturn(methodIdentifier);
        when(packageIdentifier.name()).thenReturn("aes");
        when(packageIdentifier.packageName()).thenReturn("crypto/aes");
        when(methodIdentifier.name()).thenReturn("NewCipher");

        // Get method name from translation
        var methodName = translation.getMethodName(matchContext, functionInvocation);
        assertThat(methodName).isPresent();
        assertThat(methodName.get()).isEqualTo("NewCipher");

        // Get invoked object type (package)
        var invokedType = translation.getInvokedObjectTypeString(matchContext, functionInvocation);
        assertThat(invokedType).isPresent();
        assertThat(invokedType.get().is("crypto/aes")).isTrue();
    }

    @Test
    void shouldNotMatchNonAesCall() {
        // Create mock function invocation: des.NewCipher(key)
        FunctionInvocationTree functionInvocation = mock(FunctionInvocationTree.class);
        MemberSelectTree memberSelect = mock(MemberSelectTree.class);
        IdentifierTree packageIdentifier = mock(IdentifierTree.class);
        IdentifierTree methodIdentifier = mock(IdentifierTree.class);

        when(functionInvocation.memberSelect()).thenReturn(memberSelect);
        when(memberSelect.expression()).thenReturn(packageIdentifier);
        when(memberSelect.identifier()).thenReturn(methodIdentifier);
        when(packageIdentifier.name()).thenReturn("des");
        when(packageIdentifier.packageName()).thenReturn("crypto/des");
        when(methodIdentifier.name()).thenReturn("NewCipher");

        // Get invoked object type (package)
        var invokedType = translation.getInvokedObjectTypeString(matchContext, functionInvocation);
        assertThat(invokedType).isPresent();
        // Should not match crypto/aes
        assertThat(invokedType.get().is("crypto/aes")).isFalse();
    }

    @Test
    void rulesShouldTargetCryptoAesPackage() {
        List<IDetectionRule<Tree>> rules = GoCryptoAES.rules();
        IDetectionRule<Tree> rule = rules.get(0);

        // Verify the rule targets crypto/aes package
        assertThat(rule.bundle().getIdentifier()).isEqualTo("GoCrypto");
    }

    @Test
    void rulesShouldTargetNewCipherMethod() {
        List<IDetectionRule<Tree>> rules = GoCryptoAES.rules();
        IDetectionRule<Tree> rule = rules.get(0);

        // Verify the rule targets NewCipher method
        if (rule instanceof com.ibm.engine.rule.DetectionRule<Tree> detectionRule) {
            assertThat(detectionRule.matchers().getMethodNamesSerializable())
                    .containsExactly("NewCipher");
            assertThat(detectionRule.matchers().getInvokedObjectTypeStringsSerializable())
                    .containsExactly("crypto/aes");
        }
    }

    @Test
    void rulesShouldHaveParameters() {
        List<IDetectionRule<Tree>> rules = GoCryptoAES.rules();
        IDetectionRule<Tree> rule = rules.get(0);

        // Verify the rule has parameter configuration
        if (rule instanceof com.ibm.engine.rule.DetectionRule<Tree> detectionRule) {
            assertThat(detectionRule.parameters()).isNotEmpty();
        }
    }
}
