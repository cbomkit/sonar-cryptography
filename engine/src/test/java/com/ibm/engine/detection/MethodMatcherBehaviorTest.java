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
package com.ibm.engine.detection;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.ibm.engine.language.ILanguageTranslation;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.Test;

class MethodMatcherBehaviorTest {
    private static IType type(String name) {
        return name::equals;
    }

    @Test
    void matchesAlternativeOwnersAndNames() {
        var matcher =
                new MethodMatcher<Object>(
                        new String[] {"Cipher", "Mac"},
                        new String[] {"create", "getInstance"},
                        List.of("String"));
        for (String owner : List.of("Cipher", "Mac")) {
            for (String name : List.of("create", "getInstance")) {
                assertThat(matcher.matchKeys(type(owner), name, List.of(type("String")))).isTrue();
            }
        }
        assertThat(matcher.matchKeys(type("Other"), "create", List.of(type("String")))).isFalse();
        assertThat(matcher.matchKeys(type("Mac"), "other", List.of(type("String")))).isFalse();
    }

    @Test
    void wildcardsMatchAnyOwnerNameAndOneParameter() {
        var matcher = new MethodMatcher<Object>("*", "*", List.of("*"));
        assertThat(matcher.matchKeys(type("Anything"), "anything", List.of(type("Unknown"))))
                .isTrue();
        assertThat(matcher.matchKeys(type("Anything"), "anything", List.of())).isFalse();
        assertThat(matcher.matchKeys(type("Anything"), "anything", List.of(type("A"), type("B"))))
                .isFalse();
    }

    @Test
    void parameterWildcardsCanBeRepeatedAndMixedWithConcreteTypes() {
        var matcher = new MethodMatcher<Object>("Cipher", "create", List.of("*", "String", "*"));
        assertThat(
                        matcher.matchKeys(
                                type("Cipher"),
                                "create",
                                List.of(type("A"), type("String"), type("B"))))
                .isTrue();
        assertThat(
                        matcher.matchKeys(
                                type("Cipher"),
                                "create",
                                List.of(type("A"), type("int"), type("B"))))
                .isFalse();
    }

    @Test
    void parametersMustMatchInOrderAndWithExactArity() {
        var matcher = new MethodMatcher<Object>("Cipher", "create", List.of("String", "int"));
        assertThat(
                        matcher.matchKeys(
                                type("Cipher"), "create", List.of(type("String"), type("int"))))
                .isTrue();
        assertThat(
                        matcher.matchKeys(
                                type("Cipher"), "create", List.of(type("int"), type("String"))))
                .isFalse();
        assertThat(matcher.matchKeys(type("Cipher"), "create", List.of(type("String")))).isFalse();
        assertThat(
                        matcher.matchKeys(
                                type("Cipher"),
                                "create",
                                List.of(type("String"), type("int"), type("long"))))
                .isFalse();
    }

    @Test
    void distinguishesUnrestrictedParametersFromAnExplicitEmptyList() {
        var unrestricted = new MethodMatcher<Object>(new String[] {"*"}, new String[] {"*"});
        var noArguments = new MethodMatcher<Object>("*", "*", List.of());
        assertThat(unrestricted.matchKeys(type("A"), "m", List.of(type("int")))).isTrue();
        assertThat(unrestricted.matchKeys(type("A"), "m", List.of())).isTrue();
        assertThat(noArguments.matchKeys(type("A"), "m", List.of())).isTrue();
        assertThat(noArguments.matchKeys(type("A"), "m", List.of(type("int")))).isFalse();
    }

    @Test
    void rejectsWildcardsCombinedWithOwnerOrNameAlternatives() {
        for (String[] choices :
                List.of(
                        new String[] {"*", "Cipher"},
                        new String[] {"Cipher", "*"},
                        new String[] {"*", "*"})) {
            assertThatThrownBy(() -> new MethodMatcher<Object>(choices, new String[] {"create"}))
                    .isInstanceOf(IllegalStateException.class);
            assertThatThrownBy(
                            () ->
                                    new MethodMatcher<Object>(
                                            new String[] {"Cipher"}, choices, List.of()))
                    .isInstanceOf(IllegalStateException.class);
        }
    }

    @Test
    void emptyOwnerOrNameAlternativesDoNotMatch() {
        assertThat(
                        new MethodMatcher<Object>(new String[] {}, new String[] {"*"})
                                .matchKeys(type("Cipher"), "create", List.of()))
                .isFalse();
        assertThat(
                        new MethodMatcher<Object>(new String[] {"*"}, new String[] {})
                                .matchKeys(type("Cipher"), "create", List.of()))
                .isFalse();
    }

    @Test
    void preservesSerializableValuesAndParameterSnapshot() {
        var parameters = new ArrayList<>(List.of("String"));
        var matcher =
                new MethodMatcher<Object>(
                        new String[] {"Cipher", "Mac"}, new String[] {"create"}, parameters);
        assertThat(matcher.getInvokedObjectTypeStringsSerializable())
                .containsExactly("Cipher", "Mac");
        assertThat(matcher.getMethodNamesSerializable()).containsExactly("create");
        assertThat(matcher.getParameterTypesSerializable()).containsExactly("String");
        parameters.set(0, "int");
        assertThat(matcher.matchKeys(type("Cipher"), "create", List.of(type("String")))).isTrue();
    }

    @Test
    void subsetMatchingOnlyAppliesToTranslatedConstructors() {
        var matcher = new MethodMatcher<Object>("Cipher", "<init>", List.of("Key", "IV"));
        var translation = translation("<init>", List.of(type("Other"), type("IV")), true);
        assertThat(matcher.match(this, translation, MatchContext.createForHookContext())).isTrue();
        assertThat(matcher.matchKeys(type("Cipher"), "<init>", List.of(type("Other"), type("IV"))))
                .isFalse();
        assertThat(
                        matcher.match(
                                this,
                                translation("<init>", List.of(type("Other")), true),
                                MatchContext.createForHookContext()))
                .isFalse();
        assertThat(
                        matcher.match(
                                this,
                                translation("<init>", List.of(type("IV")), false),
                                MatchContext.createForHookContext()))
                .isFalse();
        var regular = new MethodMatcher<Object>("Cipher", "create", List.of("Key", "IV"));
        assertThat(
                        regular.match(
                                this,
                                translation("create", List.of(type("IV")), true),
                                MatchContext.createForHookContext()))
                .isFalse();
    }

    @Test
    void constructorSubsetWildcardAlsoMatchesAnEmptyFieldList() {
        var matcher = new MethodMatcher<Object>("Cipher", "<init>", List.of("*", "IV"));
        assertThat(
                        matcher.match(
                                this,
                                translation("<init>", List.of(), true),
                                MatchContext.createForHookContext()))
                .isTrue();
    }

    @Test
    void unresolvedOwnerOrMethodNeverMatchesEvenWithWildcards() {
        var matcher = new MethodMatcher<Object>("*", "*", List.of());
        var translation = translation("create", List.of(), false);
        when(translation.getInvokedObjectTypeString(MatchContext.createForHookContext(), this))
                .thenReturn(Optional.empty());
        assertThat(matcher.match(this, translation, MatchContext.createForHookContext())).isFalse();
        translation = translation("create", List.of(), false);
        when(translation.getMethodName(MatchContext.createForHookContext(), this))
                .thenReturn(Optional.empty());
        assertThat(matcher.match(this, translation, MatchContext.createForHookContext())).isFalse();
    }

    @SuppressWarnings("unchecked")
    private ILanguageTranslation<Object> translation(
            String name, List<IType> parameters, boolean subset) {
        ILanguageTranslation<Object> translation = mock(ILanguageTranslation.class);
        var context = MatchContext.createForHookContext();
        when(translation.getInvokedObjectTypeString(context, this))
                .thenReturn(Optional.of(type("Cipher")));
        when(translation.getMethodName(context, this)).thenReturn(Optional.of(name));
        when(translation.getMethodNames(context, this)).thenCallRealMethod();
        when(translation.getMethodParameterTypes(context, this)).thenReturn(parameters);
        when(translation.supportsSubsetParameterMatching()).thenReturn(subset);
        return translation;
    }
}
