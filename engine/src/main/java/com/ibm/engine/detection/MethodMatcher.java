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

import com.ibm.engine.language.ILanguageTranslation;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.function.Function;
import java.util.function.Predicate;
import javax.annotation.Nonnull;
import org.sonarsource.analyzer.commons.collections.SetUtils;

public final class MethodMatcher<T> {
    public static final String ANY = "*";

    @Nonnull private final Predicate<IType> invokedObjectTypeString;
    @Nonnull private final Predicate<String> methodName;
    @Nonnull private final Predicate<List<IType>> parameterTypes;

    /*
     * The following attributes are only used for serializing the MethodMatcher class (see
     * `MethodMatcherSerializer.java`). This is indeed required to then obtain a graph representation
     * of the detection rules. One can access their value through the public getter functions below.
     */
    @Nonnull private final List<String> invokedObjectTypeStringsSerializable;
    @Nonnull private final List<String> methodNamesSerializable;
    @Nonnull private final List<String> parameterTypesSerializable;

    public MethodMatcher(
            @Nonnull String invokedObjectTypeString,
            @Nonnull String methodName,
            @Nonnull List<String> parameterTypes) {

        this.invokedObjectTypeStringsSerializable = List.of(invokedObjectTypeString);
        this.methodNamesSerializable = List.of(methodName);
        this.parameterTypesSerializable = parameterTypes;

        this.invokedObjectTypeString =
                createPredicate(invokedObjectTypeString, (type1 -> (iType -> iType.is(type1))));

        this.methodName = createPredicate(methodName, (methodName1 -> (methodName1::equals)));

        List<Predicate<IType>> types =
                parameterTypes.stream()
                        .<Predicate<IType>>map(
                                parameterType ->
                                        substituteAny(
                                                type -> type.is(parameterType), parameterType))
                        .toList();
        this.parameterTypes =
                (List<IType> actualTypes) -> exactMatchesParameters(types, actualTypes);
    }

    public MethodMatcher(
            @Nonnull String[] invokedObjectTypeStrings,
            @Nonnull String[] methodNames,
            @Nonnull List<String> parameterTypes) {

        this.invokedObjectTypeStringsSerializable = Arrays.asList(invokedObjectTypeStrings);
        this.methodNamesSerializable = Arrays.asList(methodNames);
        this.parameterTypesSerializable = parameterTypes;

        this.invokedObjectTypeString =
                createPredicate(
                        invokedObjectTypeStrings,
                        types -> (type -> types.stream().anyMatch(type::is)));

        this.methodName =
                createPredicate(
                        methodNames, names -> (name -> names.stream().anyMatch(name::equals)));

        List<Predicate<IType>> types =
                parameterTypes.stream()
                        .<Predicate<IType>>map(
                                parameterType ->
                                        substituteAny(
                                                type -> type.is(parameterType), parameterType))
                        .toList();
        this.parameterTypes =
                (List<IType> actualTypes) -> exactMatchesParameters(types, actualTypes);
    }

    public MethodMatcher(
            @Nonnull String[] invokedObjectTypeStrings, @Nonnull String[] methodNames) {

        this.invokedObjectTypeStringsSerializable = Arrays.asList(invokedObjectTypeStrings);
        this.methodNamesSerializable = Arrays.asList(methodNames);
        this.parameterTypesSerializable = List.of();

        this.invokedObjectTypeString =
                createPredicate(
                        invokedObjectTypeStrings,
                        types -> (type -> types.stream().anyMatch(type::is)));

        this.methodName =
                createPredicate(
                        methodNames, names -> (name -> names.stream().anyMatch(name::equals)));
        this.parameterTypes = (List<IType> actualTypes) -> true;
    }

    private static <E> Predicate<E> substituteAny(Predicate<E> predicate, String... elements) {
        if (SetUtils.immutableSetOf(elements).contains(ANY)) {
            if (elements.length > 1) {
                throw new IllegalStateException(
                        "Incompatible MethodMatchers.ANY with other predicates.");
            }
            return e -> true;
        }
        return predicate;
    }

    private static <E> Predicate<E> createPredicate(
            @Nonnull String element,
            @Nonnull Function<String, Predicate<E>> singleElementPredicate) {
        return substituteAny(singleElementPredicate.apply(element), element);
    }

    private static <E> Predicate<E> createPredicate(
            @Nonnull String[] elements,
            @Nonnull Function<List<String>, Predicate<E>> multiElementsPredicate) {
        List<String> multiElements = Arrays.asList(elements);
        return substituteAny(multiElementsPredicate.apply(multiElements), elements);
    }

    private boolean exactMatchesParameters(
            @Nonnull List<Predicate<IType>> expectedTypes, @Nonnull List<IType> actualTypes) {
        return actualTypes.size() == expectedTypes.size()
                && matchesParameters(expectedTypes, actualTypes);
    }

    private boolean matchesParameters(
            @Nonnull List<Predicate<IType>> expectedTypes, @Nonnull List<IType> actualTypes) {
        for (int i = 0; i < expectedTypes.size(); i++) {
            if (!expectedTypes.get(i).test(actualTypes.get(i))) {
                return false;
            }
        }
        return true;
    }

    public boolean match(
            @Nonnull T expression,
            @Nonnull ILanguageTranslation<T> translation,
            @Nonnull MatchContext matchContext) {
        Optional<IType> invokedObjectType =
                translation.getInvokedObjectTypeString(matchContext, expression);
        Optional<String> invokedMethodName = translation.getMethodName(matchContext, expression);
        List<IType> param = translation.getMethodParameterTypes(matchContext, expression);

        if (invokedObjectType.isEmpty() || invokedMethodName.isEmpty()) {
            return false;
        }

        boolean typeMatches = this.invokedObjectTypeString.test(invokedObjectType.get());
        boolean nameMatches = this.methodName.test(invokedMethodName.get());

        if (!typeMatches || !nameMatches) {
            return false;
        }

        // For languages supporting subset parameter matching (e.g., Go composite literals),
        // the rule matches if at least one expected parameter exists in the actual fields.
        if (invokedMethodName.get().equals("<init>")
                && !parameterTypesSerializable.isEmpty()
                && translation.supportsSubsetParameterMatching()) {
            return anyParameterMatches(param);
        }

        return this.parameterTypes.test(param);
    }

    /**
     * Checks that at least one expected parameter type exists in the actual parameter types. This
     * supports named parameter matching (e.g., Go struct field names in composite literals) where
     * the composite literal may only specify a subset of the fields the rule can detect.
     */
    private boolean anyParameterMatches(@Nonnull List<IType> actualTypes) {
        for (String expectedType : parameterTypesSerializable) {
            if (ANY.equals(expectedType)) {
                return true;
            }
            boolean found = actualTypes.stream().anyMatch(actual -> actual.is(expectedType));
            if (found) {
                return true;
            }
        }
        return false;
    }

    @Nonnull
    public List<String> getInvokedObjectTypeStringsSerializable() {
        return this.invokedObjectTypeStringsSerializable;
    }

    @Nonnull
    public List<String> getMethodNamesSerializable() {
        return this.methodNamesSerializable;
    }

    @Nonnull
    public List<String> getParameterTypesSerializable() {
        return this.parameterTypesSerializable;
    }
}
