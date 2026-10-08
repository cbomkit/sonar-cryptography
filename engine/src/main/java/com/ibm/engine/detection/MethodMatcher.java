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
import java.util.Iterator;
import java.util.List;
import javax.annotation.Nonnull;

/** Matches a call signature against the owner, name and argument choices in a detection rule. */
public final class MethodMatcher<T> {
    public static final String ANY = "*";

    private final boolean anyOwner;
    private final boolean anyName;
    private final boolean anyArguments;
    private final String[] argumentSignature;

    // Keep the rule's original values available to MethodMatcherSerializer.
    @Nonnull private final List<String> invokedObjectTypeStringsSerializable;
    @Nonnull private final List<String> methodNamesSerializable;
    @Nonnull private final List<String> parameterTypesSerializable;

    public MethodMatcher(
            @Nonnull String owner, @Nonnull String name, @Nonnull List<String> arguments) {
        this(List.of(owner), List.of(name), arguments, false);
    }

    public MethodMatcher(
            @Nonnull String[] owners, @Nonnull String[] names, @Nonnull List<String> arguments) {
        this(Arrays.asList(owners), Arrays.asList(names), arguments, false);
    }

    public MethodMatcher(@Nonnull String[] owners, @Nonnull String[] names) {
        this(Arrays.asList(owners), Arrays.asList(names), List.of(), true);
    }

    private MethodMatcher(
            List<String> owners, List<String> names, List<String> arguments, boolean anyArguments) {
        anyOwner = acceptsEveryChoice(owners);
        anyName = acceptsEveryChoice(names);
        this.anyArguments = anyArguments;
        argumentSignature = arguments.toArray(String[]::new);
        invokedObjectTypeStringsSerializable = owners;
        methodNamesSerializable = names;
        parameterTypesSerializable = arguments;
    }

    private static boolean acceptsEveryChoice(List<String> choices) {
        for (String choice : choices) {
            if (ANY.equals(choice)) {
                if (choices.size() != 1) {
                    throw new IllegalStateException(
                            "A wildcard must be the only owner or method name choice.");
                }
                return true;
            }
        }
        return false;
    }

    public boolean match(
            @Nonnull T expression,
            @Nonnull ILanguageTranslation<T> translation,
            @Nonnull MatchContext context) {
        var owner = translation.getInvokedObjectTypeString(context, expression);
        var name = translation.getMethodName(context, expression);
        var arguments = translation.getMethodParameterTypes(context, expression);
        return owner.isPresent()
                && name.isPresent()
                && acceptsCall(
                        owner.get(),
                        name.get(),
                        arguments,
                        translation.supportsSubsetParameterMatching());
    }

    /**
     * Matches a detached call, which has an ordered argument list rather than constructor fields.
     */
    public boolean matchKeys(
            @Nonnull IType owner, @Nonnull String name, @Nonnull List<IType> arguments) {
        return acceptsCall(owner, name, arguments, false);
    }

    private boolean acceptsCall(
            IType owner, String name, List<IType> arguments, boolean subsetConstructors) {
        if (!acceptsOwner(owner) || !(anyName || methodNamesSerializable.contains(name))) {
            return false;
        }
        if (subsetConstructors && "<init>".equals(name) && !parameterTypesSerializable.isEmpty()) {
            return acceptsConstructorFields(arguments);
        }
        if (anyArguments) {
            return true;
        }
        if (arguments.size() != argumentSignature.length) {
            return false;
        }
        Iterator<IType> supplied = arguments.iterator();
        for (String expected : argumentSignature) {
            IType actual = supplied.next();
            if (!ANY.equals(expected) && !actual.is(expected)) {
                return false;
            }
        }
        return true;
    }

    private boolean acceptsOwner(IType actual) {
        if (anyOwner) {
            return true;
        }
        for (String candidate : invokedObjectTypeStringsSerializable) {
            if (actual.is(candidate)) {
                return true;
            }
        }
        return false;
    }

    private boolean acceptsConstructorFields(List<IType> supplied) {
        return parameterTypesSerializable.stream()
                .anyMatch(
                        expected ->
                                ANY.equals(expected)
                                        || supplied.stream()
                                                .anyMatch(actual -> actual.is(expected)));
    }

    @Nonnull
    public List<String> getInvokedObjectTypeStringsSerializable() {
        return invokedObjectTypeStringsSerializable;
    }

    @Nonnull
    public List<String> getMethodNamesSerializable() {
        return methodNamesSerializable;
    }

    @Nonnull
    public List<String> getParameterTypesSerializable() {
        return parameterTypesSerializable;
    }
}
