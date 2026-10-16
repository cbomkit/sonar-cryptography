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
package com.ibm.engine.language.csharp;

import com.ibm.engine.detection.MethodMatcher;
import com.ibm.engine.language.IArgumentBinder;
import com.ibm.engine.language.csharp.tree.CSharpArgument;
import com.ibm.engine.language.csharp.tree.CSharpMethodInvocationTree;
import com.ibm.engine.language.csharp.tree.CSharpObjectCreationTree;
import com.ibm.engine.language.csharp.tree.CSharpTree;
import com.ibm.engine.rule.DetectionRule;
import com.ibm.engine.rule.Parameter;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import javax.annotation.Nonnull;

/**
 * Binds the arguments of a C# method invocation or object creation to the parameters declared by a
 * {@link DetectionRule}, performing the overload resolution that the C# frontend has no semantic
 * model for.
 *
 * <p>A rule that declares any named parameter is built with a {@link MethodMatcher} that carries no
 * parameter type list, so the matcher accepts a call to the method at <em>any</em> arity and all
 * structural matching happens here. That makes this class, not the matcher, responsible for
 * deciding which .NET overload a call site is and therefore which argument belongs to which
 * declared parameter.
 *
 * <h2>Arity</h2>
 *
 * <p>A call is accepted only when its argument count lies in the band {@code [required, declared]},
 * where {@code required} counts the positional and non-optional named parameters. Because C#
 * overloads are distinguished by arity, this is what keeps one rule per overload from also matching
 * a sibling overload: a rule whose parameters are all required matches exactly one arity, so a set
 * of such rules for one method has pairwise disjoint bands and a call can never be detected twice.
 * A call whose arity no rule covers yields no detection at all, which is why each rule set
 * enumerates every overload arity of the methods it covers.
 *
 * <h2>Which argument fills a parameter</h2>
 *
 * <p>Three steps, in order, first match wins:
 *
 * <ol>
 *   <li><b>Keyword.</b> An argument written {@code name: value} fills the parameter declared with
 *       that name, wherever it sits in the call. This is what makes reordered keyword arguments
 *       resolve correctly.
 *   <li><b>Position.</b> The argument at the parameter's index fills it, but only when that
 *       argument carries no keyword of its own and its inferred type is not definitely incompatible
 *       with the declared type. Requiring the slot to be unnamed is what stops a keyword argument
 *       from being attributed to a parameter it was not written for.
 *   <li><b>Type.</b> Failing both, the parameter is filled from the call's arguments by type, but
 *       only when <em>exactly one</em> unnamed argument has a type assignable to the declared type.
 *       Uniqueness is the whole safeguard: it resolves the case of two .NET overloads that share an
 *       arity but order their parameters differently, and declines as soon as the choice would be a
 *       guess.
 * </ol>
 *
 * <p>The call is rejected outright if a required parameter cannot be filled by any of the three. An
 * optional parameter that cannot be filled is simply left unbound, and the rest of the call is
 * still detected.
 *
 * <p>Type comparison uses {@link CSharpTypeInference#isDefinitelyIncompatible}, which is stricter
 * than the predicate behind the matcher: an argument of unknown type still fills a parameter, but a
 * recognized primitive never fills a parameter declared as a known cryptography type, nor the other
 * way round. A parameter declared {@link MethodMatcher#ANY} accepts anything.
 */
final class CSharpNamedArgumentBinder implements IArgumentBinder<CSharpTree> {

    @Nonnull
    @Override
    public Optional<Map<Integer, CSharpTree>> bind(
            @Nonnull DetectionRule<CSharpTree> rule, @Nonnull CSharpTree call) {
        final List<CSharpArgument> arguments;
        if (call instanceof CSharpMethodInvocationTree invocation) {
            arguments = invocation.getArguments();
        } else if (call instanceof CSharpObjectCreationTree creation) {
            arguments = creation.getArguments();
        } else {
            return Optional.empty();
        }

        final List<Parameter<CSharpTree>> parameters = rule.parameters();
        final long required =
                parameters.stream()
                        .filter(p -> p.getKeywordName().isEmpty() || !p.isKeywordOptional())
                        .count();
        if (arguments.size() < required || arguments.size() > parameters.size()) {
            return Optional.empty();
        }

        final Map<Integer, CSharpTree> bindings = new HashMap<>();
        final boolean[] consumed = new boolean[arguments.size()];
        for (Parameter<CSharpTree> parameter : parameters) {
            final int slot = findArgument(parameter, arguments, consumed);
            if (slot < 0) {
                if (isRequired(parameter)) {
                    return Optional.empty();
                }
                continue;
            }
            consumed[slot] = true;
            bindings.put(parameter.getIndex(), arguments.get(slot).value());
        }
        return Optional.of(Map.copyOf(bindings));
    }

    private static boolean isRequired(@Nonnull Parameter<CSharpTree> parameter) {
        return parameter.getKeywordName().isEmpty() || !parameter.isKeywordOptional();
    }

    /**
     * Returns the index of the argument that fills {@code parameter}, or {@code -1} if none does.
     * An argument already taken by an earlier parameter is never offered again, so one argument can
     * never supply two different values.
     */
    private static int findArgument(
            @Nonnull Parameter<CSharpTree> parameter,
            @Nonnull List<CSharpArgument> arguments,
            @Nonnull boolean[] consumed) {
        final String expectedType = parameter.getParameterType();

        final Optional<String> keyword = parameter.getKeywordName();
        if (keyword.isPresent()) {
            for (int i = 0; i < arguments.size(); i++) {
                if (!consumed[i] && keyword.get().equals(arguments.get(i).name())) {
                    return i;
                }
            }
        }

        final int index = parameter.getIndex();
        if (index < arguments.size() && !consumed[index]) {
            CSharpArgument candidate = arguments.get(index);
            if (!candidate.isNamed() && !incompatible(candidate, expectedType)) {
                return index;
            }
        }

        return findUniqueByType(arguments, expectedType, consumed);
    }

    /**
     * Returns the index of the single unclaimed, unnamed argument whose inferred type is assignable
     * to {@code expectedType}, or {@code -1} if there is none or more than one. Arguments of
     * unknown type are not candidates here: allowing them would make "unique" meaningless, since an
     * unknown type is assignable to everything.
     */
    private static int findUniqueByType(
            @Nonnull List<CSharpArgument> arguments,
            @Nonnull String expectedType,
            @Nonnull boolean[] consumed) {
        if (MethodMatcher.ANY.equals(expectedType)) {
            return -1;
        }
        int found = -1;
        for (int i = 0; i < arguments.size(); i++) {
            CSharpArgument argument = arguments.get(i);
            if (consumed[i] || argument.isNamed()) {
                continue;
            }
            String inferred = CSharpTypeInference.infer(argument.value());
            if (inferred == null
                    || !CSharpTypeInference.isDefinitelyAssignable(inferred, expectedType)) {
                continue;
            }
            if (found >= 0) {
                return -1;
            }
            found = i;
        }
        return found;
    }

    private static boolean incompatible(
            @Nonnull CSharpArgument argument, @Nonnull String expectedType) {
        if (MethodMatcher.ANY.equals(expectedType)) {
            return false;
        }
        String inferred = CSharpTypeInference.infer(argument.value());
        return inferred != null
                && CSharpTypeInference.isDefinitelyIncompatible(inferred, expectedType);
    }
}
