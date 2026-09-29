/*
 * Sonar Cryptography Plugin
 * Copyright (C) 2026 PQCA
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
 * {@link DetectionRule}.
 *
 * <p>Named parameters are matched by keyword first, falling back to the positional index only when
 * the argument at that index has no keyword of its own, so that a keyword argument is never
 * attributed to the wrong parameter. Positional parameters are matched by index. The call is
 * rejected if it has fewer arguments than there are mandatory parameters (positional + required
 * named), or if a required named parameter cannot be resolved. C# has no semantic type resolution
 * here, so parameter types are not checked.
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

        List<Parameter<CSharpTree>> parameters = rule.parameters();
        long mandatory =
                parameters.stream()
                        .filter(p -> p.getKeywordName().isEmpty() || !p.isKeywordOptional())
                        .count();
        if (arguments.size() < mandatory) {
            return Optional.empty();
        }

        Map<Integer, CSharpTree> bindings = new HashMap<>();
        for (Parameter<CSharpTree> parameter : parameters) {
            Optional<CSharpArgument> argument;
            if (parameter.getKeywordName().isPresent()) {
                argument =
                        findArgumentByKeyword(
                                parameter.getKeywordName().get(), parameter.getIndex(), arguments);
                if (argument.isEmpty() && !parameter.isKeywordOptional()) {
                    return Optional.empty();
                }
            } else if (parameter.getIndex() < arguments.size()) {
                argument = Optional.of(arguments.get(parameter.getIndex()));
            } else {
                argument = Optional.empty();
            }
            argument.ifPresent(arg -> bindings.put(parameter.getIndex(), arg.value()));
        }
        return Optional.of(Map.copyOf(bindings));
    }

    /**
     * Tries to find an argument matching the given keyword name. Falls back to the positional index
     * if no keyword-named argument is found and the argument at that index is itself positional
     * (i.e. has no keyword name).
     */
    @Nonnull
    private static Optional<CSharpArgument> findArgumentByKeyword(
            @Nonnull String keywordName,
            int positionalIndex,
            @Nonnull List<CSharpArgument> arguments) {
        for (CSharpArgument arg : arguments) {
            if (keywordName.equals(arg.name())) {
                return Optional.of(arg);
            }
        }
        if (positionalIndex < arguments.size()) {
            CSharpArgument arg = arguments.get(positionalIndex);
            if (!arg.isNamed()) {
                return Optional.of(arg);
            }
        }
        return Optional.empty();
    }
}
