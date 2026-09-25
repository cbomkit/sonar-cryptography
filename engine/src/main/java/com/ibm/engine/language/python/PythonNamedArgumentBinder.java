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
package com.ibm.engine.language.python;

import com.ibm.engine.detection.IType;
import com.ibm.engine.detection.MethodMatcher;
import com.ibm.engine.language.IArgumentBinder;
import com.ibm.engine.rule.DetectionRule;
import com.ibm.engine.rule.Parameter;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import javax.annotation.Nonnull;
import org.sonar.plugins.python.api.tree.Argument;
import org.sonar.plugins.python.api.tree.CallExpression;
import org.sonar.plugins.python.api.tree.RegularArgument;
import org.sonar.plugins.python.api.tree.Tree;

final class PythonNamedArgumentBinder implements IArgumentBinder<Tree> {

    @Nonnull
    @Override
    public Optional<Map<Integer, Tree>> bind(
            @Nonnull DetectionRule<Tree> rule, @Nonnull Tree call) {
        if (!(call instanceof CallExpression expression)) {
            return Optional.empty();
        }
        List<Argument> arguments = expression.arguments();
        if (arguments.stream().anyMatch(arg -> !(arg instanceof RegularArgument))) {
            return Optional.empty();
        }

        Map<Integer, Tree> bindings = new HashMap<>();
        Set<Integer> usedArguments = new HashSet<>();
        for (Parameter<Tree> parameter : rule.parameters()) {
            int argumentIndex;
            if (parameter.getKeywordName().isPresent()) {
                argumentIndex =
                        findArgumentIndex(
                                parameter.getKeywordName().get(), parameter.getIndex(), arguments);
            } else {
                argumentIndex = parameter.getIndex();
                if (argumentIndex >= arguments.size()
                        || keywordName(arguments.get(argumentIndex)) != null) {
                    return Optional.empty();
                }
            }

            if (argumentIndex < 0 || !usedArguments.add(argumentIndex)) {
                if (parameter.isKeywordOptional()) {
                    continue;
                }
                return Optional.empty();
            }

            Tree argument = ((RegularArgument) arguments.get(argumentIndex)).expression();
            if (!parameter.getParameterType().equals(MethodMatcher.ANY)) {
                Optional<IType> resolvedType = PythonSemantic.resolveTreeType(argument);
                if (resolvedType.isPresent()
                        && !resolvedType.get().is(parameter.getParameterType())) {
                    if (parameter.isKeywordOptional()) {
                        continue;
                    }
                    return Optional.empty();
                }
            }
            bindings.put(parameter.getIndex(), argument);
        }
        return Optional.of(Map.copyOf(bindings));
    }

    @Nonnull
    static Optional<Argument> findArgumentByKeyword(
            @Nonnull String name, int positionalIndex, @Nonnull List<Argument> arguments) {
        int index = findArgumentIndex(name, positionalIndex, arguments);
        return index < 0 ? Optional.empty() : Optional.of(arguments.get(index));
    }

    private static int findArgumentIndex(
            @Nonnull String name, int positionalIndex, @Nonnull List<Argument> arguments) {
        for (int i = 0; i < arguments.size(); i++) {
            if (name.equals(keywordName(arguments.get(i)))) {
                return i;
            }
        }
        if (positionalIndex < arguments.size()
                && arguments.get(positionalIndex) instanceof RegularArgument regularArgument
                && regularArgument.keywordArgument() == null) {
            return positionalIndex;
        }
        return -1;
    }

    private static String keywordName(Argument argument) {
        if (argument instanceof RegularArgument regularArgument
                && regularArgument.keywordArgument() != null) {
            return regularArgument.keywordArgument().name();
        }
        return null;
    }
}
