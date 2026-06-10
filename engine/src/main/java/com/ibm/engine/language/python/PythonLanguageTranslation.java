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
import com.ibm.engine.detection.MatchContext;
import com.ibm.engine.language.ILanguageTranslation;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import javax.annotation.Nonnull;
import org.sonar.plugins.python.api.symbols.Symbol;
import org.sonar.plugins.python.api.tree.Argument;
import org.sonar.plugins.python.api.tree.CallExpression;
import org.sonar.plugins.python.api.tree.Name;
import org.sonar.plugins.python.api.tree.QualifiedExpression;
import org.sonar.plugins.python.api.tree.RegularArgument;
import org.sonar.plugins.python.api.tree.Tree;

public class PythonLanguageTranslation implements ILanguageTranslation<Tree> {

    @Nonnull
    @Override
    public Optional<String> getMethodName(
            @Nonnull MatchContext matchContext, @Nonnull Tree methodInvocation) {
        if (methodInvocation instanceof CallExpression callExpression) {
            // We use "name" and not "fullyQualifiedName" to make it like in the Java implementation
            Symbol methodInvocationSymbol = callExpression.calleeSymbol();
            if (methodInvocationSymbol != null) {
                return Optional.of(methodInvocationSymbol.name());
            } else if (callExpression.callee()
                    instanceof Name nameTree) { // Rare case when the symbol is not defined,
                // sometimes for imported classes
                return Optional.of(nameTree.name());
            }
        }
        return Optional.empty();
    }

    @Nonnull
    @Override
    public Optional<IType> getInvokedObjectTypeString(
            @Nonnull MatchContext matchContext, @Nonnull Tree methodInvocation) {
        // This method should return the type of the *invoked object* (or qualifier): for a method
        // invocation `X25519PrivateKey.generate()`, it should return
        // `cryptography.hazmat.primitives.asymmetric.X25519PrivateKey`, and for
        // `global_var.bit_count()`, it should return the type of `global_var`.
        if (methodInvocation instanceof CallExpression callExpression) {
            // We will call `resolveTreeType`, that will return an IType accepting the function name
            // "type" (like `cryptography.hazmat.primitives.asymmetric.dsa.DSAPublicNumbers`) as
            // well as the "invoked object type" (`cryptography.hazmat.primitives.asymmetric.dsa`)
            // used in the rule's `forObjectTypes`
            if (callExpression.callee() instanceof QualifiedExpression qualifiedExpression) {
                return PythonSemantic.resolveTreeType(qualifiedExpression.name());
            } else if (callExpression.callee() instanceof Name functionName) {
                return PythonSemantic.resolveTreeType(functionName);
            }
        }
        return Optional.empty();
    }

    @Override
    public @Nonnull Optional<IType> getMethodReturnTypeString(
            @Nonnull MatchContext matchContext, @Nonnull Tree methodInvocation) {
        // TODO: This does not take the subscriptionIndex into account, so it will return an IType
        // accepting the type of all
        return PythonSemantic.resolveTreeType(methodInvocation);
    }

    @Override
    public @Nonnull List<IType> getMethodParameterTypes(
            @Nonnull MatchContext matchContext, @Nonnull Tree methodInvocation) {
        if (methodInvocation instanceof CallExpression callExpression) {
            List<Argument> arguments = callExpression.arguments();
            if (!arguments.isEmpty()) {
                // Count ALL argument types including *args and **kwargs to prevent false matches
                // when rules specify .withoutParameters()
                return arguments.stream()
                        .<Optional<IType>>map(
                                argument -> {
                                    if (argument instanceof RegularArgument regularArg) {
                                        return PythonSemantic.resolveTreeType(
                                                regularArg.expression());
                                    } else {
                                        // For non-regular arguments (*args, **kwargs), return a
                                        // placeholder type
                                        // that will never match any specific type in detection
                                        // rules.
                                        // This ensures they are counted as parameters without
                                        // matching wildcards.
                                        return Optional.<IType>of(
                                                new IType() {
                                                    @Override
                                                    public boolean is(@Nonnull String type) {
                                                        // Use unique markers that won't conflict
                                                        // with actual types or wildcards
                                                        return type.equals("__PYTHON_VARARGS__")
                                                                || type.equals("__PYTHON_KWARGS__");
                                                    }
                                                });
                                    }
                                })
                        .filter(Optional::isPresent)
                        .map(Optional::get)
                        .toList();
            }
        }
        return Collections.emptyList();
    }

    @Override
    public @Nonnull Optional<String> resolveIdentifierAsString(
            @Nonnull MatchContext matchContext, @Nonnull Tree name) {
        if (name instanceof Name nameTree) {
            return Optional.of(nameTree.name());
        }
        return Optional.empty();
    }

    @Override
    public @Nonnull Optional<String> getEnumIdentifierName(
            @Nonnull MatchContext matchContext, @Nonnull Tree enumIdentifier) {
        // TODO: Implement enums in the Python case?
        return Optional.empty();
    }

    @Override
    public @Nonnull Optional<String> getEnumClassName(
            @Nonnull MatchContext matchContext, @Nonnull Tree enumClass) {
        // TODO: Implement enums in the Python case?
        return Optional.empty();
    }
}
