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

import com.ibm.engine.model.factory.IValueFactory;
import com.ibm.engine.rule.Parameter;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import java.util.Optional;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;

public interface IDetectionEngine<T, S> {
    /**
     * Runs the IDetectionEngine on a given tree.
     *
     * @param tree The tree to be analyzed.
     */
    void run(@Nonnull T tree);

    /**
     * Runs the detection engine on a given tree.
     *
     * @param traceSymbol The tracing symbol to be used during execution.
     * @param tree The tree on which the detection engine should be run.
     */
    void run(@Nonnull TraceSymbol<S> traceSymbol, @Nonnull T tree);

    /**
     * This function will resolve a specific parameter of a method definition, by extracting
     * the corresponding argument from the method invocation with the actual value instantiation.
     * <p>
     * Example:
     * <pre>
     * {@code Key newKey = generateKey("RSA", 2048);
     *
     * public static Key generateKey(String cipher, int keySize) {
     *     ...
     * }
     * }
     * <li>methodDefinition: <pre>{@code generateKey(String cipher, int keySize)}</li>
     * <li>methodInvocation: <pre>{@code generateKey("RSA", 2048)}</li>
     * <li>methodParameterIdentifier: <pre>{@code cipher}</li>
     * <li>return: <pre>{@code RSA}</li>
     *
     * @param methodDefinition the method definition
     * @param methodInvocation the tree which calls a defined method with the actual parameter values
     * @param methodParameterIdentifier the specific parameter of the method, that should be resolved
     * @return identifier of the method-call-argument that is related to the specified method parameter identifier
     * and the index for the parameter
     */
    @Nullable T extractArgumentFromMethodCaller(
            @Nonnull T methodDefinition,
            @Nonnull T methodInvocation,
            @Nonnull T methodParameterIdentifier);

    /**
     * This method will take any kind of expression tree and tries to resolve the constant values of
     * this expression. The values will then be cast to the defined clazz.
     *
     * @param clazz the class to which the discovered values should be cast to.
     * @param expression any expression tree for which the values should be resolved.
     * @return a list of ResolvedValues.
     */
    @Nonnull
    <O> List<ResolvedValue<O, T>> resolveValuesInInnerScope(
            @Nonnull Class<O> clazz,
            @Nonnull T expression,
            @Nullable IValueFactory<T> valueFactory);

    /**
     * Resolves an expression from a method definition in the context of a specific method call. The
     * default implementation returns no values; languages with explicit call-argument mapping can
     * override it.
     */
    @Nonnull
    default <O> List<ResolvedValue<O, T>> resolveValuesInInnerScope(
            @Nonnull Class<O> clazz,
            @Nonnull T methodDefinition,
            @Nonnull T methodInvocation,
            @Nonnull T expression,
            @Nullable IValueFactory<T> valueFactory) {
        return Collections.emptyList();
    }

    /**
     * Resolves values in the outer scope for a given expression and parameter.
     *
     * @param expression The expression to resolve the values in the outer scope for.
     * @param parameter The parameter to detect the value from.
     */
    void resolveValuesInOuterScope(@Nonnull T expression, @Nonnull Parameter<T> parameter);

    /**
     * Resolve the return value of a method based on its definition.
     *
     * @param clazz The class to which the return value should be cast to.
     * @param methodDefinition The method definition that needs to be resolved.
     */
    <O> void resolveMethodReturnValues(
            @Nonnull Class<O> clazz, @Nonnull T methodDefinition, @Nonnull Parameter<T> parameter);

    /**
     * Provided with an enum definition and a list of possible selections on an enum value (like
     * member-select "ENUM.member1" or method-invocation "ENUM.member2.getName()"), this method
     * tries to resolve a constant value related to the selection on the enum-class. If a value is
     * found, the value will be cast to the provided clazz.
     *
     * @param clazz to which the resolved value will be cast to.
     * @param enumClassDefinition a enum class definition.
     * @param selections a list of selection on the enum class (method-invocation and/or
     *     member-select).
     * @return the resolved value of the enum.
     * @param <O> generic parameter.
     */
    @Nullable <O> ResolvedValue<O, T> resolveEnumValue(
            @Nonnull Class<O> clazz,
            @Nonnull T enumClassDefinition,
            @Nonnull LinkedList<T> selections);

    /**
     * Returns an assigned symbol, if any, for the given expression. Returns null otherwise.
     *
     * @param expression the expression.
     * @return The assigned symbol, if any, or an empty optional otherwise.
     */
    @Nonnull
    Optional<TraceSymbol<S>> getAssignedSymbol(@Nonnull T expression);

    /**
     * Returns the related symbol for the detectionParameter of a given expression.
     *
     * <p>Example
     *
     * <pre>
     * {@code Cipher c = Cipher.getInstance("AES");}
     *
     * </pre>
     *
     * @param methodInvocation the method invocation tree.
     * @param parameter the method parameter to get the symbol from.
     * @return The assigned symbol, if any, or an empty optional otherwise.
     */
    @Nonnull
    Optional<TraceSymbol<S>> getMethodInvocationParameterSymbol(
            @Nonnull T methodInvocation, @Nonnull Parameter<T> parameter);

    /**
     * Returns the symbol representing the given parameter from an init/constructor call, if any.
     *
     * @param newClass the new class expression (init) which contains the parameter, not null
     * @param parameter the parameter to retrieve the symbol for, not null
     * @return the symbol representing the given parameter, or an empty optional if none exists
     */
    @Nonnull
    Optional<TraceSymbol<S>> getNewClassParameterSymbol(
            @Nonnull T newClass, @Nonnull Parameter<T> parameter);

    /**
     * Checks if the given method invocation is on a variable.
     *
     * @param methodInvocation The method invocation to check.
     * @param variableSymbol The variable symbol to check against.
     * @return True if the method invocation is on a variable, false otherwise.
     */
    boolean isInvocationOnVariable(T methodInvocation, @Nonnull TraceSymbol<S> variableSymbol);

    /**
     * Checks if the newClass can be initialized for the variable symbol.
     *
     * @param newClass The new class to be used for initialization.
     * @param variableSymbol The variable symbol that needs to be initialized.
     * @return Returns true if the newClass can be initialized for the variable symbol, false
     *     otherwise.
     */
    boolean isInitForVariable(T newClass, @Nonnull TraceSymbol<S> variableSymbol);
}
