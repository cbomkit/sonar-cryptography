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
package com.ibm.engine.language;

import com.ibm.engine.detection.IType;
import com.ibm.engine.detection.MatchContext;
import java.util.List;
import java.util.Optional;
import javax.annotation.Nonnull;

public interface ILanguageTranslation<T> {
    /**
     * Resolves the name of the method from the provided method invocation/caller.
     *
     * <p>Example:
     *
     * <p>KeyGenerator keyGenerator = KeyGenerator.getInstance #methodInvocationTree (cipher);
     *
     * <p>return: "getInstance"
     *
     * <p>
     *
     * @param methodInvocation to resolve the method name.
     * @return name of the method.
     */
    @Nonnull
    Optional<String> getMethodName(@Nonnull MatchContext matchContext, @Nonnull T methodInvocation);

    /**
     * Returns the invoked object type from a method invocation.
     *
     * @param matchContext provides context the matching procedure
     * @param methodInvocation the method invocation for which to retrieve the invoked object type.
     * @return the invoked object type, or an empty Optional if not available.
     */
    @Nonnull
    Optional<IType> getInvokedObjectTypeString(
            @Nonnull MatchContext matchContext, @Nonnull T methodInvocation);

    /**
     * Returns the return type of the method as String.
     *
     * @param methodInvocation a method invocation
     * @return return type as string
     */
    @Nonnull
    Optional<IType> getMethodReturnTypeString(
            @Nonnull MatchContext matchContext, @Nonnull T methodInvocation);

    /**
     * Returns the Type of each argument of the provided method as String.
     *
     * <p>Example:
     *
     * <p>public static Key generateKey(String cipher, int keySize) { ... }
     *
     * <p>return: ["java.lang.String", "int"]
     *
     * <p>
     *
     * @param methodInvocation a method invocation
     * @return list of argument types as string.
     */
    @Nonnull
    List<IType> getMethodParameterTypes(
            @Nonnull MatchContext matchContext, @Nonnull T methodInvocation);

    /**
     * Resolves the name of the provided Identifier.
     *
     * <p>Example:
     *
     * <p>KeyGenerator keyGenerator = KeyGenerator.getInstance(cipher #identifierTree);
     *
     * <p>return: "cipher"
     *
     * <p>
     *
     * @param identifierTree to resolve name.
     * @return name of the identifier.
     */
    @Nonnull
    Optional<String> resolveIdentifierAsString(
            @Nonnull MatchContext matchContext, @Nonnull T identifierTree);

    /**
     * Returns the enum identifier name.
     *
     * @param matchContext provides context the matching procedure
     * @param enumIdentifier The enum identifier to get the name of.
     * @return an optional string with the enum identifier name.
     */
    @Nonnull
    Optional<String> getEnumIdentifierName(
            @Nonnull MatchContext matchContext, @Nonnull T enumIdentifier);

    /**
     * @param matchContext provides context the matching procedure
     * @param enumClass The class whose name we want to get.
     * @return Returns the name of the enum class in the given context.
     */
    @Nonnull
    Optional<String> getEnumClassName(@Nonnull MatchContext matchContext, @Nonnull T enumClass);

    /**
     * Returns whether constructor parameter matching should use subset logic (i.e., the rule
     * matches if at least one expected parameter type exists in the actual parameters). This is
     * needed for languages like Go where composite literals may specify only a subset of fields.
     *
     * @return true if subset matching should be used for constructors, false for exact matching
     */
    default boolean supportsSubsetParameterMatching() {
        return false;
    }
}
