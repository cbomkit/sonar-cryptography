/*
 * Sonar Cryptography Plugin
 * Copyright (C) 2025 PQCA
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
package com.ibm.engine.language.cpp;

import com.ibm.engine.detection.IType;
import com.ibm.engine.detection.MatchContext;
import com.ibm.engine.language.ILanguageTranslation;
import com.ibm.engine.language.cpp.tree.CppIdentifierTree;
import com.ibm.engine.language.cpp.tree.CppLiteralTree;
import com.ibm.engine.language.cpp.tree.CppMemberAccessTree;
import com.ibm.engine.language.cpp.tree.CppMethodInvocationTree;
import com.ibm.engine.language.cpp.tree.CppTree;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import javax.annotation.Nonnull;

/**
 * Language translation implementation for C/C++.
 *
 * <p>Mirrors {@link com.ibm.engine.language.csharp.CSharpLanguageTranslation}: extracts method
 * names, object type strings, and parameter information from the {@link CppTree} hierarchy produced
 * by the ANTLR4-based tree converter.
 *
 * <p>Since ANTLR4 provides only syntactic information (no full C/C++ type inference), all parameter
 * types are treated as matching any expected type. Object type matching is string-based: the engine
 * matches the inferred type name (e.g. {@code "EVP_CIPHER_CTX"}) against the type strings declared
 * in detection rules.
 *
 * <p>For C/C++ there are no constructors in the Java/C# sense — all initialization goes through
 * function calls like {@code EVP_CIPHER_CTX_new()} — so {@code forConstructor()} is not used.
 * The {@code "<init>"} sentinel is therefore never returned here.
 */
public final class CppLanguageTranslation implements ILanguageTranslation<CppTree> {

    @Nonnull
    @Override
    public Optional<String> getMethodName(
            @Nonnull MatchContext matchContext, @Nonnull CppTree methodInvocation) {
        if (methodInvocation instanceof CppMethodInvocationTree invocation) {
            return Optional.of(invocation.methodName());
        }
        return Optional.empty();
    }

    @Nonnull
    @Override
    public Optional<IType> getInvokedObjectTypeString(
            @Nonnull MatchContext matchContext, @Nonnull CppTree methodInvocation) {
        if (methodInvocation instanceof CppMethodInvocationTree invocation) {
            String typeName = invocation.objectType();
            if (typeName == null) {
                // No inferred object type — match any type to avoid blocking detection
                return Optional.of(expectedType -> true);
            }
            return Optional.of(expectedType -> expectedType.equals(typeName));
        }
        return Optional.empty();
    }

    @Nonnull
    @Override
    public Optional<IType> getMethodReturnTypeString(
            @Nonnull MatchContext matchContext, @Nonnull CppTree methodInvocation) {
        // ANTLR4 provides no type inference; return type unavailable
        return Optional.empty();
    }

    @Nonnull
    @Override
    public List<IType> getMethodParameterTypes(
            @Nonnull MatchContext matchContext, @Nonnull CppTree methodInvocation) {
        if (!(methodInvocation instanceof CppMethodInvocationTree invocation)) {
            return Collections.emptyList();
        }
        List<CppTree> args = invocation.arguments();
        if (args.isEmpty()) {
            return Collections.emptyList();
        }
        // No semantic type info available from ANTLR4 — every argument matches any expected type
        List<IType> types = new ArrayList<>(args.size());
        for (int i = 0; i < args.size(); i++) {
            types.add(expectedType -> true);
        }
        return types;
    }

    @Nonnull
    @Override
    public Optional<String> resolveIdentifierAsString(
            @Nonnull MatchContext matchContext, @Nonnull CppTree identifierTree) {
        if (identifierTree instanceof CppLiteralTree literal) {
            // Return the unquoted value so string literals like "AES-256-CBC"
            // are resolved as AES-256-CBC (without surrounding quotes)
            return Optional.of(literal.unquotedValue());
        } else if (identifierTree instanceof CppIdentifierTree identifier) {
            return Optional.of(identifier.name());
        }
        return Optional.empty();
    }

    @Nonnull
    @Override
    public Optional<String> getEnumIdentifierName(
            @Nonnull MatchContext matchContext, @Nonnull CppTree enumIdentifier) {
        // C has no enum member-access syntax like C# (CipherMode.CBC).
        // Enum constants appear as plain identifiers (EVP_CIPH_CBC_MODE)
        // or as member accesses on a struct (params->mode).
        if (enumIdentifier instanceof CppMemberAccessTree memberAccess) {
            return Optional.of(memberAccess.memberName());
        } else if (enumIdentifier instanceof CppIdentifierTree identifier) {
            return Optional.of(identifier.name());
        }
        return Optional.empty();
    }

    @Nonnull
    @Override
    public Optional<String> getEnumClassName(
            @Nonnull MatchContext matchContext, @Nonnull CppTree enumClass) {
        // C does not have qualified enum syntax like C#.
        // Member access object side is returned as a best-effort "class" name.
        if (enumClass instanceof CppMemberAccessTree memberAccess) {
            CppTree object = memberAccess.object();
            if (object instanceof CppIdentifierTree identifier) {
                return Optional.of(identifier.name());
            }
        }
        return Optional.empty();
    }
}
