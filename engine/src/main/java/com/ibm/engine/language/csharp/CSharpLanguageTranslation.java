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

import com.ibm.engine.detection.IType;
import com.ibm.engine.detection.MatchContext;
import com.ibm.engine.language.ILanguageTranslation;
import com.ibm.engine.language.csharp.tree.CSharpIdentifierTree;
import com.ibm.engine.language.csharp.tree.CSharpLiteralTree;
import com.ibm.engine.language.csharp.tree.CSharpMemberAccessTree;
import com.ibm.engine.language.csharp.tree.CSharpMethodInvocationTree;
import com.ibm.engine.language.csharp.tree.CSharpObjectCreationTree;
import com.ibm.engine.language.csharp.tree.CSharpTree;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import javax.annotation.Nonnull;

/**
 * Language translation implementation for C#.
 *
 * <p>Extracts method names, object type strings, and parameter information from the CSharpTree
 * hierarchy produced by the ANTLR4-based tree converter. Since ANTLR4 provides only syntactic
 * information (no type inference), all parameter types match any expected type.
 */
public final class CSharpLanguageTranslation implements ILanguageTranslation<CSharpTree> {

    @Nonnull
    @Override
    public Optional<String> getMethodName(
            @Nonnull MatchContext matchContext, @Nonnull CSharpTree methodInvocation) {
        if (methodInvocation instanceof CSharpMethodInvocationTree invocation) {
            return Optional.of(invocation.getMethodName());
        } else if (methodInvocation instanceof CSharpObjectCreationTree) {
            // Constructor calls map to the "<init>" sentinel used throughout the engine
            return Optional.of("<init>");
        }
        return Optional.empty();
    }

    @Nonnull
    @Override
    public Optional<IType> getInvokedObjectTypeString(
            @Nonnull MatchContext matchContext, @Nonnull CSharpTree methodInvocation) {
        if (methodInvocation instanceof CSharpMethodInvocationTree invocation) {
            String typeName = invocation.getObjectTypeName();
            return Optional.of(expectedType -> expectedType.equals(typeName));
        } else if (methodInvocation instanceof CSharpObjectCreationTree creation) {
            String typeName = creation.getTypeName();
            return Optional.of(expectedType -> expectedType.equals(typeName));
        }
        return Optional.empty();
    }

    @Nonnull
    @Override
    public Optional<IType> getMethodReturnTypeString(
            @Nonnull MatchContext matchContext, @Nonnull CSharpTree methodInvocation) {
        // ANTLR4 provides no type inference; return type unavailable
        return Optional.empty();
    }

    @Nonnull
    @Override
    public List<IType> getMethodParameterTypes(
            @Nonnull MatchContext matchContext, @Nonnull CSharpTree methodInvocation) {
        List<CSharpTree> args = null;
        if (methodInvocation instanceof CSharpMethodInvocationTree invocation) {
            args = invocation.getArguments();
        } else if (methodInvocation instanceof CSharpObjectCreationTree creation) {
            args = creation.getArguments();
        }
        if (args == null || args.isEmpty()) {
            return Collections.emptyList();
        }
        // No semantic type info; every argument matches any expected type
        List<IType> types = new ArrayList<>(args.size());
        for (int i = 0; i < args.size(); i++) {
            types.add(expectedType -> true);
        }
        return types;
    }

    @Nonnull
    @Override
    public Optional<String> resolveIdentifierAsString(
            @Nonnull MatchContext matchContext, @Nonnull CSharpTree identifierTree) {
        if (identifierTree instanceof CSharpLiteralTree literal) {
            return Optional.of(literal.getValue());
        } else if (identifierTree instanceof CSharpIdentifierTree identifier) {
            return Optional.of(identifier.getName());
        }
        return Optional.empty();
    }

    @Nonnull
    @Override
    public Optional<String> getEnumIdentifierName(
            @Nonnull MatchContext matchContext, @Nonnull CSharpTree enumIdentifier) {
        if (enumIdentifier instanceof CSharpMemberAccessTree memberAccess) {
            // e.g. CipherMode.CBC  →  "CBC"
            return Optional.of(memberAccess.getMemberName());
        } else if (enumIdentifier instanceof CSharpIdentifierTree identifier) {
            return Optional.of(identifier.getName());
        }
        return Optional.empty();
    }

    @Nonnull
    @Override
    public Optional<String> getEnumClassName(
            @Nonnull MatchContext matchContext, @Nonnull CSharpTree enumClass) {
        if (enumClass instanceof CSharpMemberAccessTree memberAccess) {
            // e.g. CipherMode.CBC  →  "CipherMode"
            return Optional.of(memberAccess.getTypeName());
        }
        return Optional.empty();
    }
}
