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
package com.ibm.engine.language.c;

import com.ibm.engine.detection.IType;
import com.ibm.engine.detection.MatchContext;
import com.ibm.engine.language.ILanguageTranslation;
import com.ibm.engine.language.c.tree.CFunctionCallTree;
import com.ibm.engine.language.c.tree.CIdentifierTree;
import com.ibm.engine.language.c.tree.CLiteralTree;
import com.ibm.engine.language.c.tree.CTree;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import javax.annotation.Nonnull;

/**
 * Language translation implementation for C/C++.
 *
 * <p>Extracts function names, object type strings, and parameter information from the CTree
 * hierarchy. Since C/C++ parsing provides only syntactic information (no type inference), all
 * parameter types match any expected type.
 */
public final class CLanguageTranslation implements ILanguageTranslation<CTree> {

    @Nonnull
    @Override
    public Optional<String> getMethodName(
            @Nonnull MatchContext matchContext, @Nonnull CTree methodInvocation) {
        if (methodInvocation instanceof CFunctionCallTree call) {
            return Optional.of(call.getFunctionName());
        }
        return Optional.empty();
    }

    @Nonnull
    @Override
    public Optional<IType> getInvokedObjectTypeString(
            @Nonnull MatchContext matchContext, @Nonnull CTree methodInvocation) {
        if (methodInvocation instanceof CFunctionCallTree call) {
            String typeName = call.getObjectTypeName();
            return Optional.of(expectedType -> expectedType.equals(typeName));
        }
        return Optional.empty();
    }

    @Nonnull
    @Override
    public Optional<IType> getMethodReturnTypeString(
            @Nonnull MatchContext matchContext, @Nonnull CTree methodInvocation) {
        return Optional.empty();
    }

    @Nonnull
    @Override
    public List<IType> getMethodParameterTypes(
            @Nonnull MatchContext matchContext, @Nonnull CTree methodInvocation) {
        List<CTree> args = null;
        if (methodInvocation instanceof CFunctionCallTree call) {
            args = call.getArguments();
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
            @Nonnull MatchContext matchContext, @Nonnull CTree identifierTree) {
        if (identifierTree instanceof CLiteralTree literal) {
            return Optional.of(literal.getValue());
        } else if (identifierTree instanceof CIdentifierTree identifier) {
            return Optional.of(identifier.getName());
        }
        return Optional.empty();
    }

    @Nonnull
    @Override
    public Optional<String> getEnumIdentifierName(
            @Nonnull MatchContext matchContext, @Nonnull CTree enumIdentifier) {
        if (enumIdentifier instanceof CIdentifierTree identifier) {
            return Optional.of(identifier.getName());
        } else if (enumIdentifier instanceof CLiteralTree literal) {
            return Optional.of(literal.getValue());
        }
        return Optional.empty();
    }

    @Nonnull
    @Override
    public Optional<String> getEnumClassName(
            @Nonnull MatchContext matchContext, @Nonnull CTree enumClass) {
        // C does not have enum classes in the OOP sense
        return Optional.empty();
    }
}
