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
package com.ibm.plugin.javascript.language;

import com.ibm.engine.detection.IType;
import com.ibm.engine.detection.MatchContext;
import com.ibm.engine.language.ILanguageTranslation;
import com.ibm.plugin.javascript.tree.JavaScriptCallTree;
import com.ibm.plugin.javascript.tree.JavaScriptIdentifierTree;
import com.ibm.plugin.javascript.tree.JavaScriptLiteralTree;
import com.ibm.plugin.javascript.tree.JavaScriptMemberTree;
import com.ibm.plugin.javascript.tree.JavaScriptTree;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import javax.annotation.Nonnull;

/**
 * Extracts method names, receiver types and parameter information from the {@link JavaScriptTree}
 * model.
 *
 * <p>There is no type checker behind the ANTLR parse tree, so the receiver "type" is the receiver
 * text (a module alias such as {@code crypto}, or a variable name), and every argument is accepted
 * for any declared parameter type — an unknown type must never cause a missed detection.
 */
public final class JavaScriptLanguageTranslation implements ILanguageTranslation<JavaScriptTree> {

    @Nonnull
    @Override
    public Optional<String> getMethodName(
            @Nonnull MatchContext matchContext, @Nonnull JavaScriptTree methodInvocation) {
        if (methodInvocation instanceof JavaScriptCallTree call) {
            return Optional.of(call.getMethodName());
        }
        return Optional.empty();
    }

    @Nonnull
    @Override
    public Optional<IType> getInvokedObjectTypeString(
            @Nonnull MatchContext matchContext, @Nonnull JavaScriptTree methodInvocation) {
        if (methodInvocation instanceof JavaScriptCallTree call) {
            String receiver = call.getReceiver();
            return Optional.of(expectedType -> expectedType.equals(receiver));
        }
        return Optional.empty();
    }

    @Nonnull
    @Override
    public Optional<IType> getMethodReturnTypeString(
            @Nonnull MatchContext matchContext, @Nonnull JavaScriptTree methodInvocation) {
        return Optional.empty();
    }

    @Nonnull
    @Override
    public List<IType> getMethodParameterTypes(
            @Nonnull MatchContext matchContext, @Nonnull JavaScriptTree methodInvocation) {
        if (!(methodInvocation instanceof JavaScriptCallTree call)
                || call.getArguments().isEmpty()) {
            return Collections.emptyList();
        }
        List<IType> types = new ArrayList<>(call.getArguments().size());
        for (int i = 0; i < call.getArguments().size(); i++) {
            types.add(expectedType -> true);
        }
        return types;
    }

    @Nonnull
    @Override
    public Optional<String> resolveIdentifierAsString(
            @Nonnull MatchContext matchContext, @Nonnull JavaScriptTree identifierTree) {
        if (identifierTree instanceof JavaScriptLiteralTree literal) {
            return Optional.of(literal.getValue());
        } else if (identifierTree instanceof JavaScriptIdentifierTree identifier) {
            return Optional.of(identifier.getName());
        }
        return Optional.empty();
    }

    @Nonnull
    @Override
    public Optional<String> getEnumIdentifierName(
            @Nonnull MatchContext matchContext, @Nonnull JavaScriptTree enumIdentifier) {
        if (enumIdentifier instanceof JavaScriptMemberTree member) {
            return Optional.of(member.getMemberName());
        } else if (enumIdentifier instanceof JavaScriptIdentifierTree identifier) {
            return Optional.of(identifier.getName());
        }
        return Optional.empty();
    }

    @Nonnull
    @Override
    public Optional<String> getEnumClassName(
            @Nonnull MatchContext matchContext, @Nonnull JavaScriptTree enumClass) {
        if (enumClass instanceof JavaScriptMemberTree member) {
            return Optional.of(member.getQualifier());
        }
        return Optional.empty();
    }
}
