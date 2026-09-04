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
package com.ibm.plugin.bridge;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.ibm.plugin.bridge.model.EslintAnalysisResult;
import com.ibm.plugin.bridge.model.EslintArgument;
import com.ibm.plugin.bridge.model.EslintCallExpression;
import com.ibm.plugin.bridge.model.EslintFileResult;
import com.ibm.plugin.javascript.api.BlockTree;
import com.ibm.plugin.javascript.api.CallExpressionTree;
import com.ibm.plugin.javascript.api.CallExpressionWithBlockTree;
import com.ibm.plugin.javascript.api.IdentifierTree;
import com.ibm.plugin.javascript.api.JavaScriptSymbol;
import com.ibm.plugin.javascript.api.LiteralTree;
import com.ibm.plugin.javascript.api.MemberExpressionTree;
import com.ibm.plugin.javascript.api.NewExpressionTree;
import com.ibm.plugin.javascript.api.SourceLocation;
import com.ibm.plugin.javascript.api.Tree;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;

/** Parses JSON output from the ESLint runner into JavaScript {@link Tree} nodes. */
public final class ESLintResultParser {

    @Nonnull private static final ObjectMapper MAPPER = new ObjectMapper();

    private ESLintResultParser() {
        // utility
    }

    @Nonnull
    public static EslintAnalysisResult parseJson(@Nonnull String json) throws IOException {
        return MAPPER.readValue(json, EslintAnalysisResult.class);
    }

    @Nonnull
    public static BlockTree toBlockTree(@Nonnull EslintFileResult fileResult) {
        Map<String, String> bindings =
                fileResult.bindings == null ? Collections.emptyMap() : fileResult.bindings;
        Map<String, String> variableValues =
                fileResult.variableValues == null
                        ? Collections.emptyMap()
                        : fileResult.variableValues;
        if (fileResult.calls == null || fileResult.calls.isEmpty()) {
            return new BlockTree(Collections.emptyList(), bindings, variableValues);
        }
        List<Tree> statements = new ArrayList<>();
        BlockTree blockTree = new BlockTree(Collections.emptyList(), bindings, variableValues);
        for (EslintCallExpression call : fileResult.calls) {
            Tree tree = toTree(call, bindings, blockTree);
            if (tree != null) {
                statements.add(tree);
            }
        }
        return new BlockTree(statements, bindings, variableValues);
    }

    @Nullable private static Tree toTree(
            @Nonnull EslintCallExpression call,
            @Nonnull Map<String, String> bindings,
            @Nonnull BlockTree blockTree) {
        SourceLocation location = SourceLocation.of(call.line, call.column);
        List<Tree> arguments = toArguments(call.arguments, bindings);
        JavaScriptSymbol assignedSymbol =
                call.variableName == null || call.variableName.isBlank()
                        ? null
                        : new JavaScriptSymbol(call.variableName, call.resultType);

        if ("new".equalsIgnoreCase(call.kind)) {
            return new NewExpressionTree(
                    call.objectType == null ? "unknown" : call.objectType, arguments, location);
        }

        CallExpressionTree callTree =
                new CallExpressionTree(
                        call.methodName == null ? "" : call.methodName,
                        call.objectType == null ? "unknown" : call.objectType,
                        arguments,
                        location,
                        call.resultType,
                        assignedSymbol);
        if (assignedSymbol != null) {
            IdentifierTree identifier =
                    new IdentifierTree(assignedSymbol.name(), call.resultType, location);
            return new CallExpressionWithBlockTree(callTree, List.of(identifier), blockTree);
        }
        return callTree;
    }

    @Nonnull
    private static List<Tree> toArguments(
            @Nullable List<EslintArgument> arguments, @Nonnull Map<String, String> bindings) {
        if (arguments == null || arguments.isEmpty()) {
            return Collections.emptyList();
        }
        List<Tree> result = new ArrayList<>();
        for (EslintArgument argument : arguments) {
            Tree tree = toArgumentTree(argument, bindings);
            if (tree != null) {
                result.add(tree);
            }
        }
        return result;
    }

    @Nullable private static Tree toArgumentTree(
            @Nonnull EslintArgument argument, @Nonnull Map<String, String> bindings) {
        SourceLocation location = SourceLocation.of(argument.line, argument.column);
        if ("literal".equalsIgnoreCase(argument.kind)) {
            return new LiteralTree(
                    argument.value == null ? "" : argument.value,
                    argument.type == null ? "string" : argument.type,
                    location);
        }
        if ("identifier".equalsIgnoreCase(argument.kind)) {
            String resolved = bindings.getOrDefault(argument.value, null);
            return new IdentifierTree(
                    argument.value == null ? "" : argument.value, resolved, location);
        }
        if ("member".equalsIgnoreCase(argument.kind)) {
            return new MemberExpressionTree(
                    argument.objectType == null ? "unknown" : argument.objectType,
                    argument.methodName == null ? "" : argument.methodName,
                    location);
        }
        if ("call".equalsIgnoreCase(argument.kind)) {
            return new CallExpressionTree(
                    argument.methodName == null ? "" : argument.methodName,
                    argument.objectType == null ? "unknown" : argument.objectType,
                    Collections.emptyList(),
                    location,
                    argument.resultType,
                    null);
        }
        return new LiteralTree("", argument.type == null ? "any" : argument.type, location);
    }
}
