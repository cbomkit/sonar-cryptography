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
package com.ibm.plugin.javascript.api;

import java.util.List;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;

/** Function or method call expression. */
public final class CallExpressionTree implements Tree, HasLocation {

    @Nonnull private final String methodName;
    @Nonnull private final String objectType;
    @Nonnull private final List<Tree> arguments;
    @Nonnull private final SourceLocation location;
    @Nullable private final String resultType;
    @Nullable private final JavaScriptSymbol assignedSymbol;

    public CallExpressionTree(
            @Nonnull String methodName,
            @Nonnull String objectType,
            @Nonnull List<Tree> arguments,
            @Nonnull SourceLocation location,
            @Nullable String resultType,
            @Nullable JavaScriptSymbol assignedSymbol) {
        this.methodName = methodName;
        this.objectType = objectType;
        this.arguments = List.copyOf(arguments);
        this.location = location;
        this.resultType = resultType;
        this.assignedSymbol = assignedSymbol;
    }

    @Nonnull
    public String methodName() {
        return methodName;
    }

    @Nonnull
    public String objectType() {
        return objectType;
    }

    @Nonnull
    public List<Tree> arguments() {
        return arguments;
    }

    @Nullable public String resultType() {
        return resultType;
    }

    @Nullable public JavaScriptSymbol assignedSymbol() {
        return assignedSymbol;
    }

    @Nonnull
    @Override
    public SourceLocation location() {
        return location;
    }
}
