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
package com.ibm.plugin.javascript.tree;

import java.util.List;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;

/**
 * A call ({@code crypto.createHash("sha256")}) or construction ({@code new Foo()}).
 *
 * <p>Call chains are desugared by the converter: {@code a.b().c().d()} becomes three calls in
 * source order where {@code c} has the receiver name that {@code b}'s result is {@linkplain
 * #getAssignedIdentifier() assigned to}. That is what lets the engine's dependent-rule traversal
 * follow {@code update}/{@code digest} after {@code createHash} for both the sequential and the
 * inline form.
 */
public final class JavaScriptCallTree implements JavaScriptTree {

    private final int line;
    private final int column;
    @Nonnull private final String receiver;
    @Nonnull private final String methodName;
    @Nonnull private final List<JavaScriptTree> arguments;
    private final boolean construction;
    @Nullable private final String assignedIdentifier;
    @Nullable private final JavaScriptScope scope;
    @Nullable private JavaScriptBlockTree enclosingBlock;

    public JavaScriptCallTree(
            int line,
            int column,
            @Nonnull String receiver,
            @Nonnull String methodName,
            @Nonnull List<JavaScriptTree> arguments,
            boolean construction,
            @Nullable String assignedIdentifier,
            @Nullable JavaScriptScope scope) {
        this.line = line;
        this.column = column;
        this.receiver = receiver;
        this.methodName = methodName;
        this.arguments = arguments;
        this.construction = construction;
        this.assignedIdentifier = assignedIdentifier;
        this.scope = scope;
    }

    @Override
    public int getLine() {
        return line;
    }

    @Override
    public int getColumn() {
        return column;
    }

    @Nonnull
    @Override
    public String getText() {
        return (receiver.isEmpty() ? "" : receiver + ".") + methodName + "(...)";
    }

    @Nullable @Override
    public JavaScriptScope getScope() {
        return scope;
    }

    /** The receiver text before the dot: a variable, a module alias ({@code crypto}) or empty. */
    @Nonnull
    public String getReceiver() {
        return receiver;
    }

    @Nonnull
    public String getMethodName() {
        return methodName;
    }

    @Nonnull
    public List<JavaScriptTree> getArguments() {
        return arguments;
    }

    public boolean isConstruction() {
        return construction;
    }

    @Nullable public String getAssignedIdentifier() {
        return assignedIdentifier;
    }

    @Nullable public JavaScriptBlockTree getEnclosingBlock() {
        return enclosingBlock;
    }

    void setEnclosingBlock(@Nonnull JavaScriptBlockTree enclosingBlock) {
        this.enclosingBlock = enclosingBlock;
    }
}
