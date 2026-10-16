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
package com.ibm.engine.language.csharp.tree;

import java.util.List;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;

/**
 * Represents a C# method invocation expression such as {@code Aes.Create()} or {@code
 * RSA.Create(2048)}.
 *
 * <p>The {@code objectTypeName} is the simple class/package name before the dot (e.g. {@code
 * "Aes"}, {@code "SHA256"}), and {@code methodName} is the method name (e.g. {@code "Create"}).
 *
 * <p>For chained calls, only the outermost method invocation is captured. A nested invocation used
 * as an argument (e.g. {@code new CFBBlockCipher(AESEngine.newInstance(), 256)}) is now a real
 * {@code CSharpMethodInvocationTree} in its own right (see {@code CSharpTreeConverter}), not
 * collapsed into a member-access leaf as in earlier versions.
 */
public final class CSharpMethodInvocationTree implements CSharpTree {

    private final int line;
    private final int column;

    /** The type/receiver name before the dot (e.g. "Aes", "RSA", "HashAlgorithm"). */
    @Nonnull private final String objectTypeName;

    /** The method name (e.g. "Create", "init"). */
    @Nonnull private final String methodName;

    /** The argument trees in call order. */
    @Nonnull private final List<CSharpArgument> arguments;

    /** Optional identifier this invocation result is assigned to (for depending rule tracking). */
    @Nullable private final String assignedIdentifier;

    /**
     * The enclosing block tree (for depending rule context), when this is a top-level statement.
     */
    @Nullable private CSharpBlockTree enclosingBlock;

    /** The lexical scope this invocation was created in — used to resolve its own arguments. */
    @Nullable private final CSharpScope scope;

    /**
     * The expression this call returns, when it targets a method of the same file that has exactly
     * one return value. Back-patched by {@code CSharpTreeConverter} after the whole file has been
     * converted, because the called method may be declared after the call.
     */
    @Nullable private CSharpTree resolvedReturnValue;

    public CSharpMethodInvocationTree(
            int line,
            int column,
            @Nonnull String objectTypeName,
            @Nonnull String methodName,
            @Nonnull List<CSharpArgument> arguments,
            @Nullable String assignedIdentifier,
            @Nullable CSharpBlockTree enclosingBlock,
            @Nullable CSharpScope scope) {
        this.line = line;
        this.column = column;
        this.objectTypeName = objectTypeName;
        this.methodName = methodName;
        this.arguments = arguments;
        this.assignedIdentifier = assignedIdentifier;
        this.enclosingBlock = enclosingBlock;
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
        return objectTypeName + "." + methodName + "(...)";
    }

    @Nullable @Override
    public CSharpScope getScope() {
        return scope;
    }

    @Nonnull
    public String getObjectTypeName() {
        return objectTypeName;
    }

    @Nonnull
    public String getMethodName() {
        return methodName;
    }

    @Nonnull
    public List<CSharpArgument> getArguments() {
        return arguments;
    }

    @Nullable public String getAssignedIdentifier() {
        return assignedIdentifier;
    }

    @Nullable public CSharpBlockTree getEnclosingBlock() {
        return enclosingBlock;
    }

    /** Back-patched by {@link CSharpBlockTree} once the block is fully constructed. */
    public void setEnclosingBlock(@Nonnull CSharpBlockTree enclosingBlock) {
        this.enclosingBlock = enclosingBlock;
    }

    @Nullable public CSharpTree getResolvedReturnValue() {
        return resolvedReturnValue;
    }

    /** Back-patched by {@code CSharpTreeConverter} once the whole file has been converted. */
    public void setResolvedReturnValue(@Nonnull CSharpTree resolvedReturnValue) {
        this.resolvedReturnValue = resolvedReturnValue;
    }
}
