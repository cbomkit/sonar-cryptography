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
 * Represents a C# object creation expression such as {@code new AesManaged()} or {@code new
 * AesGcm(key)}.
 *
 * <p>Detection rules match constructors using {@code
 * forObjectTypes("AesManaged").forMethods("<init>")}.
 */
public final class CSharpObjectCreationTree implements CSharpTree {

    private final int line;
    private final int column;

    /** The simple type name (e.g. "AesManaged", "AesGcm", "HMACSHA256"). */
    @Nonnull private final String typeName;

    /** The constructor arguments. */
    @Nonnull private final List<CSharpTree> arguments;

    /** Optional identifier this new object is assigned to. */
    @Nullable private final String assignedIdentifier;

    /** The enclosing block tree (for depending rule context). */
    @Nullable private CSharpBlockTree enclosingBlock;

    public CSharpObjectCreationTree(
            int line,
            int column,
            @Nonnull String typeName,
            @Nonnull List<CSharpTree> arguments,
            @Nullable String assignedIdentifier,
            @Nullable CSharpBlockTree enclosingBlock) {
        this.line = line;
        this.column = column;
        this.typeName = typeName;
        this.arguments = arguments;
        this.assignedIdentifier = assignedIdentifier;
        this.enclosingBlock = enclosingBlock;
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
        return "new " + typeName + "(...)";
    }

    @Nonnull
    public String getTypeName() {
        return typeName;
    }

    @Nonnull
    public List<CSharpTree> getArguments() {
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
}
