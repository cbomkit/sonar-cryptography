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
package com.ibm.engine.language.cpp.tree;

/**
 * Base interface for all C/C++ abstract syntax tree (AST) nodes used by the engine.
 *
 * <p>This interface fills the {@code T} (Tree) generic type parameter used throughout the engine.
 * It is the C/C++ equivalent of {@code Tree} in the Java language support (from the Sonar Java
 * plugin API) and {@code CSharpTree} in the C# language support.
 *
 * <p>Because we use ANTLR to parse C/C++ source files directly (rather than a Sonar language
 * plugin), we build our own lightweight tree node hierarchy rather than relying on a pre-existing
 * AST API. Each concrete implementation of this interface represents a specific syntactic construct
 * in C/C++ source code.
 *
 * <p>The concrete tree node types are:
 *
 * <ul>
 *   <li>{@link CppLiteralTree} — string literals and numeric constants
 *   <li>{@link CppIdentifierTree} — variable and function names
 *   <li>{@link CppMethodInvocationTree} — function call expressions
 *   <li>{@link CppMemberAccessTree} — {@code ->} and {@code .} member access
 *   <li>{@link CppBlockTree} — compound statement / code block
 * </ul>
 *
 * <p>The {@link Kind} enum allows the engine and detection rules to distinguish between node types
 * without needing to use {@code instanceof} checks everywhere.
 */
public interface CppTree {

    /**
     * Enumerates the kinds of C/C++ tree nodes recognised by the engine.
     *
     * <p>This mirrors the role of the {@code Tree.Kind} enum in the Sonar Java plugin API.
     */
    enum Kind {
        /** A string literal ({@code "AES-256-CBC"}) or numeric constant ({@code 256}). */
        LITERAL,

        /** A bare identifier — a variable name or function name used as an expression. */
        IDENTIFIER,

        /**
         * A function call expression, e.g. {@code EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(),
         * NULL, key, iv)}.
         */
        METHOD_INVOCATION,

        /**
         * A member access expression using {@code ->} or {@code .}, e.g. {@code ctx->cipher} or
         * {@code params.key_len}.
         */
        MEMBER_ACCESS,

        /** A compound statement enclosed in braces, i.e. a {@code { }} block. */
        BLOCK,
    }

    /**
     * Returns the kind of this tree node.
     *
     * @return the {@link Kind} of this node, never {@code null}
     */
    Kind kind();

    /**
     * Returns the 1-based line number in the source file where this node begins.
     *
     * <p>Used by the engine to record the detection location (file + line) in the CBOM output.
     *
     * @return line number ≥ 1
     */
    int line();

    /**
     * Returns the 0-based character offset within its line where this node begins.
     *
     * @return column offset ≥ 0
     */
    int column();
}
