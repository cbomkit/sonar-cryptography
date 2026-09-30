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

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

/**
 * A C/C++ tree node representing an identifier — a variable name, function name, or type name as
 * it appears in an expression.
 *
 * <p>Examples of identifiers this node captures:
 *
 * <ul>
 *   <li>A function name used in a call: {@code EVP_aes_256_cbc} in {@code EVP_aes_256_cbc()}
 *   <li>A variable passed as an argument: {@code ctx}, {@code key}, {@code iv}
 *   <li>A macro constant: {@code EVP_MAX_KEY_LENGTH}, {@code RSA_PKCS1_PADDING}
 * </ul>
 *
 * <p>Example C code producing this node:
 *
 * <pre>{@code
 * EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
 * //               ^^^                  ^^^
 * //        identifier (variable)   identifier (function)
 * }</pre>
 *
 * <p>The engine uses this node to match function names against detection rules. When the detection
 * engine sees a {@link CppMethodInvocationTree}, it checks the callee identifier name against the
 * patterns defined in each {@code IDetectionRule}.
 */
public final class CppIdentifierTree implements CppTree {

    /** The identifier name exactly as it appears in source code. */
    @Nonnull private final String name;

    /**
     * The optional type string of this identifier, derived from context (e.g. {@code
     * "EVP_CIPHER_CTX *"} for a pointer variable). This is used by the engine's {@code
     * forObjectTypes} matching. May be {@code null} when the type cannot be inferred from the
     * current single-method scope.
     */
    @Nullable private final String type;

    private final int line;
    private final int column;

    /**
     * Creates a new {@code CppIdentifierTree} without type information.
     *
     * @param name the identifier name as it appears in source code
     * @param line 1-based line number in the source file
     * @param column 0-based column offset within the line
     */
    public CppIdentifierTree(@Nonnull String name, int line, int column) {
        this.name = name;
        this.type = null;
        this.line = line;
        this.column = column;
    }

    /**
     * Creates a new {@code CppIdentifierTree} with optional type information.
     *
     * @param name the identifier name as it appears in source code
     * @param type the inferred type string, or {@code null} if not known
     * @param line 1-based line number in the source file
     * @param column 0-based column offset within the line
     */
    public CppIdentifierTree(@Nonnull String name, @Nullable String type, int line, int column) {
        this.name = name;
        this.type = type;
        this.line = line;
        this.column = column;
    }

    /**
     * Returns the identifier name exactly as it appears in source code.
     *
     * @return identifier name, never {@code null}
     */
    @Nonnull
    public String name() {
        return name;
    }

    /**
     * Returns the inferred type of this identifier, if available.
     *
     * <p>For OpenSSL code, this would be something like {@code "EVP_CIPHER_CTX"} or {@code "RSA"}.
     * This is used by the engine when matching {@code forObjectTypes(...)} in detection rules.
     *
     * @return the type string, or {@code null} if not determinable from single-method scope
     */
    @Nullable
    public String type() {
        return type;
    }

    @Override
    public Kind kind() {
        return Kind.IDENTIFIER;
    }

    @Override
    public int line() {
        return line;
    }

    @Override
    public int column() {
        return column;
    }

    @Override
    public String toString() {
        return "CppIdentifierTree{name='" + name + "', type='" + type + "', line=" + line + "}";
    }
}
