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

/**
 * A C/C++ tree node representing a member access expression using {@code ->} or {@code .}.
 *
 * <p>In C, struct fields and pointer-to-struct fields are frequently used when working with OpenSSL
 * types. This node captures expressions like:
 *
 * <ul>
 *   <li>Pointer member access: {@code ctx->cipher}, {@code rsa->n}, {@code params->key_len}
 *   <li>Direct member access: {@code suite.algorithm}, {@code config.padding}
 * </ul>
 *
 * <p>Example C code producing this node:
 *
 * <pre>{@code
 * // Arrow operator (pointer to struct)
 * EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
 * ctx->encrypt = 1;
 *
 * // Dot operator (direct struct access)
 * RSA_METHOD method;
 * method.rsa_sign = my_sign_function;
 * }</pre>
 *
 * <p>The engine uses this node primarily to resolve the object type when matching {@code
 * forObjectTypes(...)} in detection rules. By tracking what type {@code ctx} is, the engine can
 * confirm that {@code EVP_EncryptInit_ex(ctx, ...)} is indeed operating on an {@code
 * EVP_CIPHER_CTX}.
 */
public final class CppMemberAccessTree implements CppTree {

    /** Enum distinguishing between {@code ->} (arrow) and {@code .} (dot) access. */
    public enum AccessType {
        /** Pointer member access via {@code ->}. */
        ARROW,
        /** Direct struct member access via {@code .}. */
        DOT
    }

    /** The expression on the left side of the operator, e.g. {@code ctx} in {@code ctx->cipher}. */
    @Nonnull private final CppTree object;

    /** The member name on the right side of the operator, e.g. {@code "cipher"} in {@code ctx->cipher}. */
    @Nonnull private final String memberName;

    /** Whether this is an arrow ({@code ->}) or dot ({@code .}) access. */
    @Nonnull private final AccessType accessType;

    private final int line;
    private final int column;

    /**
     * Creates a new {@code CppMemberAccessTree}.
     *
     * @param object the tree node representing the left-hand side expression
     * @param memberName the name of the struct member being accessed
     * @param accessType whether this is {@code ->} or {@code .} access
     * @param line 1-based line number in the source file
     * @param column 0-based column offset within the line
     */
    public CppMemberAccessTree(
            @Nonnull CppTree object,
            @Nonnull String memberName,
            @Nonnull AccessType accessType,
            int line,
            int column) {
        this.object = object;
        this.memberName = memberName;
        this.accessType = accessType;
        this.line = line;
        this.column = column;
    }

    /**
     * Returns the tree node representing the object (left-hand side of the access operator).
     *
     * @return the object expression tree, never {@code null}
     */
    @Nonnull
    public CppTree object() {
        return object;
    }

    /**
     * Returns the name of the struct member being accessed.
     *
     * @return member name, never {@code null}
     */
    @Nonnull
    public String memberName() {
        return memberName;
    }

    /**
     * Returns whether this is a {@code ->} (arrow) or {@code .} (dot) member access.
     *
     * @return the access type, never {@code null}
     */
    @Nonnull
    public AccessType accessType() {
        return accessType;
    }

    /** Returns {@code true} if this is a {@code ->} (pointer) member access. */
    public boolean isArrow() {
        return accessType == AccessType.ARROW;
    }

    /** Returns {@code true} if this is a {@code .} (direct) member access. */
    public boolean isDot() {
        return accessType == AccessType.DOT;
    }

    @Override
    public Kind kind() {
        return Kind.MEMBER_ACCESS;
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
        String op = accessType == AccessType.ARROW ? "->" : ".";
        return "CppMemberAccessTree{object="
                + object
                + ", op='"
                + op
                + "', member='"
                + memberName
                + "', line="
                + line
                + "}";
    }
}
