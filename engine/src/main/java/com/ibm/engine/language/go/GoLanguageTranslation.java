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
package com.ibm.engine.language.go;

import com.ibm.engine.detection.IType;
import com.ibm.engine.detection.MatchContext;
import com.ibm.engine.language.ILanguageTranslation;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import javax.annotation.Nonnull;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.sonar.plugins.go.api.FunctionInvocationTree;
import org.sonar.plugins.go.api.IdentifierTree;
import org.sonar.plugins.go.api.LiteralTree;
import org.sonar.plugins.go.api.MemberSelectTree;
import org.sonar.plugins.go.api.Tree;

/**
 * Language translation implementation for Go. Provides methods to extract information from Go AST
 * nodes.
 */
public final class GoLanguageTranslation implements ILanguageTranslation<Tree> {

    @Nonnull
    private static final Logger LOGGER = LoggerFactory.getLogger(GoLanguageTranslation.class);

    @Nonnull
    @Override
    public Optional<String> getMethodName(
            @Nonnull MatchContext matchContext, @Nonnull Tree methodInvocation) {
        if (methodInvocation instanceof FunctionInvocationTree functionInvocation) {
            Tree memberSelect = functionInvocation.memberSelect();
            if (memberSelect instanceof MemberSelectTree memberSelectTree) {
                // pkg.Function() or receiver.Method() pattern
                return Optional.of(memberSelectTree.identifier().name());
            } else if (memberSelect instanceof IdentifierTree identifierTree) {
                // Direct function call: Function()
                return Optional.of(identifierTree.name());
            }
        } else if (methodInvocation instanceof MemberSelectTree memberSelectTree) {
            // Function reference: pkg.Function (without invocation parentheses)
            // e.g., sha256.New passed as a parameter to hmac.New
            return Optional.of(memberSelectTree.identifier().name());
        }
        return Optional.empty();
    }

    @Nonnull
    @Override
    public Optional<IType> getInvokedObjectTypeString(
            @Nonnull MatchContext matchContext, @Nonnull Tree methodInvocation) {
        if (methodInvocation instanceof FunctionInvocationTree functionInvocation) {
            Tree memberSelect = functionInvocation.memberSelect();
            return getTypeFromMemberSelect(memberSelect, matchContext);
        } else if (methodInvocation instanceof MemberSelectTree memberSelectTree) {
            // Function reference: pkg.Function (without invocation parentheses)
            // e.g., sha256.New passed as a parameter to hmac.New
            return getTypeFromMemberSelect(memberSelectTree, matchContext);
        }
        return Optional.empty();
    }

    /**
     * Extracts the type information from a member select tree or identifier tree.
     *
     * @param memberSelect the tree to extract type from (MemberSelectTree or IdentifierTree)
     * @param matchContext the match context
     * @return the type if found
     */
    @Nonnull
    private Optional<IType> getTypeFromMemberSelect(
            @Nonnull Tree memberSelect, @Nonnull MatchContext matchContext) {
        if (memberSelect instanceof MemberSelectTree memberSelectTree) {
            // Get the receiver/package expression
            Tree expression = memberSelectTree.expression();
            if (expression instanceof IdentifierTree identifierTree) {
                // Could be package name or variable name
                String name = identifierTree.name();
                String packageName = identifierTree.packageName();
                String typeName = identifierTree.type();

                // For package-level function calls (e.g., aes.NewCipher)
                // the expression is the package alias
                if (packageName != null
                        && !packageName.isEmpty()
                        && !"UNKNOWN".equals(packageName)) {
                    return Optional.of(createGoType(packageName, matchContext));
                }
                // For method calls on a variable, use the type
                if (typeName != null && !typeName.isEmpty() && !"UNKNOWN".equals(typeName)) {
                    return Optional.of(createGoType(typeName, matchContext));
                }
                // Fallback to the identifier name (likely package alias)
                return Optional.of(createGoType(name, matchContext));
            }
        } else if (memberSelect instanceof IdentifierTree identifierTree) {
            // Direct function call - check package
            String packageName = identifierTree.packageName();
            if (packageName != null && !packageName.isEmpty()) {
                return Optional.of(createGoType(packageName, matchContext));
            }
        }
        return Optional.empty();
    }

    @Nonnull
    @Override
    public Optional<IType> getMethodReturnTypeString(
            @Nonnull MatchContext matchContext, @Nonnull Tree methodInvocation) {
        if (methodInvocation instanceof FunctionInvocationTree functionInvocation) {
            List<org.sonar.plugins.go.api.Type> returnTypes = functionInvocation.returnTypes();
            if (returnTypes != null && !returnTypes.isEmpty()) {
                org.sonar.plugins.go.api.Type firstReturnType = returnTypes.get(0);
                String typeName = firstReturnType.type();
                if (typeName != null && !typeName.isEmpty()) {
                    return Optional.of(createGoType(typeName, matchContext));
                }
            }
        }
        return Optional.empty();
    }

    @Nonnull
    @Override
    public List<IType> getMethodParameterTypes(
            @Nonnull MatchContext matchContext, @Nonnull Tree methodInvocation) {
        if (methodInvocation instanceof FunctionInvocationTree functionInvocation) {
            List<Tree> arguments = functionInvocation.arguments();
            if (arguments == null || arguments.isEmpty()) {
                return Collections.emptyList();
            }

            List<IType> types = new ArrayList<>();
            for (Tree argument : arguments) {
                types.add(createArgumentType(argument, matchContext));
            }
            return types;
        } else if (methodInvocation instanceof MemberSelectTree) {
            // Function reference: pkg.Function (without invocation parentheses)
            // Function references have no arguments at the call site
            return Collections.emptyList();
        }
        return Collections.emptyList();
    }

    @Nonnull
    @Override
    public Optional<String> resolveIdentifierAsString(
            @Nonnull MatchContext matchContext, @Nonnull Tree identifier) {
        if (identifier instanceof IdentifierTree identifierTree) {
            return Optional.of(identifierTree.name());
        } else if (identifier instanceof LiteralTree literalTree) {
            return Optional.of(literalTree.value());
        }
        return Optional.empty();
    }

    @Nonnull
    @Override
    public Optional<String> getEnumIdentifierName(
            @Nonnull MatchContext matchContext, @Nonnull Tree enumIdentifier) {
        // Go uses const blocks instead of enums
        if (enumIdentifier instanceof IdentifierTree identifierTree) {
            return Optional.of(identifierTree.name());
        }
        return Optional.empty();
    }

    @Nonnull
    @Override
    public Optional<String> getEnumClassName(
            @Nonnull MatchContext matchContext, @Nonnull Tree enumClass) {
        // Go doesn't have enum classes
        return Optional.empty();
    }

    /**
     * Creates an IType that matches Go type patterns.
     *
     * <p>Go types can be matched by:
     *
     * <ul>
     *   <li>Full package path: "crypto/aes"
     *   <li>Package name only: "aes"
     *   <li>Type with package: "aes.Block"
     *   <li>Dot-qualified type: "*dsa.Parameters" matches "*Parameters"
     * </ul>
     */
    @Nonnull
    private IType createGoType(@Nonnull String typeName, @Nonnull MatchContext matchContext) {
        return expectedType -> {
            if (typeName.equals(expectedType)) {
                return true;
            }
            // Normalize both types and compare
            String normalizedTypeName = normalizeGoType(typeName);
            String normalizedExpectedType = normalizeGoType(expectedType);
            return normalizedTypeName.equals(normalizedExpectedType);
        };
    }

    /**
     * Normalizes a Go type to its shortest canonical form for matching.
     *
     * <p>Go types from the parser can include full package paths (e.g., {@code
     * *crypto/dsa.Parameters}). This method strips the path prefix, keeping only the short package
     * name and type, while preserving any pointer/slice prefix.
     *
     * <p>Examples:
     *
     * <ul>
     *   <li>"*crypto/dsa.Parameters" → "*dsa.Parameters"
     *   <li>"crypto/dsa" → "dsa"
     *   <li>"[]crypto/dsa.Parameters" → "[]dsa.Parameters"
     *   <li>"*math/big.Int" → "*big.Int"
     *   <li>"io.Reader" → "io.Reader" (unchanged, no path)
     *   <li>"*dsa.Parameters" → "*dsa.Parameters" (unchanged, no path)
     * </ul>
     */
    @Nonnull
    private static String normalizeGoType(@Nonnull String goType) {
        if (!goType.contains("/")) {
            return goType;
        }
        // Extract prefix (*, [], etc.) - everything before the first letter
        int prefixEnd = 0;
        while (prefixEnd < goType.length() && !Character.isLetter(goType.charAt(prefixEnd))) {
            prefixEnd++;
        }
        String prefix = goType.substring(0, prefixEnd);
        String withoutPrefix = goType.substring(prefixEnd);
        // Strip path and package: "crypto/dsa.Parameters" → "Parameters"
        String shortened = withoutPrefix.substring(withoutPrefix.lastIndexOf('/') + 1);
        int dotIndex = shortened.lastIndexOf('.');
        if (dotIndex >= 0) {
            shortened = shortened.substring(dotIndex + 1);
        }
        return prefix + shortened;
    }

    /** Creates an IType for a function argument based on its AST node. */
    @Nonnull
    private IType createArgumentType(@Nonnull Tree argument, @Nonnull MatchContext matchContext) {
        if (argument instanceof IdentifierTree identifierTree) {
            String typeName = identifierTree.type();
            if (typeName != null && !typeName.isEmpty()) {
                return createGoType(typeName, matchContext);
            }
        } else if (argument instanceof FunctionInvocationTree functionInvocation) {
            // For function call arguments, get the return type
            Optional<IType> returnType =
                    getMethodReturnTypeString(matchContext, functionInvocation);
            if (returnType.isPresent()) {
                return returnType.get();
            }
        } else if (argument instanceof LiteralTree) {
            // For literals, match the literal type
            return expectedType -> {
                // Go literal types: string, int, float64, etc.
                return true; // Literals match any expected type for simplicity
            };
        }
        // Default: match any type
        return expectedType -> true;
    }
}
