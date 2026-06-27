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
package com.ibm.plugin.rules.detection.openssl.ssl;

import com.ibm.engine.model.IAction;
import com.sonar.cxx.sslr.api.AstNode;
import com.sonar.cxx.sslr.api.GenericTokenType;
import java.util.List;
import java.util.Map;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.sonar.cxx.parser.CxxGrammarImpl;
import org.sonar.cxx.parser.CxxTokenType;
import org.sonar.cxx.utils.CxxAstNodeHelper;
import org.sonar.cxx.utils.CxxConstantUtils;

/**
 * Specialized IAction for OpenSSL protocol version detection.
 *
 * <p>Extracts the version parameter from SSL_CTX_set_min/max_proto_version calls by directly
 * navigating the C++ AST structure and resolves it to a human-readable version string.
 *
 * <p>The sonar-cxx parser represents a call like {@code SSL_CTX_set_min_proto_version(ctx, 0x0303)}
 * with a single argument node that has three children: {@code ctx} (IDENTIFIER), {@code ,} (COMMA),
 * and {@code 0x0303} (NUMBER). This class extracts the third child (index 2) as the version
 * parameter.
 *
 * <p>Supports:
 *
 * <ul>
 *   <li>Direct hex literals (e.g., {@code 0x0303} → "TLSv1.2")
 *   <li>Compile-time constants via CxxConstantUtils (e.g., resolved {@code const int} variables)
 *   <li>Well-known OpenSSL constant names (e.g., {@code TLS1_2_VERSION} → "TLSv1.2") when the
 *       preprocessor does not expand them
 *   <li>Fallback to generic markers for unresolvable expressions (e.g., runtime variables)
 * </ul>
 */
public final class OpenSSLVersionValue implements IAction<AstNode> {
    private static final Logger LOGGER = LoggerFactory.getLogger(OpenSSLVersionValue.class);

    /**
     * Maps well-known OpenSSL version constant names to their version strings. These constants are
     * defined in {@code openssl/tls1.h} and {@code openssl/ssl3.h}. When the sonar-cxx preprocessor
     * cannot expand these macros (e.g., headers not on the include path), they appear as bare
     * IDENTIFIERs in the AST and must be resolved by name.
     */
    private static final Map<String, String> OPENSSL_VERSION_CONSTANTS =
            Map.ofEntries(
                    Map.entry("SSL3_VERSION", "SSLv3.0"), // 0x0300
                    Map.entry("TLS1_VERSION", "TLSv1.0"), // 0x0301
                    Map.entry("TLS1_1_VERSION", "TLSv1.1"), // 0x0302
                    Map.entry("TLS1_2_VERSION", "TLSv1.2"), // 0x0303
                    Map.entry("TLS1_3_VERSION", "TLSv1.3"), // 0x0304
                    Map.entry("DTLS1_VERSION", "DTLSv1.0"), // 0xFEFF
                    Map.entry("DTLS1_2_VERSION", "DTLSv1.2"), // 0xFEFD
                    Map.entry("DTLS1_BAD_VER", "DTLSv1.0")); // 0x0100

    @Nonnull private final String kind; // "MIN" or "MAX"
    @Nonnull private final AstNode methodCallNode;

    public OpenSSLVersionValue(@Nonnull String kind, @Nonnull AstNode methodCallNode) {
        this.kind = kind;
        this.methodCallNode = methodCallNode;
    }

    @Nonnull
    @Override
    public AstNode getLocation() {
        return methodCallNode;
    }

    @Nonnull
    @Override
    public String asString() {
        try {
            List<AstNode> arguments = CxxAstNodeHelper.getFunctionCallArguments(methodCallNode);

            // sonar-cxx returns expressionList.getChildren() — always a single initializerList
            // node.
            // initializerList children: [0]=ctx, [1]=COMMA, [2]=version param.
            // Guard on node type so a future sonar-cxx grammar change (e.g. adding skipIfOneChild)
            // produces a visible warning instead of silently returning the fallback marker string.
            if (!arguments.isEmpty()) {
                AstNode argList = arguments.get(0);
                if (!argList.is(CxxGrammarImpl.initializerList)) {
                    LOGGER.warn(
                            "Unexpected AST structure for {} version: expected initializerList"
                                    + " but got {}. sonar-cxx grammar may have changed.",
                            kind,
                            argList.getType());
                } else if (argList.getNumberOfChildren() >= 3) {
                    AstNode versionParam = argList.getChildren().get(2);
                    String resolved = resolveVersionString(versionParam);
                    if (resolved != null) {
                        LOGGER.debug("Resolved {} version parameter → \"{}\"", kind, resolved);
                        return resolved;
                    }
                }
            }
        } catch (Exception e) {
            LOGGER.warn("Error extracting {} version parameter: {}", kind, e.getMessage());
        }

        // Fallback to generic marker when version cannot be resolved
        return "TLS-" + kind + "-VERSION";
    }

    /**
     * Resolves a version parameter AST node to a version string.
     *
     * <p>Resolution strategy (in order):
     *
     * <ol>
     *   <li>If the node is a NUMBER literal, parse it and map to a version string
     *   <li>If the node is an IDENTIFIER matching a well-known OpenSSL constant name, map it
     *       directly (handles the case where the preprocessor did not expand the macro)
     *   <li>Try CxxConstantUtils to resolve const variables or enum constants
     *   <li>Traverse through single-child wrapper nodes and retry at each level
     * </ol>
     *
     * @param versionParam The AST node representing the version parameter
     * @return The version string (e.g., "TLSv1.2"), or null if resolution fails
     */
    @Nullable private String resolveVersionString(@Nonnull AstNode versionParam) {
        AstNode current = versionParam;
        while (current != null) {
            // 1. Direct NUMBER literal (e.g., 0x0303)
            if (current.is(CxxTokenType.NUMBER)) {
                return resolveNumberToVersionString(current.getTokenValue());
            }

            // 2. Well-known OpenSSL constant name (e.g., TLS1_2_VERSION)
            if (current.is(GenericTokenType.IDENTIFIER)) {
                String constantName = current.getTokenValue();
                String versionString = OPENSSL_VERSION_CONSTANTS.get(constantName);
                if (versionString != null) {
                    LOGGER.debug(
                            "Resolved {} version from OpenSSL constant name: {} → \"{}\"",
                            kind,
                            constantName,
                            versionString);
                    return versionString;
                }
            }

            // 3. Try CxxConstantUtils (handles const variables, enum constants, expressions)
            Object result = CxxConstantUtils.resolveAsConstant(current);
            if (result instanceof Number num) {
                String versionString = mapVersionToString(num.intValue());
                if (versionString != null) {
                    return versionString;
                }
                LOGGER.warn("Unknown version value {} for {} version", num.intValue(), kind);
                return null;
            }

            // 4. Descend through single-child wrapper nodes
            if (current.getNumberOfChildren() == 1) {
                current = current.getFirstChild();
            } else {
                break;
            }
        }
        return null;
    }

    /**
     * Parses a C++ number literal string and maps it to a version string.
     *
     * @param tokenValue The raw token value (e.g., "0x0303", "771", "0x0303u")
     * @return The version string, or null if the number is unknown
     */
    @Nullable private static String resolveNumberToVersionString(@Nonnull String tokenValue) {
        try {
            int value;
            if (tokenValue.length() > 1
                    && tokenValue.charAt(0) == '0'
                    && (tokenValue.charAt(1) == 'x' || tokenValue.charAt(1) == 'X')) {
                // Hex literal: f/F are valid hex digits, so only strip integer suffixes (u/l)
                String hex = tokenValue.replaceAll("[uUlL]+$", "").substring(2);
                value = Integer.parseInt(hex, 16);
            } else {
                // Decimal/octal literal: strip all type suffixes including float suffix (f/F)
                String dec = tokenValue.replaceAll("[uUlLfF]+$", "");
                value = Integer.parseInt(dec);
            }
            return mapVersionToString(value);
        } catch (NumberFormatException e) {
            return null;
        }
    }

    /**
     * Maps an OpenSSL version integer to a human-readable version string.
     *
     * @param versionValue The integer version value (e.g., 0x0303 = 771)
     * @return The version string (e.g., "TLSv1.2"), or null if the value is unknown
     */
    @Nullable private static String mapVersionToString(int versionValue) {
        return switch (versionValue) {
            case 768 -> "SSLv3.0"; // 0x0300
            case 769 -> "TLSv1.0"; // 0x0301
            case 770 -> "TLSv1.1"; // 0x0302
            case 771 -> "TLSv1.2"; // 0x0303
            case 772 -> "TLSv1.3"; // 0x0304
            case 65279 -> "DTLSv1.0"; // 0xFEFF
            case 65277 -> "DTLSv1.2"; // 0xFEFD
            default -> null;
        };
    }
}
