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
package com.ibm.plugin.rules.detection.openssl.kdf;

import com.ibm.engine.detection.ResolvedValue;
import com.ibm.engine.model.Algorithm;
import com.ibm.engine.model.IValue;
import com.ibm.engine.model.factory.IValueFactory;
import com.ibm.plugin.rules.detection.openssl.digest.OpenSSLNameCanonicalizerFactory;
import com.sonar.cxx.sslr.api.AstNode;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import javax.annotation.Nonnull;
import org.sonar.cxx.parser.CxxGrammarImpl;
import org.sonar.cxx.parser.CxxPunctuator;
import org.sonar.cxx.utils.CxxAstNodeHelper;

/**
 * Resolves a named entry from an {@code OSSL_PARAM} array literal — e.g. an {@code
 * EVP_KDF_CTX_set_params(kctx, params)} or {@code EVP_MAC_CTX_set_params(ctx, params)} call's
 * {@code params} argument, traced back by {@link com.ibm.engine.language.cxx.CxxSemantic} to its
 * {@code OSSL_PARAM params[] = {...}} declaration. Scans the array's {@code
 * OSSL_PARAM_construct_utf8_string(key, value, size)} elements for the one keyed {@code paramKey}
 * (e.g. {@code OSSL_KDF_PARAM_DIGEST}'s value {@code "digest"}, or {@code OSSL_MAC_PARAM_CIPHER}'s
 * value {@code "cipher"}) and resolves its value argument against {@code canonicalTable} the same
 * way {@link OpenSSLNameCanonicalizerFactory} does. An array with no such element, or a {@code
 * value} that is not the {@code bracedInitList} node produced by {@link
 * com.ibm.engine.language.cxx.CxxSemantic}, resolves to nothing.
 */
public final class OpenSSLParamsScannerFactory implements IValueFactory<AstNode> {

    @Nonnull private final String paramKey;
    @Nonnull private final Map<String, String> canonicalTable;

    public OpenSSLParamsScannerFactory(
            @Nonnull String paramKey, @Nonnull Map<String, String> canonicalTable) {
        this.paramKey = paramKey;
        this.canonicalTable = canonicalTable;
    }

    @Override
    @Nonnull
    public Optional<IValue<AstNode>> apply(@Nonnull ResolvedValue<Object, AstNode> resolvedValue) {
        if (!(resolvedValue.value() instanceof AstNode arrayNode)
                || !arrayNode.is(CxxGrammarImpl.bracedInitList)) {
            return Optional.empty();
        }

        // The grammar wraps the comma-separated elements in a single initializerList child
        // (`{ initializerList }`), rather than exposing initializerClause as direct children
        // of the bracedInitList itself.
        final AstNode initializerList = arrayNode.getFirstChild(CxxGrammarImpl.initializerList);
        if (initializerList == null) {
            return Optional.empty();
        }

        // initializerClause is a single-alternative pass-through rule (-> assignmentExpression),
        // so sonar-cxx's grammar elides it from the tree: initializerList's direct children are
        // the element expressions themselves (here, postfixExpression call nodes) interleaved
        // with COMMA tokens, not wrapped in an intermediate initializerClause node.
        for (AstNode call : initializerList.getChildren(CxxGrammarImpl.postfixExpression)) {
            if (!CxxAstNodeHelper.isFunctionCall(call)) {
                continue;
            }
            final String functionName = CxxAstNodeHelper.getFunctionCallName(call);
            if (functionName == null || !functionName.startsWith("OSSL_PARAM_construct_")) {
                continue;
            }
            final List<AstNode> args = flattenCallArguments(call);
            if (args.size() < 2 || !paramKey.equals(literalStringValue(args.get(0)))) {
                continue;
            }
            final String name = literalStringValue(args.get(1));
            if (name != null) {
                return Optional.of(
                        new Algorithm<>(
                                OpenSSLNameCanonicalizerFactory.canonicalize(canonicalTable, name),
                                resolvedValue.tree()));
            }
        }
        return Optional.empty();
    }

    /**
     * {@link CxxAstNodeHelper#getFunctionCallArguments} returns {@code
     * expressionList.getChildren()}, which for a multi-argument call is always a single-element
     * list wrapping an {@code initializerList} node, not the individual arguments - so it must be
     * unwrapped the same way the outer {@code OSSL_PARAM} array literal is above.
     */
    @Nonnull
    private static List<AstNode> flattenCallArguments(@Nonnull AstNode call) {
        final List<AstNode> raw = CxxAstNodeHelper.getFunctionCallArguments(call);
        if (raw.size() == 1 && raw.get(0).is(CxxGrammarImpl.initializerList)) {
            return raw.get(0).getChildren().stream()
                    .filter(child -> !child.is(CxxPunctuator.COMMA))
                    .toList();
        }
        return raw;
    }

    @Nonnull
    private static String literalStringValue(@Nonnull AstNode node) {
        final String raw = node.getTokenValue();
        if (raw != null && raw.length() >= 2 && raw.startsWith("\"") && raw.endsWith("\"")) {
            return raw.substring(1, raw.length() - 1);
        }
        return raw == null ? "" : raw;
    }
}
