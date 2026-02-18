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
package com.ibm.plugin.translation.translator;

import com.ibm.engine.model.IValue;
import com.ibm.engine.model.context.AlgorithmParameterContext;
import com.ibm.engine.model.context.CipherContext;
import com.ibm.engine.model.context.DigestContext;
import com.ibm.engine.model.context.IDetectionContext;
import com.ibm.engine.model.context.KeyAgreementContext;
import com.ibm.engine.model.context.KeyContext;
import com.ibm.engine.model.context.KeyDerivationFunctionContext;
import com.ibm.engine.model.context.MacContext;
import com.ibm.engine.model.context.PRNGContext;
import com.ibm.engine.model.context.PrivateKeyContext;
import com.ibm.engine.model.context.ProtocolContext;
import com.ibm.engine.model.context.PublicKeyContext;
import com.ibm.engine.model.context.SecretKeyContext;
import com.ibm.engine.model.context.SignatureContext;
import com.ibm.engine.rule.IBundle;
import com.ibm.mapper.ITranslator;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.utils.DetectionLocation;
import com.ibm.plugin.translation.translator.contexts.CxxCipherContextTranslator;
import com.ibm.plugin.translation.translator.contexts.CxxDigestContextTranslator;
import com.ibm.plugin.translation.translator.contexts.CxxKeyAgreementContextTranslator;
import com.ibm.plugin.translation.translator.contexts.CxxKeyContextTranslator;
import com.ibm.plugin.translation.translator.contexts.CxxKeyDerivationFunctionContextTranslator;
import com.ibm.plugin.translation.translator.contexts.CxxMacContextTranslator;
import com.ibm.plugin.translation.translator.contexts.CxxPRNGContextTranslator;
import com.ibm.plugin.translation.translator.contexts.CxxProtocolContextTranslator;
import com.ibm.plugin.translation.translator.contexts.CxxSecretKeyContextTranslator;
import com.ibm.plugin.translation.translator.contexts.CxxSignatureContextTranslator;
import com.sonar.cxx.sslr.api.AstNode;
import com.sonar.cxx.sslr.api.Grammar;
import com.sonar.cxx.sslr.api.Token;
import java.util.List;
import java.util.Optional;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import org.sonar.cxx.parser.CxxGrammarImpl;
import org.sonar.cxx.squidbridge.SquidAstVisitorContext;
import org.sonar.cxx.squidbridge.api.Symbol;
import org.sonar.cxx.squidbridge.checks.SquidCheck;
import org.sonar.cxx.utils.CxxAstNodeHelper;

/**
 * C++ translator for converting detection findings to the mapper model.
 *
 * <p>This class extends the base {@link ITranslator} and provides C++-specific translation logic
 * for various cryptographic detection contexts (cipher, key, digest, signature, etc.).
 *
 * <p>The translator delegates to context-specific translators based on the detection context type.
 */
public final class CxxTranslator
        extends ITranslator<
                SquidCheck<?>, AstNode, Symbol, SquidAstVisitorContext<? extends Grammar>> {

    public CxxTranslator() {
        // nothing
    }

    @Override
    @Nonnull
    public Optional<INode> translate(
            @Nonnull final IBundle bundleIdentifier,
            @Nonnull final IValue<AstNode> value,
            @Nonnull final IDetectionContext detectionValueContext,
            @Nonnull final String filePath) {
        DetectionLocation detectionLocation =
                getDetectionContextFrom(value.getLocation(), bundleIdentifier, filePath);
        if (detectionLocation == null) {
            return Optional.empty();
        }

        // cipher context
        if (detectionValueContext.is(CipherContext.class)) {
            CxxCipherContextTranslator cxxCipherContextTranslation =
                    new CxxCipherContextTranslator();
            return cxxCipherContextTranslation.translate(
                    bundleIdentifier, value, detectionValueContext, detectionLocation);

            // secret key context
        } else if (detectionValueContext.is(SecretKeyContext.class)) {
            CxxSecretKeyContextTranslator cxxSecretKeyContextTranslation =
                    new CxxSecretKeyContextTranslator();
            return cxxSecretKeyContextTranslation.translate(
                    bundleIdentifier, value, detectionValueContext, detectionLocation);

            // private- / public- / secret- / key context
        } else if (detectionValueContext.is(KeyContext.class)
                || detectionValueContext.is(PublicKeyContext.class)
                || detectionValueContext.is(PrivateKeyContext.class)
                || detectionValueContext.is(SecretKeyContext.class)) {
            CxxKeyContextTranslator cxxKeyContextTranslation = new CxxKeyContextTranslator();
            return cxxKeyContextTranslation.translate(
                    bundleIdentifier, value, detectionValueContext, detectionLocation);

            // key agreement context
        } else if (detectionValueContext.is(KeyAgreementContext.class)) {
            CxxKeyAgreementContextTranslator cxxKeyAgreementContextTranslation =
                    new CxxKeyAgreementContextTranslator();
            return cxxKeyAgreementContextTranslation.translate(
                    bundleIdentifier, value, detectionValueContext, detectionLocation);

            // PRNG context
        } else if (detectionValueContext.is(PRNGContext.class)) {
            CxxPRNGContextTranslator cxxPRNGContextTranslation = new CxxPRNGContextTranslator();
            return cxxPRNGContextTranslation.translate(
                    bundleIdentifier, value, detectionValueContext, detectionLocation);

            // digest context
        } else if (detectionValueContext.is(DigestContext.class)) {
            CxxDigestContextTranslator cxxDigestContextTranslation =
                    new CxxDigestContextTranslator();
            return cxxDigestContextTranslation.translate(
                    bundleIdentifier, value, detectionValueContext, detectionLocation);

            // signature context
        } else if (detectionValueContext.is(SignatureContext.class)) {
            CxxSignatureContextTranslator cxxSignatureContextTranslation =
                    new CxxSignatureContextTranslator();
            return cxxSignatureContextTranslation.translate(
                    bundleIdentifier, value, detectionValueContext, detectionLocation);

            // mac context
        } else if (detectionValueContext.is(MacContext.class)) {
            CxxMacContextTranslator cxxMacContextTranslation = new CxxMacContextTranslator();
            return cxxMacContextTranslation.translate(
                    bundleIdentifier, value, detectionValueContext, detectionLocation);

            // key derivation function context
        } else if (detectionValueContext.is(KeyDerivationFunctionContext.class)) {
            CxxKeyDerivationFunctionContextTranslator cxxKdfContextTranslation =
                    new CxxKeyDerivationFunctionContextTranslator();
            return cxxKdfContextTranslation.translate(
                    bundleIdentifier, value, detectionValueContext, detectionLocation);

            // algorithm parameter context
        } else if (detectionValueContext.is(AlgorithmParameterContext.class)) {
            // TODO: Implement CxxAlgorithmParameterContextTranslator
            return Optional.empty();

            // protocol
        } else if (detectionValueContext.is(ProtocolContext.class)) {
            CxxProtocolContextTranslator cxxProtocolContextTranslation =
                    new CxxProtocolContextTranslator();
            return cxxProtocolContextTranslation.translate(
                    bundleIdentifier, value, detectionValueContext, detectionLocation);
        }
        return Optional.empty();
    }

    /**
     * Gets a detection location from the specified AstNode location and file path.
     *
     * <p>This method extracts line number, column offset, and keywords from the AST node to create
     * a DetectionLocation for reporting findings.
     */
    @Override
    @Nullable public DetectionLocation getDetectionContextFrom(
            @Nonnull AstNode location, @Nonnull IBundle bundle, @Nonnull String filePath) {
        Token token = location.getToken();
        if (token == null) {
            return null;
        }

        int lineNumber = token.getLine();
        int offset = token.getColumn();
        List<String> keywords = extractKeywords(location);

        return new DetectionLocation(filePath, lineNumber, offset, keywords, bundle);
    }

    /**
     * Extracts keywords from the AST node for the detection location.
     *
     * @param node The AST node to extract keywords from
     * @return List of keywords (function name, etc.)
     */
    @Nonnull
    private List<String> extractKeywords(@Nonnull AstNode node) {
        // Try to extract function name for function calls
        if (node.is(CxxGrammarImpl.postfixExpression)) {
            if (CxxAstNodeHelper.isFunctionCall(node)) {
                String functionName = CxxAstNodeHelper.getFunctionCallName(node);
                if (functionName != null) {
                    return List.of(functionName);
                }
            }
        } else if (node.is(CxxGrammarImpl.newExpression)) {
            // For new expressions, try to get the type name from the type specifier
            AstNode typeSpecifier = node.getFirstDescendant(CxxGrammarImpl.typeSpecifier);
            if (typeSpecifier != null) {
                String typeName = CxxAstNodeHelper.getIdentifierName(typeSpecifier);
                if (typeName != null) {
                    return List.of(typeName);
                }
            }
        }

        // Fallback to token value
        Token token = node.getToken();
        if (token != null) {
            return List.of(token.getValue());
        }

        return List.of();
    }
}
