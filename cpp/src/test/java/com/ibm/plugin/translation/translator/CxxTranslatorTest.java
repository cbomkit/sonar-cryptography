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

import static org.assertj.core.api.Assertions.assertThat;

import com.ibm.engine.model.ValueAction;
import com.ibm.engine.model.context.AlgorithmParameterContext;
import com.ibm.engine.model.context.KeyContext;
import com.ibm.engine.model.context.SecretKeyContext;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.utils.DetectionLocation;
import com.sonar.cxx.sslr.api.AstNode;
import com.sonar.cxx.sslr.api.GenericTokenType;
import com.sonar.cxx.sslr.api.Token;
import com.sonar.cxx.sslr.api.TokenType;
import java.net.URI;
import java.util.Map;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import org.sonar.cxx.parser.CxxGrammarImpl;

class CxxTranslatorTest {

    private final CxxTranslator translator = new CxxTranslator();

    private static Token fakeToken(TokenType type, String value, int line, int column) {
        return Token.builder()
                .setLine(line)
                .setColumn(column)
                .setValueAndOriginalValue(value)
                .setType(type)
                .setURI(URI.create("file:///test.cpp"))
                .build();
    }

    private static final class PlainAstNodeType implements TokenType {
        @Override
        public String getName() {
            return "PLAIN";
        }

        @Override
        public String getValue() {
            return "PLAIN";
        }

        @Override
        public boolean hasToBeSkippedFromAst(AstNode node) {
            return false;
        }
    }

    // --- getDetectionContextFrom ---

    @Test
    void aNodeWithNoTokenYieldsNoDetectionLocation() {
        AstNode nodeWithNoToken = new AstNode(new PlainAstNodeType(), "empty", null);
        DetectionLocation location =
                translator.getDetectionContextFrom(nodeWithNoToken, () -> "OpenSSL", "f.cpp");
        assertThat(location).isNull();
    }

    @Test
    void aNodeWithATokenYieldsALocationCarryingItsLineAndColumn() {
        AstNode leaf = new AstNode(fakeToken(GenericTokenType.IDENTIFIER, "foo", 7, 3));
        DetectionLocation location =
                translator.getDetectionContextFrom(leaf, () -> "OpenSSL", "f.cpp");
        assertThat(location).isNotNull();
        assertThat(location.lineNumber()).isEqualTo(7);
        assertThat(location.offSet()).isEqualTo(3);
        assertThat(location.filePath()).isEqualTo("f.cpp");
    }

    // --- extractKeywords, exercised through translate()'s DetectionLocation.keywords() ---

    @Test
    void aFunctionCallPostfixExpressionYieldsTheCalleeNameAsKeyword() {
        AstNode idExpression = new AstNode(CxxGrammarImpl.idExpression, "idExpression", null);
        AstNode identifier =
                new AstNode(fakeToken(GenericTokenType.IDENTIFIER, "EVP_MD_fetch", 1, 0));
        idExpression.addChild(identifier);

        AstNode openParen = new AstNode(fakeToken(new PlainAstNodeType(), "(", 1, 12));
        AstNode closeParen = new AstNode(fakeToken(new PlainAstNodeType(), ")", 1, 13));

        // a real parser-built postfixExpression node carries its first token itself, in addition
        // to that same token being reachable through its idExpression child
        AstNode postfixExpression =
                new AstNode(
                        CxxGrammarImpl.postfixExpression,
                        "postfixExpression",
                        fakeToken(GenericTokenType.IDENTIFIER, "EVP_MD_fetch", 1, 0));
        postfixExpression.addChild(idExpression);
        postfixExpression.addChild(openParen);
        postfixExpression.addChild(closeParen);

        DetectionLocation location =
                translator.getDetectionContextFrom(postfixExpression, () -> "OpenSSL", "f.cpp");
        assertThat(location).isNotNull();
        assertThat(location.keywords()).containsExactly("EVP_MD_fetch");
    }

    @Test
    void aNewExpressionYieldsTheConstructedTypeNameAsKeyword() {
        AstNode typeIdentifier =
                new AstNode(fakeToken(GenericTokenType.IDENTIFIER, "EVP_PKEY_CTX", 1, 4));
        AstNode typeSpecifier = new AstNode(CxxGrammarImpl.typeSpecifier, "typeSpecifier", null);
        typeSpecifier.addChild(typeIdentifier);

        // a real parser-built newExpression node carries its own first token (e.g. "new")
        AstNode newExpression =
                new AstNode(
                        CxxGrammarImpl.newExpression,
                        "newExpression",
                        fakeToken(new PlainAstNodeType(), "new", 1, 0));
        newExpression.addChild(typeSpecifier);

        DetectionLocation location =
                translator.getDetectionContextFrom(newExpression, () -> "OpenSSL", "f.cpp");
        assertThat(location).isNotNull();
        assertThat(location.keywords()).containsExactly("EVP_PKEY_CTX");
    }

    @Test
    void aNewExpressionWithNoTypeSpecifierFallsBackToTheTokenValue() {
        // newExpression itself carries a token (its first token, e.g. "new"), so with no
        // typeSpecifier descendant, extractKeywords falls back to that node's own token value.
        AstNode newExpression =
                new AstNode(
                        CxxGrammarImpl.newExpression,
                        "newExpression",
                        fakeToken(new PlainAstNodeType(), "new", 1, 0));

        DetectionLocation location =
                translator.getDetectionContextFrom(newExpression, () -> "OpenSSL", "f.cpp");
        assertThat(location).isNotNull();
        assertThat(location.keywords()).containsExactly("new");
    }

    @Test
    void anUnrecognizedNodeShapeFallsBackToItsOwnTokenValue() {
        AstNode plainLeaf = new AstNode(fakeToken(new PlainAstNodeType(), "someToken", 2, 0));

        DetectionLocation location =
                translator.getDetectionContextFrom(plainLeaf, () -> "OpenSSL", "f.cpp");
        assertThat(location).isNotNull();
        assertThat(location.keywords()).containsExactly("someToken");
    }

    // --- translate() dispatch ---

    private static AstNode leafWithToken() {
        return new AstNode(fakeToken(GenericTokenType.IDENTIFIER, "x", 1, 0));
    }

    @Test
    void secretKeyContextDispatchesToTheSecretKeyTranslatorAndYieldsEmptyForAPlainValueAction() {
        // No cpp rule currently produces a SecretKeyContext value, but the dispatch branch
        // itself is reachable and must not throw.
        Optional<INode> node =
                translator.translate(
                        () -> "OpenSSL",
                        new ValueAction<>("AES-256", leafWithToken()),
                        new SecretKeyContext(Map.of()),
                        "f.cpp");
        assertThat(node).isEmpty();
    }

    @Test
    void keyContextDispatchesToTheKeyTranslator() {
        Optional<INode> node =
                translator.translate(
                        () -> "OpenSSL",
                        new ValueAction<>("RSA", leafWithToken()),
                        new KeyContext(),
                        "f.cpp");
        assertThat(node).isPresent();
    }

    @Test
    void algorithmParameterContextIsNotYetImplementedAndYieldsEmpty() {
        Optional<INode> node =
                translator.translate(
                        () -> "OpenSSL",
                        new ValueAction<>("whatever", leafWithToken()),
                        new AlgorithmParameterContext(),
                        "f.cpp");
        assertThat(node).isEmpty();
    }

    @Test
    void aValueWithNoResolvableLocationYieldsEmpty() {
        AstNode nodeWithNoToken = new AstNode(new PlainAstNodeType(), "empty", null);
        Optional<INode> node =
                translator.translate(
                        () -> "OpenSSL",
                        new ValueAction<>("RSA", nodeWithNoToken),
                        new KeyContext(),
                        "f.cpp");
        assertThat(node).isEmpty();
    }
}
