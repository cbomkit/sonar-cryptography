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
package com.ibm.engine.language.cxx;

import static org.assertj.core.api.Assertions.assertThat;

import com.ibm.engine.detection.IType;
import com.ibm.engine.detection.MatchContext;
import com.sonar.cxx.sslr.api.AstNode;
import com.sonar.cxx.sslr.api.GenericTokenType;
import com.sonar.cxx.sslr.api.Token;
import com.sonar.cxx.sslr.api.TokenType;
import java.net.URI;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.sonar.cxx.parser.CxxGrammarImpl;
import org.sonar.cxx.parser.CxxPunctuator;
import org.sonar.cxx.parser.CxxTokenType;

/**
 * {@link CxxLanguageTranslation#getMethodParameterTypes} gives an argument that is a literal its
 * source text as its type (e.g. matched by {@code withMethodParameter("\"AES-256-GCM\"")}), also
 * when the literal is not wrapped in a {@code LITERAL} grammar node but is reached through nodes of
 * one child each. A literal that is only part of the argument, as {@code 2} in {@code a[2]}, does
 * not give the argument its text.
 */
class CxxLanguageTranslationLiteralArgumentTest {

    private final CxxLanguageTranslation translation = new CxxLanguageTranslation();

    @Test
    void matchesAStringLiteralNestedBelowTheArgumentNodeWithNoLiteralWrapper() {
        AstNode methodInvocation = buildFunctionCall(buildNestedStringToken("\"AES-256-GCM\""));

        List<IType> types =
                translation.getMethodParameterTypes(
                        MatchContext.createForHookContext(), methodInvocation);

        assertThat(types).hasSize(1);
        assertThat(types.get(0).is("\"AES-256-GCM\"")).isTrue();
        assertThat(types.get(0).is("\"something-else\"")).isFalse();
    }

    @Test
    void doesNotMatchALiteralThatIsOnlyPartOfTheArgument() {
        AstNode subscript = new AstNode(new PlainAstNodeType(), "postfixExpression", null);
        subscript.addChild(new AstNode(fakeToken(GenericTokenType.IDENTIFIER, "a")));
        subscript.addChild(new AstNode(fakeToken(CxxPunctuator.BR_LEFT, "[")));
        subscript.addChild(new AstNode(fakeToken(CxxTokenType.NUMBER, "2")));
        subscript.addChild(new AstNode(fakeToken(CxxPunctuator.BR_RIGHT, "]")));
        AstNode methodInvocation = buildFunctionCall(subscript);

        List<IType> types =
                translation.getMethodParameterTypes(
                        MatchContext.createForHookContext(), methodInvocation);

        assertThat(types).hasSize(1);
        assertThat(types.get(0).is("2")).isFalse();
    }

    /**
     * A raw {@code STRING} token nested two levels under a wrapper node that is not itself
     * grammar-typed as {@code LITERAL} - so {@code getFirstDescendant(CxxGrammarImpl.LITERAL)}
     * finds nothing, and only a token-type-aware descendant walk reaches it.
     */
    private static AstNode buildNestedStringToken(String text) {
        AstNode stringToken = new AstNode(fakeToken(CxxTokenType.STRING, text));
        AstNode innerWrapper = new AstNode(new PlainAstNodeType(), "innerWrapper", null);
        innerWrapper.addChild(stringToken);
        AstNode outerWrapper = new AstNode(new PlainAstNodeType(), "initializerClause", null);
        outerWrapper.addChild(innerWrapper);
        return outerWrapper;
    }

    /**
     * Builds a minimal {@code postfixExpression}-shaped function call whose single argument is
     * {@code argument}: {@code CxxAstNodeHelper.isFunctionCall} requires a {@code
     * postfixExpression} child token {@code "("}; {@code extractActualArguments} then requires a
     * descendant {@code expressionList} node whose children (no {@code initializerList} child) are
     * the arguments.
     */
    private static AstNode buildFunctionCall(AstNode argument) {
        AstNode postfixExpression =
                new AstNode(CxxGrammarImpl.postfixExpression, "postfixExpression", null);
        AstNode openParen = new AstNode(fakeToken(CxxPunctuator.BR_LEFT, "("));
        AstNode expressionList = new AstNode(CxxGrammarImpl.expressionList, "expressionList", null);
        expressionList.addChild(argument);
        AstNode closeParen = new AstNode(fakeToken(CxxPunctuator.BR_RIGHT, ")"));

        postfixExpression.addChild(openParen);
        postfixExpression.addChild(expressionList);
        postfixExpression.addChild(closeParen);
        return postfixExpression;
    }

    private static Token fakeToken(TokenType type, String value) {
        return Token.builder()
                .setLine(1)
                .setColumn(0)
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
}
