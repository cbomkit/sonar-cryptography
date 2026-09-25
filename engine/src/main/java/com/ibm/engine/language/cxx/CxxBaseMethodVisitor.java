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

import com.ibm.engine.detection.IBaseMethodVisitor;
import com.ibm.engine.detection.IDetectionEngine;
import com.ibm.engine.detection.TraceSymbol;
import com.sonar.cxx.sslr.api.AstNode;
import com.sonar.cxx.sslr.api.AstNodeType;
import javax.annotation.Nonnull;
import org.sonar.cxx.parser.CxxGrammarImpl;
import org.sonar.cxx.squidbridge.api.AstNodeTraversal;
import org.sonar.cxx.squidbridge.api.Symbol;
import org.sonar.cxx.utils.CxxAstNodeHelper;

public class CxxBaseMethodVisitor implements IBaseMethodVisitor<AstNode> {
    @Nonnull private final TraceSymbol<Symbol> traceSymbol;
    @Nonnull private final IDetectionEngine<AstNode, Symbol> detectionEngine;

    private static final AstNodeType[] DETECTION_NODE_TYPES = {
        CxxGrammarImpl.postfixExpression, CxxGrammarImpl.newExpression, CxxGrammarImpl.enumSpecifier
    };

    public CxxBaseMethodVisitor(
            @Nonnull TraceSymbol<Symbol> traceSymbol,
            @Nonnull IDetectionEngine<AstNode, Symbol> detectionEngine) {
        this.traceSymbol = traceSymbol;
        this.detectionEngine = detectionEngine;
    }

    @Override
    public void visitMethodDefinition(@Nonnull AstNode method) {
        if (method.is(CxxGrammarImpl.functionDefinition)) {
            AstNode functionBody = CxxAstNodeHelper.getFunctionDefinitionBody(method);
            if (functionBody != null) {
                traverseAndDetect(functionBody);
            }
        } else if (method.is(CxxGrammarImpl.translationUnit)) {
            traverseAndDetect(method);
        }
    }

    private void traverseAndDetect(@Nonnull AstNode root) {
        AstNodeTraversal.traverse(root, DETECTION_NODE_TYPES, this::visitNode);
    }

    private void visitNode(@Nonnull AstNode node) {
        if (node.is(CxxGrammarImpl.postfixExpression)) {
            visitPostfixExpression(node);
        } else if (node.is(CxxGrammarImpl.newExpression)) {
            visitNewExpression(node);
        } else if (node.is(CxxGrammarImpl.enumSpecifier)) {
            visitEnumSpecifier(node);
        }
    }

    private void visitPostfixExpression(@Nonnull AstNode node) {
        if (CxxAstNodeHelper.isFunctionCall(node)) {
            detectionEngine.run(traceSymbol, node);
        }
    }

    private void visitNewExpression(@Nonnull AstNode node) {
        detectionEngine.run(traceSymbol, node);
    }

    private void visitEnumSpecifier(@Nonnull AstNode node) {
        detectionEngine.run(traceSymbol, node);
    }
}
