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

import com.ibm.engine.language.go.GoScanContext;
import com.ibm.engine.model.IValue;
import com.ibm.engine.model.context.CipherContext;
import com.ibm.engine.model.context.IDetectionContext;
import com.ibm.engine.rule.IBundle;
import com.ibm.mapper.ITranslator;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.utils.DetectionLocation;
import com.ibm.plugin.translation.translator.contexts.GoCipherContextTranslator;
import java.util.List;
import java.util.Optional;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import org.sonar.go.symbols.Symbol;
import org.sonar.plugins.go.api.FunctionInvocationTree;
import org.sonar.plugins.go.api.IdentifierTree;
import org.sonar.plugins.go.api.MemberSelectTree;
import org.sonar.plugins.go.api.Tree;
import org.sonar.plugins.go.api.checks.GoCheck;

public class GoTranslator extends ITranslator<GoCheck, Tree, Symbol, GoScanContext> {

    public GoTranslator() {
        // nothing
    }

    @Nonnull
    @Override
    public Optional<INode> translate(
            @Nonnull final IBundle bundleIdentifier,
            @Nonnull final IValue<Tree> value,
            @Nonnull final IDetectionContext detectionValueContext,
            @Nonnull final String filePath) {
        DetectionLocation detectionLocation =
                getDetectionContextFrom(value.getLocation(), bundleIdentifier, filePath);
        if (detectionLocation == null) {
            return Optional.empty();
        }

        if (detectionValueContext.is(CipherContext.class)) {
            final GoCipherContextTranslator goCipherContextTranslator =
                    new GoCipherContextTranslator();
            return goCipherContextTranslator.translate(
                    bundleIdentifier, value, detectionValueContext, detectionLocation);
        }

        return Optional.empty();
    }

    @Override
    protected @Nullable DetectionLocation getDetectionContextFrom(
            @Nonnull Tree location, @Nonnull IBundle bundle, @Nonnull String filePath) {
        // Get position information from the tree
        int lineNumber = location.metaData().textRange().start().line();
        int offset = location.metaData().textRange().start().lineOffset();

        List<String> keywords = List.of();
        if (location instanceof FunctionInvocationTree functionInvocation) {
            Tree memberSelect = functionInvocation.memberSelect();
            if (memberSelect instanceof MemberSelectTree memberSelectTree) {
                IdentifierTree identifier = memberSelectTree.identifier();
                if (identifier != null) {
                    keywords = List.of(identifier.name());
                }
            } else if (memberSelect instanceof IdentifierTree identifier) {
                keywords = List.of(identifier.name());
            }
        }

        return new DetectionLocation(filePath, lineNumber, offset, keywords, bundle);
    }
}
