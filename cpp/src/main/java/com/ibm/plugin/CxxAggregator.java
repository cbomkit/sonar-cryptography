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
package com.ibm.plugin;

import com.ibm.engine.language.ILanguageSupport;
import com.ibm.engine.language.LanguageSupporter;
import com.ibm.mapper.model.INode;
import com.ibm.output.IAggregator;
import com.sonar.cxx.sslr.api.AstNode;
import com.sonar.cxx.sslr.api.Grammar;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import javax.annotation.Nonnull;
import org.sonar.cxx.squidbridge.SquidAstVisitorContext;
import org.sonar.cxx.squidbridge.api.Symbol;
import org.sonar.cxx.squidbridge.checks.SquidCheck;

public final class CxxAggregator implements IAggregator {

    private static ILanguageSupport<
                    SquidCheck<?>, AstNode, Symbol, SquidAstVisitorContext<? extends Grammar>>
            cxxLanguageSupport = LanguageSupporter.cxxLanguageSupporter();
    private static List<INode> detectedNodes = new ArrayList<>();

    private CxxAggregator() {
        // nothing
    }

    public static void addNodes(@Nonnull List<INode> newNodes) {
        detectedNodes.addAll(newNodes);
        IAggregator.log(newNodes);
    }

    @Nonnull
    public static List<INode> getDetectedNodes() {
        return Collections.unmodifiableList(detectedNodes);
    }

    @Nonnull
    public static ILanguageSupport<
                    SquidCheck<?>, AstNode, Symbol, SquidAstVisitorContext<? extends Grammar>>
            getLanguageSupport() {
        return cxxLanguageSupport;
    }

    public static void reset() {
        cxxLanguageSupport = LanguageSupporter.cxxLanguageSupporter();
        detectedNodes = new ArrayList<>();
    }
}
