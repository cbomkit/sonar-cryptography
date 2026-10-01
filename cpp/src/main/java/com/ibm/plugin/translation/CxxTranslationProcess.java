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
package com.ibm.plugin.translation;

import com.ibm.engine.detection.DetectionStore;
import com.ibm.enricher.Enricher;
import com.ibm.mapper.ITranslationProcess;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.reorganizer.IReorganizerRule;
import com.ibm.mapper.reorganizer.Reorganizer;
import com.ibm.mapper.utils.Utils;
import com.ibm.plugin.translation.translator.CxxTranslator;
import com.sonar.cxx.sslr.api.AstNode;
import com.sonar.cxx.sslr.api.Grammar;
import java.util.List;
import javax.annotation.Nonnull;
import org.sonar.cxx.squidbridge.SquidAstVisitorContext;
import org.sonar.cxx.squidbridge.api.Symbol;
import org.sonar.cxx.squidbridge.checks.SquidCheck;

/**
 * C++ translation process for converting detection findings to the mapper model.
 *
 * <p>This class implements the three-phase translation pipeline:
 *
 * <ol>
 *   <li>Translate: Convert detection values to mapper model nodes
 *   <li>Reorganize: Apply reorganizer rules to normalize the tree structure
 *   <li>Enrich: Add additional algorithm details from the enricher
 * </ol>
 */
public final class CxxTranslationProcess
        extends ITranslationProcess<
                SquidCheck<?>, AstNode, Symbol, SquidAstVisitorContext<? extends Grammar>> {

    public CxxTranslationProcess(@Nonnull List<IReorganizerRule> reorganizerRules) {
        super(reorganizerRules);
    }

    @Override
    @Nonnull
    public List<INode> initiate(
            @Nonnull
                    DetectionStore<
                                    SquidCheck<?>,
                                    AstNode,
                                    Symbol,
                                    SquidAstVisitorContext<? extends Grammar>>
                            rootDetectionStore) {
        // 1. Translate
        final CxxTranslator cxxTranslator = new CxxTranslator();
        final List<INode> translatedValues = cxxTranslator.translate(rootDetectionStore);
        Utils.printNodeTree("translated ", translatedValues);

        // 2. Reorganize
        final Reorganizer cxxReorganizer = new Reorganizer(reorganizerRules);
        final List<INode> reorganizedValues = cxxReorganizer.reorganize(translatedValues);
        Utils.printNodeTree("reorganised", reorganizedValues);

        // 3. Enrich
        final List<INode> enrichedValues = Enricher.enrich(reorganizedValues).stream().toList();
        Utils.printNodeTree("enriched   ", enrichedValues);

        return enrichedValues;
    }
}
