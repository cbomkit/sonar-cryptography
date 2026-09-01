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
package com.ibm.engine.language.c;

import com.ibm.engine.detection.IBaseMethodVisitor;
import com.ibm.engine.detection.IDetectionEngine;
import com.ibm.engine.detection.TraceSymbol;
import com.ibm.engine.language.c.tree.CBlockTree;
import com.ibm.engine.language.c.tree.CTree;
import javax.annotation.Nonnull;

/**
 * Base method visitor for C/C++ that invokes the detection engine on each function body.
 *
 * <p>Mirrors {@code CSharpBaseMethodVisitor}: when the sensor dispatches a function body (a {@link
 * CBlockTree}) via {@link #visitMethodDefinition}, the detection engine is run on it.
 */
public final class CBaseMethodVisitor implements IBaseMethodVisitor<CTree> {

    @Nonnull private final TraceSymbol<CSymbol> traceSymbol;
    @Nonnull private final IDetectionEngine<CTree, CSymbol> detectionEngine;

    public CBaseMethodVisitor(
            @Nonnull TraceSymbol<CSymbol> traceSymbol,
            @Nonnull IDetectionEngine<CTree, CSymbol> detectionEngine) {
        this.traceSymbol = traceSymbol;
        this.detectionEngine = detectionEngine;
    }

    @Override
    public void visitMethodDefinition(@Nonnull CTree method) {
        if (method instanceof CBlockTree blockTree) {
            detectionEngine.run(traceSymbol, blockTree);
        }
    }
}
