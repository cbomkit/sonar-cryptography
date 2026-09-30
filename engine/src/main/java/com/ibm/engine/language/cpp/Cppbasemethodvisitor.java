/*
 * Sonar Cryptography Plugin
 * Copyright (C) 2025 PQCA
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
package com.ibm.engine.language.cpp;

import com.ibm.engine.detection.IBaseMethodVisitor;
import com.ibm.engine.detection.IDetectionEngine;
import com.ibm.engine.detection.TraceSymbol;
import com.ibm.engine.language.cpp.tree.CppBlockTree;
import com.ibm.engine.language.cpp.tree.CppTree;
import javax.annotation.Nonnull;

/**
 * Base method visitor for C/C++ that invokes the detection engine on each function body.
 *
 * <p>Mirrors {@link com.ibm.engine.language.csharp.CSharpBaseMethodVisitor}: when the sensor
 * dispatches a function body (a {@link CppBlockTree}) via {@link #visitMethodDefinition}, the
 * detection engine is run on it.
 *
 * <p>In C/C++ every top-level function body is a {@link CppBlockTree}. The ANTLR tree converter
 * ({@code CppTreeConverter}) extracts one {@link CppBlockTree} per function body, and the sensor
 * calls {@link #visitMethodDefinition} once per block. The detection engine then walks the block's
 * statement list looking for function calls that match registered detection rules.
 */
public final class CppBaseMethodVisitor implements IBaseMethodVisitor<CppTree> {

    @Nonnull private final TraceSymbol<CppSymbol> traceSymbol;
    @Nonnull private final IDetectionEngine<CppTree, CppSymbol> detectionEngine;

    public CppBaseMethodVisitor(
            @Nonnull TraceSymbol<CppSymbol> traceSymbol,
            @Nonnull IDetectionEngine<CppTree, CppSymbol> detectionEngine) {
        this.traceSymbol = traceSymbol;
        this.detectionEngine = detectionEngine;
    }

    /**
     * Visits a C/C++ function body and runs the detection engine on it.
     *
     * <p>Only {@link CppBlockTree} nodes are processed — any other tree type is ignored because
     * C/C++ detection rules operate at the block (function body) level.
     *
     * @param method a tree node representing a function body, expected to be a {@link CppBlockTree}
     */
    @Override
    public void visitMethodDefinition(@Nonnull CppTree method) {
        if (method instanceof CppBlockTree blockTree) {
            detectionEngine.run(traceSymbol, blockTree);
        }
    }
}
