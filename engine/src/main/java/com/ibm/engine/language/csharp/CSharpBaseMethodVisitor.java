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
package com.ibm.engine.language.csharp;

import com.ibm.engine.detection.IBaseMethodVisitor;
import com.ibm.engine.detection.IDetectionEngine;
import com.ibm.engine.detection.TraceSymbol;
import com.ibm.engine.language.csharp.tree.CSharpBlockTree;
import com.ibm.engine.language.csharp.tree.CSharpTree;
import javax.annotation.Nonnull;

/**
 * Base method visitor for C# that invokes the detection engine on each method body.
 *
 * <p>Mirrors {@code GoBaseMethodVisitor}: when the sensor dispatches a method body (a {@link
 * CSharpBlockTree}) via {@link #visitMethodDefinition}, the detection engine is run on it.
 */
public final class CSharpBaseMethodVisitor implements IBaseMethodVisitor<CSharpTree> {

    @Nonnull private final TraceSymbol<CSharpSymbol> traceSymbol;
    @Nonnull private final IDetectionEngine<CSharpTree, CSharpSymbol> detectionEngine;

    public CSharpBaseMethodVisitor(
            @Nonnull TraceSymbol<CSharpSymbol> traceSymbol,
            @Nonnull IDetectionEngine<CSharpTree, CSharpSymbol> detectionEngine) {
        this.traceSymbol = traceSymbol;
        this.detectionEngine = detectionEngine;
    }

    @Override
    public void visitMethodDefinition(@Nonnull CSharpTree method) {
        if (method instanceof CSharpBlockTree blockTree) {
            detectionEngine.run(traceSymbol, blockTree);
        }
    }
}
