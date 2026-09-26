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
package com.ibm.plugin.javascript.language;

import com.ibm.engine.detection.IBaseMethodVisitor;
import com.ibm.engine.detection.IDetectionEngine;
import com.ibm.engine.detection.TraceSymbol;
import com.ibm.plugin.javascript.api.BlockTree;
import com.ibm.plugin.javascript.api.JavaScriptSymbol;
import com.ibm.plugin.javascript.api.Tree;
import javax.annotation.Nonnull;

/** Base method visitor that scans a {@link BlockTree} for cryptographic call patterns. */
public final class JavaScriptBaseMethodVisitor implements IBaseMethodVisitor<Tree> {

    @Nonnull private final TraceSymbol<JavaScriptSymbol> traceSymbol;
    @Nonnull private final IDetectionEngine<Tree, JavaScriptSymbol> detectionEngine;

    public JavaScriptBaseMethodVisitor(
            @Nonnull TraceSymbol<JavaScriptSymbol> traceSymbol,
            @Nonnull IDetectionEngine<Tree, JavaScriptSymbol> detectionEngine) {
        this.traceSymbol = traceSymbol;
        this.detectionEngine = detectionEngine;
    }

    @Override
    public void visitMethodDefinition(@Nonnull Tree method) {
        if (method instanceof BlockTree blockTree) {
            detectionEngine.run(traceSymbol, blockTree);
        }
    }
}
