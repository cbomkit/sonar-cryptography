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
package com.ibm.plugin.rules.resolve;

import com.ibm.engine.detection.DetectionStore;
import com.ibm.engine.detection.Finding;
import com.ibm.engine.utils.DetectionStoreLogger;
import com.ibm.mapper.model.INode;
import com.ibm.plugin.TestBase;
import java.util.List;
import javax.annotation.Nonnull;
import org.junit.jupiter.api.Test;
import org.sonar.plugins.python.api.PythonCheck;
import org.sonar.plugins.python.api.PythonVisitorContext;
import org.sonar.plugins.python.api.symbols.Symbol;
import org.sonar.plugins.python.api.tree.Tree;
import org.sonar.python.checks.utils.PythonCheckVerifier;

class ResolveLoopsTest extends TestBase {

    public ResolveLoopsTest() {
        super(ResolveScopeValues.rules());
    }

    @Override
    public void asserts(
            int findingId,
            @Nonnull DetectionStore<PythonCheck, Tree, Symbol, PythonVisitorContext> detectionStore,
            @Nonnull List<INode> nodes) {
        // nothing
    }

    @Test
    void test() {
        PythonCheckVerifier.verify("src/test/files/rules/resolve/ResolveLoopsTestFile.py", this);
    }

    @Override
    public void update(@Nonnull Finding<PythonCheck, Tree, Symbol, PythonVisitorContext> finding) {
        final DetectionStore<
                        PythonCheck,
                        Tree,
                        org.sonar.plugins.python.api.symbols.Symbol,
                        PythonVisitorContext>
                detectionStore = finding.detectionStore();
        (new DetectionStoreLogger<PythonCheck, Tree, Symbol, PythonVisitorContext>())
                .print(detectionStore);
        detectionStore
                .getDetectionValues()
                .forEach(
                        iValue -> {
                            detectionStore
                                    .getScanContext()
                                    .reportIssue(this, iValue.getLocation(), iValue.asString());
                        });
    }
}
