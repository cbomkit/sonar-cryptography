/*
 * Sonar Cryptography Plugin
 * Copyright (C) 2026 PQCA
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

import static org.assertj.core.api.Assertions.assertThat;

import com.ibm.engine.detection.DetectionStore;
import com.ibm.engine.language.csharp.CSharpCheck;
import com.ibm.engine.language.csharp.CSharpScanContext;
import com.ibm.engine.language.csharp.CSharpSymbol;
import com.ibm.engine.language.csharp.tree.CSharpTree;
import com.ibm.mapper.model.INode;
import java.util.ArrayList;
import java.util.List;
import javax.annotation.Nonnull;
import org.junit.jupiter.api.Test;

/**
 * Pins that one call site yields one finding, in the shapes where the converter sees the same
 * expression twice.
 *
 * <p>An expression-bodied member's arrow body was converted once to register what the member
 * returns and once more to collect the body's statements. Conversion is not free of side effects: a
 * lambda body becomes a body of its own, so the second conversion produced a second body over the
 * same statements and the call site inside it was reported twice. Duplicate findings are worse than
 * they look -- the same key or algorithm appears twice in the inventory with no way to tell that it
 * is one call -- so this asserts the exact set of findings rather than merely that each expected
 * one occurs.
 */
class CSharpSingleReportPerCallSiteTest extends TestBase {

    private final List<String> found = new ArrayList<>();

    @Test
    void test() throws Exception {
        CSharpVerifier.verify("rules/detection/CSharpSingleReportPerCallSiteTestFile.cs", this);
        assertThat(found)
                .as("one finding per call site, in source order")
                .containsExactly("RSA-2048", "RSA-3072", "RSA-4096");
    }

    @Override
    public void asserts(
            int findingId,
            @Nonnull
                    DetectionStore<CSharpCheck, CSharpTree, CSharpSymbol, CSharpScanContext>
                            detectionStore,
            @Nonnull List<INode> nodes) {
        assertThat(nodes).hasSize(1);
        found.add(nodes.get(0).asString());
    }
}
