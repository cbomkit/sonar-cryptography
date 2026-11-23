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
package com.ibm.plugin.rules.detection.npgsql;

import static org.assertj.core.api.Assertions.assertThat;

import com.ibm.engine.detection.DetectionStore;
import com.ibm.engine.language.csharp.CSharpCheck;
import com.ibm.engine.language.csharp.CSharpScanContext;
import com.ibm.engine.language.csharp.CSharpSymbol;
import com.ibm.engine.language.csharp.tree.CSharpTree;
import com.ibm.mapper.model.INode;
import com.ibm.plugin.CSharpVerifier;
import com.ibm.plugin.TestBase;
import java.util.ArrayList;
import java.util.List;
import javax.annotation.Nonnull;
import org.junit.jupiter.api.Test;

/**
 * Whether a database connection requires TLS, read from the driver's {@code SslMode} property.
 *
 * <p>Three members require it and are reported; the opportunistic ones and the disabled one are
 * not, because they do not state that any cryptography happens. The last two counter-checks guard
 * the two ways this could go wrong: a property of the same name holding a string, which the
 * declared type refuses, and the same setting written inside a connection string, which is
 * deliberately not read out of the literal.
 */
class NpgsqlTest extends TestBase {

    private final List<String> found = new ArrayList<>();

    @Test
    void test() throws Exception {
        CSharpVerifier.verify("rules/detection/npgsql/NpgsqlTestFile.cs", this);
        assertThat(found)
                .as("TLS only where the mode requires it")
                .containsExactly(
                        "TLS", // SslMode.Require
                        "TLS", // SslMode.VerifyFull, written as an object initializer
                        "TLS", // SslMode.VerifyCA
                        "TLS"); // MySqlConnector's SslMode.Required
    }

    @Override
    public void asserts(
            int findingId,
            @Nonnull
                    DetectionStore<CSharpCheck, CSharpTree, CSharpSymbol, CSharpScanContext>
                            detectionStore,
            @Nonnull List<INode> nodes) {
        // A detection whose value the translator declines -- an opportunistic or disabled
        // option -- arrives here with no nodes at all, and contributes nothing.
        nodes.forEach(node -> found.add(node.asString()));
    }
}
