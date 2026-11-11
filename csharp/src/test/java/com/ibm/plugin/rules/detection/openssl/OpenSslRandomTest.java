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
package com.ibm.plugin.rules.detection.openssl;

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
 * OpenSSL's DRBG, reported as a generic generator because the call selects nothing.
 *
 * <p>The counter-checks are the two calls that touch randomness without drawing from it: {@code
 * RAND_set_DRBG_type} configures a generator and {@code RAND_seed} feeds the pool, and neither is a
 * use of the generator. The concrete construction is deliberately not named anywhere -- OpenSSL
 * defaults to CTR-DRBG over AES-256, but that default is a property of the build and the
 * configuration file rather than of the source being scanned.
 */
class OpenSslRandomTest extends TestBase {

    private final List<String> found = new ArrayList<>();

    @Test
    void test() throws Exception {
        CSharpVerifier.verify("rules/detection/openssl/OpenSslRandomTestFile.cs", this);
        assertThat(found)
                .as("one generator component per call that draws random bytes")
                .containsExactly(
                        "DRBG", // RAND_bytes
                        "DRBG", // RAND_priv_bytes
                        "DRBG", // RAND_pseudo_bytes
                        "DRBG"); // RAND_bytes_ex
    }

    @Override
    public void asserts(
            int findingId,
            @Nonnull
                    DetectionStore<CSharpCheck, CSharpTree, CSharpSymbol, CSharpScanContext>
                            detectionStore,
            @Nonnull List<INode> nodes) {
        nodes.forEach(node -> found.add(node.asString()));
    }
}
