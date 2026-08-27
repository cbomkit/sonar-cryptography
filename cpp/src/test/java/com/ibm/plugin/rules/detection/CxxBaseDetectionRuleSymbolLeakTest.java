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
package com.ibm.plugin.rules.detection;

import static org.assertj.core.api.Assertions.assertThat;

import com.ibm.engine.detection.DetectionStore;
import com.ibm.mapper.model.INode;
import com.ibm.plugin.CxxVerifier;
import com.ibm.plugin.TestBase;
import com.sonar.cxx.sslr.api.AstNode;
import com.sonar.cxx.sslr.api.Grammar;
import java.util.List;
import javax.annotation.Nonnull;
import org.junit.jupiter.api.Test;
import org.sonar.cxx.squidbridge.SquidAstVisitorContext;
import org.sonar.cxx.squidbridge.api.AstNodeSymbolExtension;
import org.sonar.cxx.squidbridge.api.AstNodeTypeExtension;
import org.sonar.cxx.squidbridge.api.Symbol;
import org.sonar.cxx.squidbridge.checks.SquidCheck;

/**
 * {@code AstNodeSymbolExtension}/{@code AstNodeTypeExtension} are process-wide {@code WeakHashMap}s
 * keyed on {@code AstNode}; their values ({@code Symbol}/{@code Type}) no longer hold their own key
 * node strongly, but {@code WeakHashMap} eviction is still lazy and GC-timed, so {@link
 * CxxBaseDetectionRule#leaveFile} removes every entry for a file's own nodes deterministically, as
 * soon as that file's AST is no longer needed, rather than leaving it to the next GC cycle. This
 * test scans two files in a single shared scan (mirroring a real multi-file analysis, {@code
 * leaveFile} firing per file as each finishes) and asserts both maps end up empty right after,
 * since population-count is exact and observable without relying on GC or heap-delta timing.
 */
class CxxBaseDetectionRuleSymbolLeakTest extends TestBase {

    @Override
    public void asserts(
            int findingId,
            @Nonnull
                    DetectionStore<
                                    SquidCheck<?>,
                                    AstNode,
                                    Symbol,
                                    SquidAstVisitorContext<? extends Grammar>>
                            detectionStore,
            @Nonnull List<INode> nodes) {
        // no per-finding assertions; this test only checks the symbol/type extension map sizes
    }

    @Test
    void symbolAndTypeExtensionsDoNotAccumulateAcrossFiles() {
        CxxVerifier.verifyFiles(
                List.of(
                        "rules/detection/openssl/keygen/OpenSSLEvpKeyGenTestFile.cc",
                        "rules/detection/openssl/kdf/OpenSSLEvpKdfTestFile.cc"),
                this);

        assertThat(AstNodeSymbolExtension.size())
                .as("every scanned file's own nodes must be released once that file leaves")
                .isEqualTo(0);
        assertThat(AstNodeTypeExtension.size())
                .as("every scanned file's own nodes must be released once that file leaves")
                .isEqualTo(0);
    }
}
