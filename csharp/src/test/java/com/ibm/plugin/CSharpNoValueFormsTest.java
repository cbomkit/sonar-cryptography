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
 * Pins the expressions that have no value of their own but do contain call sites.
 *
 * <p>A ternary, a {@code ??}, a switch expression, a collection expression, a lambda's expression
 * body and a target-typed {@code new()} all either choose between values, hold several, or name no
 * type at all, so none of them resolves to one — and while that was the whole answer, the creations
 * written inside them were not reported at all. Resolving a value or a type from them would be a
 * guess and still is not done; emitting the call sites is not, because whichever branch runs, the
 * code constructs what the arm says it does.
 *
 * <p>The three counter-checks at the end are the reason this is safe: {@code is} and a comparison
 * yield a boolean and so must not resolve to their operand, and a key size arriving as a method
 * parameter must leave the RSA without one rather than attach a guess. They are asserted by the
 * expected list below containing exactly one bare {@code "RSA"}.
 *
 * <p>Every finding is asserted in source order against the full expected list rather than one by
 * one, so a shape that starts being reported twice fails here — the arms of a ternary are reached
 * through more than one path in the converter, which is exactly where a duplicate would come from.
 */
class CSharpNoValueFormsTest extends TestBase {

    private final List<String> found = new ArrayList<>();

    @Test
    void test() throws Exception {
        CSharpVerifier.verify("rules/detection/CSharpNoValueFormsTestFile.cs", this);
        assertThat(found)
                .as("one finding per call site, in source order")
                .containsExactly(
                        "RSA-1001", // () => RSA.Create(1001)
                        "RSA-1002", // _ => RSA.Create(1002)
                        "RSA-1003", // factory: () => RSA.Create(1003)
                        "RSA-1004", // Func<RSA> f = () => RSA.Create(1004)
                        "RSA-1005", // () => new RSACng(1005)
                        "RSA-1006", // 256 => RSA.Create(1006)
                        "RSA-1007", // 384 => new RSACng(1007)
                        "HMAC-SHA-256", // "SHA256" => () => new HMACSHA256()
                        "HMAC-SHA-512", // _ => () => new HMACSHA512()
                        "SHA-256", // [.. head, .. SHA256.HashData(tail)]
                        "RSA-1008", // [RSA.Create(1008), ...]
                        "RSA-1009", // [..., new RSACng(1009)]
                        "RSA-1010", // strong ? RSA.Create(1010) : ...
                        "RSA-1011", // ... : new RSACng(1011)
                        "RSA-1012", // given ?? RSA.Create(1012)
                        "RSA", // RSA.Create(bits) — deliberately without a key length
                        "NATIVEPRNG", // new() { Material = RandomNumberGenerator.GetBytes(n) }
                        "HMAC-SHA-256", // new() { () => new HMACSHA256(), ... }
                        "HMAC-SHA-512", // new() { ..., () => new HMACSHA512() }
                        "RSA-1013"); // yield return [..., new Func<..>(_ => RSA.Create(1013)), ..]
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
