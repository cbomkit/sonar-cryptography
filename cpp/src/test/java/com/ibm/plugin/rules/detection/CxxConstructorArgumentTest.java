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
import java.util.ArrayList;
import java.util.List;
import javax.annotation.Nonnull;
import org.junit.jupiter.api.Test;
import org.sonar.cxx.squidbridge.SquidAstVisitorContext;
import org.sonar.cxx.squidbridge.api.Symbol;
import org.sonar.cxx.squidbridge.checks.SquidCheck;

/**
 * A value passed to a constructor or a member function of a C++ class is followed into it, as one
 * passed to a function is: the object may be declared with arguments ({@code Hasher h("SHA224")},
 * {@code Hasher h{...}}, also when the declaration reads as a function declaration, {@code Hasher
 * h(name)}), created with {@code new} or as a temporary, and the constructor or member function
 * defined in its class or outside it ({@code Digester::Digester(...)}), in a namespace or not, as
 * is one passed to a static member function ({@code Hasher::select(...)}). A declaration of a
 * variable of a built-in type, a pointer or a reference calls no constructor, nor does the
 * declaration of a function whose parameters are types ({@code Hasher make(Config)}).
 */
class CxxConstructorArgumentTest extends TestBase {

    private final List<String> findings = new ArrayList<>();

    @Test
    void test() {
        CxxVerifier.verify("rules/detection/CxxConstructorArgumentTestFile.cc", this);
        assertThat(findings)
                .containsExactly(
                        "SHA-224",
                        "SHA-384",
                        "SHA-512",
                        "SHA-1",
                        "MD5",
                        "SHA3-256",
                        "SHA-256",
                        "SHA3-512",
                        "SHA-512/256",
                        "SHA-512/224",
                        "SM3");
    }

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
        assertThat(nodes).hasSize(1);
        findings.add(nodes.get(0).asString());
    }
}
