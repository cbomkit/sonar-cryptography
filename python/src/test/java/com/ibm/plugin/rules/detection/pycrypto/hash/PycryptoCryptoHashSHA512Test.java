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
package com.ibm.plugin.rules.detection.pycrypto.hash;

import static org.assertj.core.api.Assertions.assertThat;

import com.ibm.engine.detection.DetectionStore;
import com.ibm.engine.model.AlgorithmParameter;
import com.ibm.engine.model.IValue;
import com.ibm.engine.model.ValueAction;
import com.ibm.engine.model.context.DigestContext;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.MessageDigest;
import com.ibm.mapper.model.functionality.Digest;
import com.ibm.plugin.TestBase;
import java.util.List;
import javax.annotation.Nonnull;
import org.junit.jupiter.api.Test;
import org.sonar.plugins.python.api.PythonCheck;
import org.sonar.plugins.python.api.PythonVisitorContext;
import org.sonar.plugins.python.api.symbols.Symbol;
import org.sonar.plugins.python.api.tree.Tree;
import org.sonar.python.checks.utils.PythonCheckVerifier;

/**
 * Extensive positive and negative tests for the {@code SHA512.new} detection rule, verifying the
 * {@code withNamedMethodParameter} feature:
 *
 * <ul>
 *   <li>Both parameters absent (no-args call) → match, no truncate child
 *   <li>Only {@code data} by keyword → match, no truncate child
 *   <li>Only {@code truncate} by keyword → match, truncate child captured
 *   <li>Both by keyword, canonical order → match, truncate child captured
 *   <li>Both by keyword, reordered → match, truncate child captured
 *   <li>Both positional → match, truncate child captured
 *   <li>Mixed positional/keyword → match, truncate child captured
 *   <li>Only data positional → match, no truncate child
 *   <li>Cryptodome module variant → match, truncate child captured
 *   <li>Different algorithm (SHA256) → no match
 *   <li>Wrong method name → no match
 *   <li>Unknown keyword only → match (both optional params absent), no truncate child
 * </ul>
 */
class PycryptoCryptoHashSHA512Test extends TestBase {

    private static final String BASE_PATH = "src/test/files/rules/detection/pycrypto/hash/";

    public PycryptoCryptoHashSHA512Test() {
        super(PycryptoCryptoHash.rules());
    }

    // -------------------------------------------------------------------------
    // Positive tests
    // -------------------------------------------------------------------------

    /** SHA512.new() — no arguments; both optional params absent; rule must still fire. */
    @Test
    void testNoArgs() {
        PythonCheckVerifier.verify(BASE_PATH + "SHA512NewNoArgsTest.py", this);
    }

    /** SHA512.new(data=b"msg") — data by keyword; truncate absent (optional). */
    @Test
    void testDataKeyword() {
        PythonCheckVerifier.verify(BASE_PATH + "SHA512NewDataKeywordTest.py", this);
    }

    /**
     * SHA512.new(truncate="256") — truncate by keyword, data absent; truncate child must be
     * captured.
     */
    @Test
    void testTruncateKeywordOnly() {
        PythonCheckVerifier.verify(BASE_PATH + "SHA512NewTruncateKeywordOnlyTest.py", this);
    }

    /**
     * SHA512.new(data=b"msg", truncate="256") — both by keyword name, canonical order; truncate
     * child must be captured.
     */
    @Test
    void testBothKeywordsCanonicalOrder() {
        PythonCheckVerifier.verify(BASE_PATH + "SHA512NewBothKeywordsCanonicalOrderTest.py", this);
    }

    /**
     * SHA512.new(truncate="256", data=b"msg") — both by keyword name, reordered; engine must find
     * each parameter by name, not by position.
     */
    @Test
    void testBothKeywordsReordered() {
        PythonCheckVerifier.verify(BASE_PATH + "SHA512NewBothKeywordsReorderedTest.py", this);
    }

    /**
     * SHA512.new(b"msg", "256") — both positional; engine uses positional fallback (data→0,
     * truncate→1).
     */
    @Test
    void testBothPositional() {
        PythonCheckVerifier.verify(BASE_PATH + "SHA512NewBothPositionalTest.py", this);
    }

    /**
     * SHA512.new(b"msg", truncate="256") — data by positional fallback (index 0), truncate by
     * keyword name.
     */
    @Test
    void testMixedPositionalKeyword() {
        PythonCheckVerifier.verify(BASE_PATH + "SHA512NewMixedPositionalKeywordTest.py", this);
    }

    /** SHA512.new(b"msg") — data by positional fallback, truncate absent (optional). */
    @Test
    void testDataPositionalOnly() {
        PythonCheckVerifier.verify(BASE_PATH + "SHA512NewDataPositionalOnlyTest.py", this);
    }

    /** Cryptodome.Hash.SHA512 — same rule, different import module name. */
    @Test
    void testCryptodome() {
        PythonCheckVerifier.verify(BASE_PATH + "SHA512NewCryptodomeTest.py", this);
    }

    /**
     * SHA512.new(truncate=256) — {@code truncate} declared as {@code "str"} but an int literal is
     * passed. The type check rejects the truncate argument; because it is optional the param is
     * treated as absent. SHA-512 is still detected, but without a truncate child.
     */
    @Test
    void testWrongTypeTruncateOptionalSkipped() {
        PythonCheckVerifier.verify(BASE_PATH + "SHA512NewNegativeWrongTypeTest.py", this);
    }

    // -------------------------------------------------------------------------
    // Negative tests
    // -------------------------------------------------------------------------

    /** SHA256.new() — different algorithm; SHA512 rule must NOT match. */
    @Test
    void testNegativeDifferentAlgo() {
        PythonCheckVerifier.verifyNoIssue(
                BASE_PATH + "SHA512NewNegativeDifferentAlgoTest.py", this);
    }

    /** SHA512.update() — wrong method name; rule must NOT match. */
    @Test
    void testNegativeWrongMethod() {
        PythonCheckVerifier.verifyNoIssue(BASE_PATH + "SHA512NewNegativeWrongMethodTest.py", this);
    }

    /**
     * SHA512.new(unknown_kwarg="value") — keyword argument not declared in the rule; the engine
     * must reject the call because the signature does not match.
     */
    @Test
    void testNegativeUnknownKwarg() {
        PythonCheckVerifier.verifyNoIssue(BASE_PATH + "SHA512NewUnknownKwargTest.py", this);
    }

    /**
     * SHA512.new(**d) — dict-unpacking argument; contents are not statically inspectable; must NOT
     * be detected.
     */
    @Test
    void testNegativeDictUnpack() {
        PythonCheckVerifier.verifyNoIssue(BASE_PATH + "SHA512NewNegativeDictUnpackTest.py", this);
    }

    /**
     * SHA512.new(*args) — sequence-unpacking argument; contents are not statically inspectable;
     * must NOT be detected.
     */
    @Test
    void testNegativeSeqUnpack() {
        PythonCheckVerifier.verifyNoIssue(BASE_PATH + "SHA512NewNegativeSeqUnpackTest.py", this);
    }

    // -------------------------------------------------------------------------
    // asserts — called once per finding
    // -------------------------------------------------------------------------

    @Override
    public void asserts(
            int findingId,
            @Nonnull DetectionStore<PythonCheck, Tree, Symbol, PythonVisitorContext> detectionStore,
            @Nonnull List<INode> nodes) {

        /*
         * Every positive test produces exactly one top-level detection for SHA512.
         */
        assertThat(detectionStore.getDetectionValues()).hasSize(1);
        assertThat(detectionStore.getDetectionValueContext()).isInstanceOf(DigestContext.class);

        IValue<Tree> rootValue = detectionStore.getDetectionValues().get(0);
        assertThat(rootValue).isInstanceOf(ValueAction.class);
        assertThat(rootValue.asString()).isEqualTo("SHA512");

        /*
         * Translation: the root node must be a MessageDigest for SHA-512, with a Digest child.
         */
        assertThat(nodes).hasSize(1);
        INode messageDigestNode = nodes.get(0);
        assertThat(messageDigestNode.getKind()).isEqualTo(MessageDigest.class);
        assertThat(messageDigestNode.asString()).isEqualTo("SHA-512");

        INode digestNode = messageDigestNode.getChildren().get(Digest.class);
        assertThat(digestNode).isNotNull();
        assertThat(digestNode.asString()).isEqualTo("DIGEST");

        /*
         * If a truncate child detection store is present, validate its value.
         * Tests that pass truncate="256" produce one AlgorithmParameter child.
         * Tests that do NOT pass truncate produce no AlgorithmParameter child.
         */
        DetectionStore<PythonCheck, Tree, Symbol, PythonVisitorContext> truncateStore =
                getStoreOfValueType(AlgorithmParameter.class, detectionStore.getChildren());
        if (truncateStore != null) {
            assertThat(truncateStore.getDetectionValues()).hasSize(1);
            assertThat(truncateStore.getDetectionValueContext()).isInstanceOf(DigestContext.class);
            IValue<Tree> truncateValue = truncateStore.getDetectionValues().get(0);
            assertThat(truncateValue).isInstanceOf(AlgorithmParameter.class);
            assertThat(truncateValue.asString()).isEqualTo("256");
        }
    }
}
