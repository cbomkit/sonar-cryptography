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
package com.ibm.mapper.mapper.jca;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.ibm.mapper.mapper.bc.BcBlockCipherEngineMapper;
import com.ibm.mapper.mapper.bc.BcBlockCipherModeMapper;
import com.ibm.mapper.model.Algorithm;
import com.ibm.mapper.model.BlockCipher;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.reorganizer.IReorganizerRule;
import com.ibm.mapper.reorganizer.rules.BlockCipherReorganizer;
import com.ibm.mapper.utils.DetectionLocation;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class BlockCipherReorganizerTest {

    private final DetectionLocation SHARED_LOCATION_CONTEXT = mock(DetectionLocation.class);
    private final INode DUMMY_PARENT = mock(INode.class);

    @Test
    @DisplayName(
            "Issue #295: Should successfully deduplicate real nodes generated from AESFastEngine and SICBlockCipher")
    void shouldDeduplicateRealBouncyCastleEngineAndModeNodes() {
        IReorganizerRule rule = BlockCipherReorganizer.DEDUPLICATE_OVERLAPPING_ROOTS;

        BcBlockCipherEngineMapper engineMapper = new BcBlockCipherEngineMapper(BlockCipher.class);
        BcBlockCipherModeMapper modeMapper = new BcBlockCipherModeMapper();

        INode aesNode =
                engineMapper
                        .parse("AESFastEngine", SHARED_LOCATION_CONTEXT)
                        .orElseThrow(
                                () ->
                                        new IllegalStateException(
                                                "Engine mapper failed to translate AESFastEngine"));

        INode aesCtrNode =
                modeMapper
                        .parse("SICBlockCipher", SHARED_LOCATION_CONTEXT)
                        .orElseThrow(
                                () ->
                                        new IllegalStateException(
                                                "Mode mapper failed to translate SICBlockCipher"));

        List<INode> roots = new ArrayList<>(List.of(aesNode, aesCtrNode));

        boolean isMatch = rule.match(aesNode, DUMMY_PARENT, roots);
        assertThat(isMatch)
                .as(
                        "The rule should detect that AESFastEngine and SICBlockCipher create overlapping roots")
                .isTrue();

        List<INode> optimizedRoots = rule.applyReorganization(aesNode, DUMMY_PARENT, roots);

        assertThat(optimizedRoots).hasSize(1);

        Algorithm remainingAlg = (Algorithm) optimizedRoots.get(0);
        assertThat(remainingAlg.getName()).isEqualTo("AES");
        assertThat(remainingAlg.getChildren()).isNotEmpty();
    }

    @Test
    @DisplayName(
            "Unit Test: Should merge parent and child BlockCipher nodes when the analyzer provides them as a nested tree")
    void shouldMergeNestedParentAndChildBlockCipherNodes() {
        IReorganizerRule rule = BlockCipherReorganizer.MERGE_BLOCK_CIPHER_PARENT_AND_CHILD;

        BcBlockCipherEngineMapper engineMapper = new BcBlockCipherEngineMapper(BlockCipher.class);
        BcBlockCipherModeMapper modeMapper = new BcBlockCipherModeMapper();

        INode parentNode =
                modeMapper
                        .parse("SICBlockCipher", SHARED_LOCATION_CONTEXT)
                        .orElseThrow(() -> new IllegalStateException("Mode mapper failed"));

        INode childNode =
                engineMapper
                        .parse("AESFastEngine", SHARED_LOCATION_CONTEXT)
                        .orElseThrow(() -> new IllegalStateException("Engine mapper failed"));

        parentNode.put(childNode);

        List<INode> roots = new ArrayList<>(List.of(parentNode));

        boolean isMatch = rule.match(parentNode, DUMMY_PARENT, roots);
        List<INode> optimizedRoots = rule.applyReorganization(parentNode, DUMMY_PARENT, roots);

        assertThat(isMatch)
                .as("The rule should detect the nested BlockCipher -> BlockCipher relationship")
                .isTrue();

        assertThat(optimizedRoots).hasSize(1);

        INode mergedNode = optimizedRoots.get(0);

        assertThat(mergedNode).isInstanceOf(Algorithm.class);
        assertThat(mergedNode.is(BlockCipher.class)).isTrue();

        assertThat(mergedNode.getChildren())
                .as(
                        "The merged node should retain the inner child properties (like Mode and KeyLength)")
                .isNotEmpty();
    }

    @Test
    @DisplayName(
            "Edge Case: Should safely iterate and deduplicate 3+ overlapping roots into a single node")
    void shouldDeduplicateMultipleOverlappingRoots() {
        IReorganizerRule rule = BlockCipherReorganizer.DEDUPLICATE_OVERLAPPING_ROOTS;

        Algorithm unknownWrapper = mock(Algorithm.class);
        when(unknownWrapper.getName()).thenReturn("Unknown");
        when(unknownWrapper.getDetectionContext()).thenReturn(SHARED_LOCATION_CONTEXT);

        Algorithm aesBase = mock(Algorithm.class);
        when(aesBase.getName()).thenReturn("AES");
        when(aesBase.getDetectionContext()).thenReturn(SHARED_LOCATION_CONTEXT);

        Algorithm aesSpecific = mock(Algorithm.class);
        when(aesSpecific.getName()).thenReturn("AES-256");
        when(aesSpecific.getDetectionContext()).thenReturn(SHARED_LOCATION_CONTEXT);

        List<INode> roots = new ArrayList<>(List.of(unknownWrapper, aesBase, aesSpecific));

        boolean isMatch = rule.match(unknownWrapper, DUMMY_PARENT, roots);
        List<INode> optimizedRoots = rule.applyReorganization(unknownWrapper, DUMMY_PARENT, roots);

        assertThat(isMatch).isTrue();
        assertThat(optimizedRoots).hasSize(1);

        Algorithm remainingAlg = (Algorithm) optimizedRoots.get(0);
        assertThat(remainingAlg.getName()).isEqualTo("AES-256");
    }

    @Test
    @DisplayName("Edge Case: Should NOT merge ambiguous prefixes like RC2 and RC256")
    void shouldNotMergeAmbiguousPrefixes() {
        IReorganizerRule rule = BlockCipherReorganizer.DEDUPLICATE_OVERLAPPING_ROOTS;

        Algorithm rc2 = mock(Algorithm.class);
        when(rc2.getName()).thenReturn("RC2");
        when(rc2.getDetectionContext()).thenReturn(SHARED_LOCATION_CONTEXT);

        Algorithm rc256 = mock(Algorithm.class);
        when(rc256.getName()).thenReturn("RC256");
        when(rc256.getDetectionContext()).thenReturn(SHARED_LOCATION_CONTEXT);

        List<INode> roots = new ArrayList<>(List.of(rc2, rc256));

        boolean isMatch = rule.match(rc2, DUMMY_PARENT, roots);

        assertThat(isMatch).isFalse();
    }

    @Test
    @DisplayName("Edge Case: Should handle empty strings and distinct case-sensitivity safely")
    void shouldHandleEmptyStringsAndCasing() {
        IReorganizerRule rule = BlockCipherReorganizer.DEDUPLICATE_OVERLAPPING_ROOTS;

        Algorithm emptyNode = mock(Algorithm.class);
        when(emptyNode.getName()).thenReturn("   "); // Blank spaces
        when(emptyNode.getDetectionContext()).thenReturn(SHARED_LOCATION_CONTEXT);

        Algorithm lowerCaseAes = mock(Algorithm.class);
        when(lowerCaseAes.getName()).thenReturn("aes"); // Lowercase
        when(lowerCaseAes.getDetectionContext()).thenReturn(SHARED_LOCATION_CONTEXT);

        List<INode> roots = new ArrayList<>(List.of(emptyNode, lowerCaseAes));

        boolean isMatch = rule.match(emptyNode, DUMMY_PARENT, roots);
        List<INode> optimizedRoots = rule.applyReorganization(emptyNode, DUMMY_PARENT, roots);

        assertThat(isMatch).isTrue();
        assertThat(optimizedRoots).hasSize(1);
        assertThat(((Algorithm) optimizedRoots.get(0)).getName()).isEqualTo("aes");
    }
}
