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
package com.ibm.mapper.reorganizer.rules;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

import com.ibm.mapper.model.BlockCipher;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.KeyLength;
import com.ibm.mapper.model.Mode;
import com.ibm.mapper.model.algorithms.AES;
import com.ibm.mapper.model.algorithms.DES;
import com.ibm.mapper.model.algorithms.DESede;
import com.ibm.mapper.model.mode.CBC;
import com.ibm.mapper.model.mode.ECB;
import com.ibm.mapper.reorganizer.Reorganizer;
import com.ibm.mapper.utils.DetectionLocation;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;

class BlockCipherReorganizerTest {

    private final DetectionLocation location = mock(DetectionLocation.class);

    @Test
    void equalBlockCiphersOfDifferentTreesAreEachMergedWithTheirChild() {
        // the encryption with a key of two possible lengths gives a tree per key length
        final AES first = new AES(new ECB(location), location);
        first.put(new AES(128, location));
        final AES second = new AES(new ECB(location), location);
        second.put(new AES(256, location));
        assertThat(first).isEqualTo(second);

        final List<INode> result =
                new Reorganizer(List.of(BlockCipherReorganizer.MERGE_BLOCK_CIPHER_PARENT_AND_CHILD))
                        .reorganize(new ArrayList<>(List.of(first, second)));

        assertThat(result)
                .extracting(INode::asString)
                .containsExactly("AES-128-ECB", "AES-256-ECB");
    }

    @Test
    void theParentKeepsItsNameAndTakesWhatTheChildHolds() {
        // DES_ede3_cbc_encrypt with key schedules set up by DES_set_key
        final DESede operation = new DESede(location);
        operation.put(new ECB(location));
        final DES keySetup = new DES(location);
        keySetup.put(new KeyLength(56, location));
        keySetup.put(new CBC(location));
        operation.put(keySetup);

        final List<INode> result =
                new Reorganizer(
                                List.of(
                                        BlockCipherReorganizer
                                                .MERGE_BLOCK_CIPHER_CHILD_INTO_PARENT))
                        .reorganize(new ArrayList<>(List.of(operation)));

        assertThat(result).singleElement().isSameAs(operation);
        assertThat(operation.hasChildOfType(BlockCipher.class)).isEmpty();
        assertThat(operation.hasChildOfType(Mode.class)).get().isInstanceOf(ECB.class);
        assertThat(operation.hasChildOfType(KeyLength.class).map(INode::asString)).contains("56");
    }

    @Test
    void theRetainedRootOfOverlappingRootsIsKept() {
        final AES retained = new AES(location);
        retained.put(new KeyLength(128, location));
        final AES removed = new AES(location);
        removed.put(new ECB(location));
        assertThat(retained).isEqualTo(removed);
        final List<INode> roots = new ArrayList<>(List.of(retained, removed));

        assertThat(
                        BlockCipherReorganizer.DEDUPLICATE_OVERLAPPING_ROOTS.match(
                                retained, null, roots))
                .isTrue();
        final List<INode> result =
                BlockCipherReorganizer.DEDUPLICATE_OVERLAPPING_ROOTS.applyReorganization(
                        retained, null, roots);

        assertThat(result).singleElement().isSameAs(retained);
        assertThat(retained.hasChildOfType(Mode.class)).isPresent();
        assertThat(retained.hasChildOfType(KeyLength.class)).isPresent();
    }
}
