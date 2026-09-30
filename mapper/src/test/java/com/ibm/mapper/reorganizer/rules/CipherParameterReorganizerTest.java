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

import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.algorithms.AES;
import com.ibm.mapper.model.functionality.Encrypt;
import com.ibm.mapper.reorganizer.Reorganizer;
import com.ibm.mapper.utils.DetectionLocation;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;

class CipherParameterReorganizerTest {

    private final DetectionLocation location = mock(DetectionLocation.class);

    @Test
    void anEncryptionIsMovedUnderItsCipher() {
        final Encrypt encrypt = new Encrypt(location);
        final AES cipher = new AES(128, location);
        encrypt.put(cipher);

        final List<INode> result =
                new Reorganizer(List.of(CipherParameterReorganizer.MOVE_ENCRYPT_UNDER_ITS_CIPHER))
                        .reorganize(new ArrayList<>(List.of(encrypt)));

        assertThat(result).singleElement().isSameAs(cipher);
        assertThat(cipher.hasChildOfType(Encrypt.class)).get().isSameAs(encrypt);
    }

    @Test
    void theEncryptionIsMovedInTheTreeOfItsRoot() {
        // an equal encryption of another tree comes before it among the roots
        final Encrypt first = new Encrypt(location);
        first.put(new AES(128, location));
        final Encrypt second = new Encrypt(location);
        final AES cipher = new AES(256, location);
        second.put(cipher);
        assertThat(first).isEqualTo(second);
        final List<INode> roots = new ArrayList<>(List.of(first, second));

        final List<INode> result =
                CipherParameterReorganizer.MOVE_ENCRYPT_UNDER_ITS_CIPHER.applyReorganization(
                        second, null, roots);

        assertThat(result).hasSize(2);
        assertThat(result.get(0)).isSameAs(first);
        assertThat(result.get(1)).isSameAs(cipher);
    }
}
