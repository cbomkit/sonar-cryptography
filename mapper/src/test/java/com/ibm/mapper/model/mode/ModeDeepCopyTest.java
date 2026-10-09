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
package com.ibm.mapper.model.mode;

import static org.assertj.core.api.Assertions.assertThat;

import com.ibm.mapper.model.BlockSize;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.Mode;
import com.ibm.mapper.utils.DetectionLocation;
import java.util.List;
import org.junit.jupiter.api.Test;

class ModeDeepCopyTest {

    static final DetectionLocation TEST =
            new DetectionLocation("testfile", 1, 1, List.of("test"), () -> "TEST");

    @Test
    void aCopyIsOfTheSameModeClass() {
        final List<Mode> modes =
                List.of(
                        new CBC(TEST),
                        new CCM(TEST),
                        new CFB(TEST),
                        new CFB(8, TEST),
                        new CNT(TEST),
                        new CTR(TEST),
                        new CTS(TEST),
                        new EAX(TEST),
                        new ECB(TEST),
                        new GCM(TEST),
                        new GCMSIV(TEST),
                        new GMAC(TEST),
                        new KW(TEST),
                        new KWP(TEST),
                        new MGM(TEST),
                        new OCB(TEST),
                        new OFB(TEST),
                        new OFB(8, TEST),
                        new PCBC(TEST),
                        new SIV(TEST),
                        new XTS(TEST),
                        new Mode("IGE", TEST));
        for (Mode mode : modes) {
            final INode copy = mode.deepCopy();
            assertThat(copy).as(mode.asString()).isExactlyInstanceOf(mode.getClass());
            assertThat(copy.asString()).isEqualTo(mode.asString());
            assertThat(copy.getKind()).isEqualTo(Mode.class);
        }
    }

    @Test
    void aCopyHasItsOwnChildren() {
        final BlockSize blockSize = new BlockSize(64, TEST);
        final Mode cfb = new CFB(TEST);
        cfb.put(blockSize);

        final INode copy = cfb.deepCopy();

        assertThat(cfb.getChildren().get(BlockSize.class)).isSameAs(blockSize);
        assertThat(copy.getChildren().get(BlockSize.class))
                .isNotSameAs(blockSize)
                .isEqualTo(blockSize);
        copy.removeChildOfType(BlockSize.class);
        assertThat(cfb.getChildren()).containsKey(BlockSize.class);
    }
}
