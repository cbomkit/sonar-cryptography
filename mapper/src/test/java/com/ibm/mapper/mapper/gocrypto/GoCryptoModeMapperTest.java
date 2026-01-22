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
package com.ibm.mapper.mapper.gocrypto;

import static org.assertj.core.api.Assertions.assertThat;

import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.mode.CBC;
import com.ibm.mapper.model.mode.CFB;
import com.ibm.mapper.model.mode.CTR;
import com.ibm.mapper.model.mode.GCM;
import com.ibm.mapper.model.mode.OFB;
import com.ibm.mapper.utils.DetectionLocation;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.Test;

class GoCryptoModeMapperTest {

    private final DetectionLocation testDetectionLocation =
            new DetectionLocation("testfile", 1, 1, List.of("test"), () -> "GoCrypto");

    @Test
    void gcm() {
        GoCryptoModeMapper mapper = new GoCryptoModeMapper();
        Optional<? extends INode> result = mapper.parse("GCM", testDetectionLocation);

        assertThat(result).isPresent();
        assertThat(result.get()).isInstanceOf(GCM.class);
    }

    @Test
    void cbc() {
        GoCryptoModeMapper mapper = new GoCryptoModeMapper();
        Optional<? extends INode> result = mapper.parse("CBC", testDetectionLocation);

        assertThat(result).isPresent();
        assertThat(result.get()).isInstanceOf(CBC.class);
    }

    @Test
    void cfb() {
        GoCryptoModeMapper mapper = new GoCryptoModeMapper();
        Optional<? extends INode> result = mapper.parse("CFB", testDetectionLocation);

        assertThat(result).isPresent();
        assertThat(result.get()).isInstanceOf(CFB.class);
    }

    @Test
    void ctr() {
        GoCryptoModeMapper mapper = new GoCryptoModeMapper();
        Optional<? extends INode> result = mapper.parse("CTR", testDetectionLocation);

        assertThat(result).isPresent();
        assertThat(result.get()).isInstanceOf(CTR.class);
    }

    @Test
    void ofb() {
        GoCryptoModeMapper mapper = new GoCryptoModeMapper();
        Optional<? extends INode> result = mapper.parse("OFB", testDetectionLocation);

        assertThat(result).isPresent();
        assertThat(result.get()).isInstanceOf(OFB.class);
    }

    @Test
    void caseInsensitive() {
        GoCryptoModeMapper mapper = new GoCryptoModeMapper();

        assertThat(mapper.parse("gcm", testDetectionLocation)).isPresent();
        assertThat(mapper.parse("Gcm", testDetectionLocation)).isPresent();
        assertThat(mapper.parse("cbc", testDetectionLocation)).isPresent();
    }

    @Test
    void unknownMode() {
        GoCryptoModeMapper mapper = new GoCryptoModeMapper();
        Optional<? extends INode> result = mapper.parse("UNKNOWN", testDetectionLocation);

        assertThat(result).isEmpty();
    }

    @Test
    void nullInput() {
        GoCryptoModeMapper mapper = new GoCryptoModeMapper();
        Optional<? extends INode> result = mapper.parse(null, testDetectionLocation);

        assertThat(result).isEmpty();
    }
}
