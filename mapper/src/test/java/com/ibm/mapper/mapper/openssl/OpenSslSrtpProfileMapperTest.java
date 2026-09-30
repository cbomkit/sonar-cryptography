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
package com.ibm.mapper.mapper.openssl;

import static org.assertj.core.api.Assertions.assertThat;

import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.collections.CipherSuiteCollection;
import com.ibm.mapper.utils.DetectionLocation;
import java.util.List;
import org.junit.jupiter.api.Test;

class OpenSslSrtpProfileMapperTest {

    private final DetectionLocation location =
            new DetectionLocation("testfile", 1, 1, List.of("test"), () -> "OpenSSL");
    private final OpenSslSrtpProfileMapper mapper = new OpenSslSrtpProfileMapper();

    @Test
    void profilesOpenSslAccepts() {
        INode srtp =
                mapper.parse("SRTP_AES128_CM_SHA1_80:BOGUS:SRTP_AEAD_AES_256_GCM", location)
                        .orElseThrow();
        assertThat(srtp.asString()).isEqualTo("SRTP");
        CipherSuiteCollection profiles =
                (CipherSuiteCollection) srtp.getChildren().get(CipherSuiteCollection.class);
        assertThat(profiles.getCollection())
                .extracting(INode::asString)
                .containsExactly("SRTP_AES128_CM_SHA1_80", "SRTP_AEAD_AES_256_GCM");
    }

    @Test
    void noKnownProfile() {
        assertThat(mapper.parse("BOGUS", location)).isEmpty();
        assertThat(mapper.parse(null, location)).isEmpty();
    }
}
