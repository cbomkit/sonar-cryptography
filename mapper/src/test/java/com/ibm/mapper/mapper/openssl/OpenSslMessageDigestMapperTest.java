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

import com.ibm.mapper.model.DigestSize;
import com.ibm.mapper.model.MessageDigest;
import com.ibm.mapper.model.algorithms.MD5SHA1;
import com.ibm.mapper.model.algorithms.MDC2;
import com.ibm.mapper.model.algorithms.SHA2;
import com.ibm.mapper.model.algorithms.shake.SHAKE;
import com.ibm.mapper.utils.DetectionLocation;
import java.util.List;
import org.junit.jupiter.api.Test;

class OpenSslMessageDigestMapperTest {

    private final DetectionLocation location =
            new DetectionLocation("testfile", 1, 1, List.of("test"), () -> "OpenSSL");
    private final OpenSslMessageDigestMapper mapper = new OpenSslMessageDigestMapper();

    @Test
    void namesSharedWithTheJca() {
        assertThat(mapper.parse("SHA256", location).orElseThrow()).isInstanceOf(SHA2.class);
    }

    @Test
    void openSslOnlyDigests() {
        assertThat(mapper.parse("shake128", location).orElseThrow()).isInstanceOf(SHAKE.class);
        MessageDigest mdc2 = mapper.parse("MDC2", location).orElseThrow();
        assertThat(mdc2).isInstanceOf(MDC2.class);
        assertThat(mdc2.getChildren().get(DigestSize.class).asString()).isEqualTo("128");
    }

    @Test
    void theConcatenatedTlsDigest() {
        MessageDigest md5Sha1 = mapper.parse("MD5-SHA1", location).orElseThrow();
        assertThat(md5Sha1).isInstanceOf(MD5SHA1.class);
        assertThat(md5Sha1.asString()).isEqualTo("MD5-SHA1");
        assertThat(md5Sha1.getChildren().get(DigestSize.class).asString()).isEqualTo("288");
    }

    @Test
    void theNullDigestAndUnknownNames() {
        assertThat(mapper.parse("NULL", location)).isEmpty();
        assertThat(mapper.parse("XYZ", location)).isEmpty();
        assertThat(mapper.parse(null, location)).isEmpty();
    }
}
