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
package com.ibm.mapper.mapper.ssl;

import static org.assertj.core.api.Assertions.assertThat;

import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.Version;
import com.ibm.mapper.utils.DetectionLocation;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.Test;

public class SSLVersionMapperTest {

    @Test
    public void tlsv12IsParsedAsVersion1_2() {
        DetectionLocation testDetectionLocation =
                new DetectionLocation("testfile", 1, 1, List.of("test"), () -> "SSL");

        final SSLVersionMapper mapper = new SSLVersionMapper();
        final Optional<? extends INode> version = mapper.parse("TLSv1.2", testDetectionLocation);

        assertThat(version).isPresent();
        assertThat(version.get().is(Version.class)).isTrue();
        assertThat(version.get().asString()).isEqualTo("1.2");
    }

    @Test
    public void tlsv1WithoutPatchIsParsedAsVersion1_0() {
        DetectionLocation testDetectionLocation =
                new DetectionLocation("testfile", 1, 1, List.of("test"), () -> "SSL");

        final SSLVersionMapper mapper = new SSLVersionMapper();
        final Optional<? extends INode> version = mapper.parse("TLSv1", testDetectionLocation);

        assertThat(version).isPresent();
        assertThat(version.get().is(Version.class)).isTrue();
        assertThat(version.get().asString()).isEqualTo("1.0");
    }

    @Test
    public void tlsv13LowercaseIsParsedAsVersion1_3() {
        DetectionLocation testDetectionLocation =
                new DetectionLocation("testfile", 1, 1, List.of("test"), () -> "SSL");

        final SSLVersionMapper mapper = new SSLVersionMapper();
        final Optional<? extends INode> version = mapper.parse("tlsv1.3", testDetectionLocation);

        assertThat(version).isPresent();
        assertThat(version.get().is(Version.class)).isTrue();
        assertThat(version.get().asString()).isEqualTo("1.3");
    }

    @Test
    public void dtlsVersionIsParsedAsVersion() {
        DetectionLocation testDetectionLocation =
                new DetectionLocation("testfile", 1, 1, List.of("test"), () -> "SSL");

        final SSLVersionMapper mapper = new SSLVersionMapper();
        Optional<? extends INode> dtls12 = mapper.parse("DTLSv1.2", testDetectionLocation);
        assertThat(dtls12).isPresent();
        assertThat(dtls12.get().asString()).isEqualTo("1.2");

        Optional<? extends INode> dtls10 = mapper.parse("DTLSv1.0", testDetectionLocation);
        assertThat(dtls10).isPresent();
        assertThat(dtls10.get().asString()).isEqualTo("1.0");
    }

    @Test
    public void sslv3WithExplicitMinorIsParsedAsVersion3_0() {
        DetectionLocation testDetectionLocation =
                new DetectionLocation("testfile", 1, 1, List.of("test"), () -> "SSL");

        final SSLVersionMapper mapper = new SSLVersionMapper();
        Optional<? extends INode> sslv3 = mapper.parse("SSLv3.0", testDetectionLocation);
        assertThat(sslv3).isPresent();
        assertThat(sslv3.get().asString()).isEqualTo("3.0");
    }

    @Test
    public void sslv3WithoutMinorIsParsedAsVersion3_0() {
        DetectionLocation testDetectionLocation =
                new DetectionLocation("testfile", 1, 1, List.of("test"), () -> "SSL");

        final SSLVersionMapper mapper = new SSLVersionMapper();
        Optional<? extends INode> sslv3 = mapper.parse("SSLv3", testDetectionLocation);
        assertThat(sslv3).isPresent();
        assertThat(sslv3.get().asString()).isEqualTo("3.0");
    }

    @Test
    public void unknownFallbackStringReturnsEmpty() {
        DetectionLocation testDetectionLocation =
                new DetectionLocation("testfile", 1, 1, List.of("test"), () -> "SSL");

        final SSLVersionMapper mapper = new SSLVersionMapper();
        assertThat(mapper.parse("TLS-MIN-VERSION", testDetectionLocation)).isEmpty();
        assertThat(mapper.parse("TLS-MAX-VERSION", testDetectionLocation)).isEmpty();
    }
}
