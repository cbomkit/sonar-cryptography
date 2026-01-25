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

import com.ibm.mapper.model.MessageDigest;
import com.ibm.mapper.model.ProbabilisticSignatureScheme;
import com.ibm.mapper.model.Signature;
import com.ibm.mapper.model.algorithms.DSA;
import com.ibm.mapper.model.algorithms.ECDSA;
import com.ibm.mapper.model.algorithms.RSAssaPSS;
import com.ibm.mapper.model.algorithms.SHA;
import com.ibm.mapper.model.algorithms.SHA2;
import com.ibm.mapper.model.algorithms.SHA3;
import com.ibm.mapper.utils.DetectionLocation;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.Test;

class JcaSignatureMapperTest {

    @Test
    void NONEwithRSA() {
        DetectionLocation testDetectionLocation =
                new DetectionLocation("testfile", 1, 1, List.of("test"), () -> "SSL");

        JcaSignatureMapper jcaSignatureMapper = new JcaSignatureMapper();
        Optional<Signature> signatureOptional =
                jcaSignatureMapper.parse("NONEwithRSA", testDetectionLocation);

        assertThat(signatureOptional).isPresent();
        assertThat(signatureOptional.get().is(Signature.class)).isTrue();
        assertThat(signatureOptional.get().getFormat()).isEmpty();
        assertThat(signatureOptional.get().getDigest()).isEmpty();
    }

    @Test
    void SHA384withDSA() {
        DetectionLocation testDetectionLocation =
                new DetectionLocation("testfile", 1, 1, List.of("test"), () -> "SSL");

        JcaSignatureMapper jcaSignatureMapper = new JcaSignatureMapper();
        Optional<Signature> signatureOptional =
                jcaSignatureMapper.parse("SHA384withDSA", testDetectionLocation);

        assertThat(signatureOptional).isPresent();
        assertThat(signatureOptional.get()).isInstanceOf(DSA.class);
        assertThat(signatureOptional.get().getFormat()).isEmpty();

        assertThat(signatureOptional.get().getDigest()).isPresent();
        MessageDigest messageDigest = signatureOptional.get().getDigest().get();
        assertThat(messageDigest).isInstanceOf(SHA2.class);
        assertThat(messageDigest.getName()).isEqualTo("SHA-384");
        assertThat(messageDigest.getDigestSize()).isPresent();
        assertThat(messageDigest.getDigestSize().get().getValue()).isEqualTo(384);
    }

    @Test
    void SHA3_224withECDSA() {
        DetectionLocation testDetectionLocation =
                new DetectionLocation("testfile", 1, 1, List.of("test"), () -> "SSL");

        JcaSignatureMapper jcaSignatureMapper = new JcaSignatureMapper();
        Optional<Signature> signatureOptional =
                jcaSignatureMapper.parse("SHA3-224withECDSA", testDetectionLocation);

        assertThat(signatureOptional).isPresent();
        assertThat(signatureOptional.get()).isInstanceOf(ECDSA.class);
        assertThat(signatureOptional.get().getFormat()).isEmpty();

        assertThat(signatureOptional.get().getDigest()).isPresent();
        MessageDigest messageDigest = signatureOptional.get().getDigest().get();
        assertThat(messageDigest).isInstanceOf(SHA3.class);
        assertThat(messageDigest.getName()).isEqualTo("SHA-3-224");
        assertThat(messageDigest.getDigestSize()).isPresent();
        assertThat(messageDigest.getDigestSize().get().getValue()).isEqualTo(224);
    }

    @Test
    void SHA1withDSAinP1363Format() {
        DetectionLocation testDetectionLocation =
                new DetectionLocation("testfile", 1, 1, List.of("test"), () -> "SSL");

        JcaSignatureMapper jcaSignatureMapper = new JcaSignatureMapper();
        Optional<Signature> signatureOptional =
                jcaSignatureMapper.parse("SHA1withDSAinP1363Format", testDetectionLocation);

        assertThat(signatureOptional).isPresent();
        assertThat(signatureOptional.get()).isInstanceOf(DSA.class);
        assertThat(signatureOptional.get().getFormat()).isPresent();
        assertThat(signatureOptional.get().getFormat().get().getValue()).isEqualTo("P1363Format");

        assertThat(signatureOptional.get().getDigest()).isPresent();
        MessageDigest messageDigest = signatureOptional.get().getDigest().get();
        assertThat(messageDigest).isInstanceOf(SHA.class);
        assertThat(messageDigest.getName()).isEqualTo("SHA-1");
        assertThat(messageDigest.getDigestSize()).isPresent();
        assertThat(messageDigest.getDigestSize().get().getValue()).isEqualTo(160);
    }

    @Test
    void RSASSA_PSS() {
        DetectionLocation testDetectionLocation =
                new DetectionLocation("testfile", 1, 1, List.of("test"), () -> "SSL");

        JcaSignatureMapper jcaSignatureMapper = new JcaSignatureMapper();
        Optional<Signature> signatureOptional =
                jcaSignatureMapper.parse("RSASSA-PSS", testDetectionLocation);

        assertThat(signatureOptional).isPresent();
        assertThat(signatureOptional.get()).isInstanceOf(RSAssaPSS.class);
        assertThat(signatureOptional.get().is(ProbabilisticSignatureScheme.class)).isTrue();
        assertThat(signatureOptional.get().getName()).isEqualTo("RSA-PSS");
        assertThat(signatureOptional.get().getFormat()).isEmpty();
    }
}
