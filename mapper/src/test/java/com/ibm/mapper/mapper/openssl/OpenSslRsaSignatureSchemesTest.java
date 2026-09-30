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
package com.ibm.mapper.mapper.openssl;

import static org.assertj.core.api.Assertions.assertThat;

import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.Padding;
import com.ibm.mapper.model.Signature;
import com.ibm.mapper.model.algorithms.ANSIX931;
import com.ibm.mapper.model.algorithms.RSA;
import com.ibm.mapper.model.padding.PKCS1;
import com.ibm.mapper.utils.DetectionLocation;
import java.util.List;
import org.junit.jupiter.api.Test;

class OpenSslRsaSignatureSchemesTest {

    private final DetectionLocation location =
            new DetectionLocation("testfile", 1, 1, List.of("test"), () -> "OpenSSL");

    @Test
    void pkcs1v15() {
        final INode scheme = OpenSslRsaSignatureSchemes.pkcs1v15(location);
        assertThat(scheme).isInstanceOf(RSA.class);
        assertThat(scheme.getKind()).isEqualTo(Signature.class);
        assertThat(scheme.hasChildOfType(Padding.class)).get().isInstanceOf(PKCS1.class);
    }

    @Test
    void x931() {
        final INode scheme = OpenSslRsaSignatureSchemes.x931(location);
        assertThat(scheme).isInstanceOf(ANSIX931.class);
        assertThat(scheme.getKind()).isEqualTo(Signature.class);
    }

    @Test
    void withoutPadding() {
        final INode scheme = OpenSslRsaSignatureSchemes.withoutPadding(location);
        assertThat(scheme).isInstanceOf(RSA.class);
        assertThat(scheme.getKind()).isEqualTo(Signature.class);
        assertThat(scheme.hasChildOfType(Padding.class)).isEmpty();
    }

    @Test
    void theCipherAndSignatureMappersGiveTheSameScheme() {
        for (String padding : List.of("RSA-PKCS1", "RSA-X931")) {
            final INode fromCipher =
                    new OpenSslCipherMapper().parse(padding, location).orElseThrow();
            final INode fromSignature =
                    new OpenSslSignatureAlgorithmMapper().parse(padding, location).orElseThrow();
            assertThat(fromCipher.getClass()).as(padding).isEqualTo(fromSignature.getClass());
            assertThat(fromCipher.asString()).as(padding).isEqualTo(fromSignature.asString());
            assertThat(fromCipher.getKind()).as(padding).isEqualTo(Signature.class);
        }
    }
}
