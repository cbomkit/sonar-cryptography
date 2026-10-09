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

import com.ibm.mapper.model.KeyDerivationFunction;
import com.ibm.mapper.model.PasswordBasedKeyDerivationFunction;
import com.ibm.mapper.model.algorithms.Argon2;
import com.ibm.mapper.model.algorithms.HKDF;
import com.ibm.mapper.model.algorithms.HMACDRBGKDF;
import com.ibm.mapper.model.algorithms.KRB5KDF;
import com.ibm.mapper.model.algorithms.PBKDF2;
import com.ibm.mapper.model.algorithms.PKCS12KDF;
import com.ibm.mapper.model.algorithms.PKCS12PBE;
import com.ibm.mapper.model.algorithms.PVKKDF;
import com.ibm.mapper.utils.DetectionLocation;
import java.util.List;
import org.junit.jupiter.api.Test;

class OpenSslKdfMapperTest {

    private final DetectionLocation location =
            new DetectionLocation("testfile", 1, 1, List.of("test"), () -> "OpenSSL");
    private final OpenSslKdfMapper mapper = new OpenSslKdfMapper();

    @Test
    void namesAcceptedByEvpKdfFetch() {
        assertThat(mapper.parse("pbkdf2", location).orElseThrow()).isInstanceOf(PBKDF2.class);
        assertThat(mapper.parse("HKDF-SHA256", location).orElseThrow()).isInstanceOf(HKDF.class);
        assertThat(mapper.parse("HKDF-SHA256", location).orElseThrow().asString())
                .isEqualTo("HKDF-SHA-256");
        assertThat(mapper.parse("ARGON2ID", location).orElseThrow().asString())
                .isEqualTo("Argon2id");
        assertThat(mapper.parse("ARGON2ID", location).orElseThrow()).isInstanceOf(Argon2.class);
    }

    @Test
    void kdfsWithTheirOwnModel() {
        assertThat(mapper.parse("PKCS12KDF", location).orElseThrow()).isInstanceOf(PKCS12KDF.class);
        assertThat(mapper.parse("PKCS12KDF", location).orElseThrow().getKind())
                .isEqualTo(PasswordBasedKeyDerivationFunction.class);
        assertThat(mapper.parse("PVKKDF", location).orElseThrow()).isInstanceOf(PVKKDF.class);
        assertThat(mapper.parse("KRB5KDF", location).orElseThrow()).isInstanceOf(KRB5KDF.class);
        assertThat(mapper.parse("HMAC-DRBG-KDF", location).orElseThrow())
                .isInstanceOf(HMACDRBGKDF.class);
        assertThat(mapper.parse("HMAC-DRBG-KDF", location).orElseThrow().getKind())
                .isEqualTo(KeyDerivationFunction.class);
    }

    @Test
    void passwordBasedEncryptionSchemes() {
        assertThat(mapper.parse("PBE-SHA1-3DES", location).orElseThrow())
                .isInstanceOf(PKCS12PBE.class);
    }

    @Test
    void noKdfAndUnknownNames() {
        assertThat(mapper.parse("NONE", location)).isEmpty();
        assertThat(mapper.parse("XYZ", location)).isEmpty();
        assertThat(mapper.parse(null, location)).isEmpty();
    }
}
