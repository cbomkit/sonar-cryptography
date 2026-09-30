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
package com.ibm.plugin.translation.translator.contexts;

import static org.assertj.core.api.Assertions.assertThat;

import com.ibm.engine.model.IValue;
import com.ibm.engine.model.ValueAction;
import com.ibm.engine.model.context.KeyDerivationFunctionContext;
import com.ibm.mapper.model.Algorithm;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.algorithms.ANSIX942;
import com.ibm.mapper.model.algorithms.ANSIX963;
import com.ibm.mapper.model.algorithms.Argon2;
import com.ibm.mapper.model.algorithms.ConcatenationKDF;
import com.ibm.mapper.model.algorithms.HKDF;
import com.ibm.mapper.model.algorithms.KDFCounter;
import com.ibm.mapper.model.algorithms.PBKDF1;
import com.ibm.mapper.model.algorithms.PBKDF2;
import com.ibm.mapper.model.algorithms.SSHKDF;
import com.ibm.mapper.model.algorithms.Scrypt;
import com.ibm.mapper.model.algorithms.TLSPRF;
import com.ibm.mapper.utils.DetectionLocation;
import com.sonar.cxx.sslr.api.AstNode;
import java.util.List;
import java.util.Optional;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

class CxxKeyDerivationFunctionContextTranslatorTest {

    private static final DetectionLocation TEST_LOCATION =
            new DetectionLocation("testfile", 1, 1, List.of("test"), () -> "OpenSSL");

    private final CxxKeyDerivationFunctionContextTranslator translator =
            new CxxKeyDerivationFunctionContextTranslator();

    /** Translates a name as passed to {@code EVP_KDF_fetch}. */
    private Optional<INode> translateFetchName(String name) {
        return translate(new com.ibm.engine.model.Algorithm<>(name, (AstNode) null));
    }

    private Optional<INode> translate(IValue<AstNode> value) {
        return translator.translate(
                () -> "OpenSSL", value, new KeyDerivationFunctionContext(), TEST_LOCATION);
    }

    private static Stream<Arguments> fetchNames() {
        return Stream.of(
                Arguments.of("PBKDF2", PBKDF2.class, "PBKDF2"),
                Arguments.of("1.2.840.113549.1.5.12", PBKDF2.class, "PBKDF2"),
                Arguments.of("PBKDF1", PBKDF1.class, "PBKDF1"),
                Arguments.of("HKDF", HKDF.class, "HKDF"),
                Arguments.of("HKDF-SHA256", HKDF.class, "HKDF-SHA-256"),
                Arguments.of("HKDF-SHA384", HKDF.class, "HKDF-SHA-384"),
                Arguments.of("HKDF-SHA512", HKDF.class, "HKDF-SHA-512"),
                Arguments.of("TLS13-KDF", HKDF.class, "HKDF"),
                Arguments.of("TLS1-PRF", TLSPRF.class, "TLS-PRF"),
                Arguments.of("SSKDF", ConcatenationKDF.class, "ConcatenationKDF"),
                Arguments.of("X963KDF", ANSIX963.class, "ANSI-KDF-X9.63"),
                Arguments.of("X942KDF-ASN1", ANSIX942.class, "ANSI-KDF-X9.42-ASN1"),
                Arguments.of("X942KDF", ANSIX942.class, "ANSI-KDF-X9.42-ASN1"),
                Arguments.of("X942KDF-CONCAT", ANSIX942.class, "ANSI-KDF-X9.42-CONCAT"),
                Arguments.of("KBKDF", KDFCounter.class, "SP800_108_CounterKDF"),
                Arguments.of("SSHKDF", SSHKDF.class, "SSHKDF"),
                Arguments.of("SCRYPT", Scrypt.class, "scrypt"),
                Arguments.of("id-scrypt", Scrypt.class, "scrypt"),
                Arguments.of("KRB5KDF", Algorithm.class, "KRB5KDF"),
                Arguments.of("ARGON2D", Argon2.class, "Argon2d"),
                Arguments.of("ARGON2I", Argon2.class, "Argon2i"),
                Arguments.of("ARGON2ID", Argon2.class, "Argon2id"),
                Arguments.of("PKCS12KDF", Algorithm.class, "PKCS12KDF"),
                Arguments.of("PVKKDF", Algorithm.class, "PVKKDF"),
                Arguments.of("HMAC-DRBG-KDF", Algorithm.class, "HMAC-DRBG-KDF"));
    }

    @ParameterizedTest
    @MethodSource("fetchNames")
    void fetchNameIsMapped(String name, Class<? extends INode> expectedClass, String expected) {
        Optional<INode> node = translateFetchName(name);
        assertThat(node).isPresent();
        assertThat(node.get()).isInstanceOf(expectedClass);
        assertThat(node.get().asString()).isEqualTo(expected);
    }

    @Test
    void fetchNameIsCaseInsensitive() {
        Optional<INode> node = translateFetchName("hkdf");
        assertThat(node).isPresent();
        assertThat(node.get()).isInstanceOf(HKDF.class);
    }

    @Test
    void pkcs5Pbkdf2HmacIsMappedToPbkdf2() {
        Optional<INode> node = translate(new ValueAction<>("PBKDF2-HMAC", (AstNode) null));
        assertThat(node).isPresent();
        assertThat(node.get()).isInstanceOf(PBKDF2.class);
        assertThat(node.get().asString()).isEqualTo("PBKDF2");
    }

    @Test
    void pkcs5Pbkdf2HmacSha1IsMappedToPbkdf2WithSha1() {
        Optional<INode> node = translate(new ValueAction<>("PBKDF2-HMAC-SHA1", (AstNode) null));
        assertThat(node).isPresent();
        assertThat(node.get()).isInstanceOf(PBKDF2.class);
        assertThat(node.get().asString()).isEqualTo("PBKDF2-SHA-1");
    }

    @Test
    void unknownAlgorithmNameResolvesToEmpty() {
        assertThat(translateFetchName("NOT-A-REAL-KDF")).isEmpty();
    }
}
