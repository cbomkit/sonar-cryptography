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
package com.ibm.plugin.rules.detection.openssl.cipher;

import com.ibm.plugin.CxxAggregator;
import com.ibm.plugin.CxxVerifier;
import com.ibm.plugin.rules.CxxInventoryRule;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

/**
 * A key length set on a cipher context ({@code EVP_CIPHER_CTX_set_key_length}) is the key length of
 * a cipher whose key length is variable; OpenSSL refuses it for a cipher whose key length is fixed,
 * which keeps the key length its name gives.
 */
class OpenSSLEvpCipherKeyLengthTest {

    @AfterEach
    void resetSharedState() {
        CxxAggregator.reset();
    }

    @Test
    void test() {
        CxxVerifier.verify(
                "rules/detection/openssl/cipher/OpenSSLEvpCipherKeyLengthTestFile.cc",
                new CxxInventoryRule());
    }
}
