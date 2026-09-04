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
package com.ibm.plugin.rules.detection.nodecrypto;

/** Shared module and object type identifiers for Node.js built-in crypto APIs. */
final class NodeCryptoTypes {

    static final String CRYPTO = "crypto";
    static final String NODE_CRYPTO = "node:crypto";
    static final String TLS = "tls";
    static final String NODE_TLS = "node:tls";

    static final String HASH = "crypto.Hash";
    static final String HMAC = "crypto.Hmac";
    static final String CIPHER = "crypto.Cipher";
    static final String DECIPHER = "crypto.Decipher";
    static final String SIGN = "crypto.Sign";
    static final String VERIFY = "crypto.Verify";
    static final String DIFFIE_HELLMAN = "crypto.DiffieHellman";
    static final String ECDH = "crypto.ECDH";

    static final String BUNDLE = "NodeCrypto";

    private NodeCryptoTypes() {
        // utility
    }
}
