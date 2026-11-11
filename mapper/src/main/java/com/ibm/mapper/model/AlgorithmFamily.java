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
package com.ibm.mapper.model;

/**
 * Canonical family of a cryptographic algorithm, independent of any output format. Algorithms
 * report their family through {@link IAlgorithm#getFamily()}, derived from their kind and
 * parameters where the family depends on them (for example RSA used for encryption versus signing).
 * Output formats translate a family to their own identifier.
 */
public enum AlgorithmFamily {
    AES,
    ARIA,
    BLAKE2,
    BLAKE3,
    BLOWFISH,
    CAMELLIA,
    CAST5,
    CAST6,
    CHACHA20,
    CMAC,
    DES,
    DSA,
    ECDH,
    ECDSA,
    ECIES,
    EDDSA,
    ELGAMAL,
    FFDH,
    HC,
    HKDF,
    HMAC,
    IDEA,
    LMS,
    MD2,
    MD4,
    MD5,
    ML_DSA,
    ML_KEM,
    MQV,
    PBES1,
    PBES2,
    PBKDF1,
    PBKDF2,
    POLY1305,
    RC2,
    RC4,
    RC5,
    RC6,
    RIPEMD,
    RSAES_OAEP,
    RSAES_PKCS1,
    RSASSA_PKCS1,
    RSASSA_PSS,
    SALSA20,
    SCRYPT,
    SEED,
    SERPENT,
    SHA1,
    SHA2,
    SHA3,
    SIPHASH,
    SKIPJACK,
    SLH_DSA,
    SM2,
    SM3,
    SM4,
    SP800_108,
    SRP,
    TRIPLE_DES,
    TWOFISH,
    WHIRLPOOL,
    XMSS,
    ZUC
}
