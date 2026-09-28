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

import com.ibm.mapper.model.Signature;
import com.ibm.mapper.model.algorithms.ANSIX931;
import com.ibm.mapper.model.algorithms.RSA;
import com.ibm.mapper.model.padding.PKCS1;
import com.ibm.mapper.utils.DetectionLocation;
import javax.annotation.Nonnull;

/**
 * The RSA signature schemes selected by an OpenSSL RSA padding, shared by the cipher and signature
 * translators: the padding of RSA_private_encrypt or EVP_PKEY_CTX_set_rsa_padding names a signature
 * scheme when it is PKCS#1 v1.5 type 1 or ANSI X9.31.
 */
final class CxxRsaSignatureSchemes {

    private CxxRsaSignatureSchemes() {
        // private
    }

    /** RSA signatures with PKCS#1 v1.5 (type 1) padding. */
    @Nonnull
    static RSA pkcs1v15(@Nonnull DetectionLocation detectionLocation) {
        final RSA rsa = new RSA(Signature.class, new RSA(detectionLocation));
        rsa.put(new PKCS1(detectionLocation));
        return rsa;
    }

    /** RSA signatures with ANSI X9.31 padding. */
    @Nonnull
    static ANSIX931 x931(@Nonnull DetectionLocation detectionLocation) {
        return new ANSIX931(detectionLocation);
    }

    /** RSA signatures without padding. */
    @Nonnull
    static RSA withoutPadding(@Nonnull DetectionLocation detectionLocation) {
        return new RSA(Signature.class, new RSA(detectionLocation));
    }
}
