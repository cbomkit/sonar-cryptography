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
package com.ibm.mapper.model.algorithms;

import com.ibm.mapper.model.Algorithm;
import com.ibm.mapper.model.KeyEncapsulationMechanism;
import com.ibm.mapper.utils.DetectionLocation;
import javax.annotation.Nonnull;

/**
 *
 *
 * <h2>{@value #NAME}</h2>
 *
 * <p>Hybrid post-quantum key encapsulation mechanism combining ECDH P-256 (secp256r1, NIST P-256)
 * with ML-KEM-768 (post-quantum KEM).
 *
 * <p>TLS Named Group: 0x11EB
 *
 * <p>Also known as SecP256r1Kyber768Draft00 (earlier draft name). Provides quantum-safe key
 * exchange for TLS 1.3.
 */
public final class SecP256r1MLKEM768 extends Algorithm implements KeyEncapsulationMechanism {

    private static final String NAME = "SecP256r1MLKEM768";

    public SecP256r1MLKEM768(@Nonnull DetectionLocation detectionLocation) {
        super(NAME, KeyEncapsulationMechanism.class, detectionLocation);
    }
}
