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
package com.ibm.mapper.model.mode;

import com.ibm.mapper.model.Mode;
import com.ibm.mapper.utils.DetectionLocation;
import javax.annotation.Nonnull;

public final class CFB extends Mode {

    /*
     * NOTE:
     * CFB/OFB with no specified value defaults to the block size of the algorithm.
     * (i.e. AES is 128; Blowfish, DES, DESede, and RC2 are 64.)
     */
    public CFB(@Nonnull DetectionLocation detectionLocation) {
        super("CFB", detectionLocation);
    }

    /*
     * NIST SP800-38A defines CFB with a bit-width.[28] The CFB mode also requires an integer
     * parameter, denoted s, such that 1 ≤ s ≤ b. In the specification of the CFB mode below,
     * each plaintext segment (Pj) and ciphertext segment (Cj) consists of s bits. The value
     * of s is sometimes incorporated into the name of the mode, e.g., the 1-bit CFB mode,
     * the 8-bit CFB mode, the 64-bit CFB mode, or the 128-bit CFB mode.
     */
    public CFB(int s, @Nonnull DetectionLocation detectionLocation) {
        super("CFB" + s, detectionLocation);
    }

    private CFB(@Nonnull CFB mode) {
        super(mode);
    }

    @Nonnull
    @Override
    protected Mode copy() {
        return new CFB(this);
    }
}
