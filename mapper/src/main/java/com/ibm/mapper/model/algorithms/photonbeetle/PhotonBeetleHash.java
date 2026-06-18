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
package com.ibm.mapper.model.algorithms.photonbeetle;

import com.ibm.mapper.model.Algorithm;
import com.ibm.mapper.model.BlockSize;
import com.ibm.mapper.model.DigestSize;
import com.ibm.mapper.model.MessageDigest;
import com.ibm.mapper.utils.DetectionLocation;
import javax.annotation.Nonnull;

/**
 *
 *
 * <h2>{@value #NAME}</h2>
 *
 * <p>
 *
 * <h3>Specification</h3>
 *
 * <ul>
 *   <li>https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/round-2/spec-doc-rnd2/photon-beetle-spec-round2.pdf
 * </ul>
 *
 * <h3>Other Names and Related Standards</h3>
 *
 * <ul>
 * </ul>
 */
public class PhotonBeetleHash extends Algorithm implements MessageDigest {

    private static final String NAME = "PHOTON-Beetle-Hash";

    public PhotonBeetleHash(@Nonnull DetectionLocation detectionLocation) {
        super(NAME, MessageDigest.class, detectionLocation);
        this.put(new DigestSize(256, detectionLocation));
    }

    public PhotonBeetleHash(int blockSize, @Nonnull DetectionLocation detectionLocation) {
        this(detectionLocation);
        this.put(new BlockSize(blockSize, detectionLocation));
    }

    private PhotonBeetleHash(@Nonnull PhotonBeetleHash photonBeetleHash) {
        super(photonBeetleHash);
    }

    @Nonnull
    @Override
    protected PhotonBeetleHash shallowCopy() {
        return new PhotonBeetleHash(this);
    }
}
