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
package com.ibm.mapper.model.algorithms.ascon;

import com.ibm.mapper.model.AuthenticatedEncryption;
import com.ibm.mapper.model.BlockSize;
import com.ibm.mapper.model.KeyLength;
import com.ibm.mapper.model.NonceLength;
import com.ibm.mapper.model.TagLength;
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
 * </ul>
 *
 * <h3>Other Names and Related Standards</h3>
 *
 * <ul>
 *   *
 * </ul>
 */
public final class Ascon128 extends Ascon implements AuthenticatedEncryption {
    private static final String NAME = "Ascon-128";

    public Ascon128(@Nonnull DetectionLocation detectionLocation) {
        super(NAME, AuthenticatedEncryption.class, detectionLocation);
        this.put(KeyLength.ofDefault(128, detectionLocation));
        this.put(new NonceLength(128, detectionLocation));
        this.put(new TagLength(128, detectionLocation));
        this.put(BlockSize.ofDefault(64, detectionLocation));
    }
}
