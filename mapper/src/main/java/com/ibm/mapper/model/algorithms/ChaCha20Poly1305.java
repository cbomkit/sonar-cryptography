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
import com.ibm.mapper.model.AuthenticatedEncryption;
import com.ibm.mapper.utils.DetectionLocation;
import javax.annotation.Nonnull;

/**
 *
 *
 * <h2>ChaCha20-Poly1305</h2>
 *
 * <p>
 *
 * <h3>Specification</h3>
 *
 * <ul>
 *   <li>https://datatracker.ietf.org/doc/html/rfc8439
 *   <li>https://cyclonedx.org/schema/cryptography-defs.json (algorithmName: ChaCha20-Poly1305)
 * </ul>
 */
public final class ChaCha20Poly1305 extends Algorithm implements AuthenticatedEncryption {

    @Override
    public @Nonnull String asString() {
        return "ChaCha20-Poly1305";
    }

    public ChaCha20Poly1305(@Nonnull DetectionLocation detectionLocation) {
        super(new ChaCha20(detectionLocation), AuthenticatedEncryption.class);
        this.put(new Poly1305(detectionLocation));
    }
}
