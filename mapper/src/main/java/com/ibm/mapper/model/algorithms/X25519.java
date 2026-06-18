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
import com.ibm.mapper.model.KeyAgreement;
import com.ibm.mapper.model.Oid;
import com.ibm.mapper.model.curves.Curve25519;
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
public final class X25519 extends Algorithm implements KeyAgreement {
    private static final String NAME = "x25519";

    public X25519(@Nonnull DetectionLocation detectionLocation) {
        super(NAME, KeyAgreement.class, detectionLocation);
        this.put(new Curve25519(detectionLocation));
        this.put(new Oid("1.3.101.110", detectionLocation));
    }

    private X25519(@Nonnull X25519 x25519) {
        super(x25519);
    }

    @Nonnull
    @Override
    protected X25519 shallowCopy() {
        return new X25519(this);
    }
}
