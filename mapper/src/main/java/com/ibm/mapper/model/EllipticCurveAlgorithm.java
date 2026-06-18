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

import com.ibm.mapper.utils.DetectionLocation;
import javax.annotation.Nonnull;

public class EllipticCurveAlgorithm extends Algorithm
        implements PublicKeyEncryption, Signature, KeyAgreement {

    public EllipticCurveAlgorithm(@Nonnull EllipticCurve curve) {
        super("EC-" + curve.asString(), PublicKeyEncryption.class, curve.detectionLocation);
        this.put(curve);
        this.put(new Oid("1.2.840.10045.2.1", curve.detectionLocation));
    }

    public EllipticCurveAlgorithm(@Nonnull DetectionLocation detectionLocation) {
        super("EC", PublicKeyEncryption.class, detectionLocation);
        this.put(new Oid("1.2.840.10045.2.1", detectionLocation));
    }

    public EllipticCurveAlgorithm(
            @Nonnull final Class<? extends IPrimitive> asKind,
            @Nonnull EllipticCurveAlgorithm ellipticCurveAlgorithm) {
        super(ellipticCurveAlgorithm, asKind);
    }

    private EllipticCurveAlgorithm(@Nonnull EllipticCurveAlgorithm ellipticCurveAlgorithm) {
        super(ellipticCurveAlgorithm);
    }

    @Nonnull
    @Override
    protected EllipticCurveAlgorithm shallowCopy() {
        return new EllipticCurveAlgorithm(this);
    }
}
