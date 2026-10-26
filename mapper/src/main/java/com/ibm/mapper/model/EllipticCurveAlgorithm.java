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

import com.ibm.mapper.model.curves.Curve25519;
import com.ibm.mapper.model.curves.Curve448;
import com.ibm.mapper.model.curves.Edwards25519;
import com.ibm.mapper.model.curves.Edwards448;
import com.ibm.mapper.utils.DetectionLocation;
import java.util.Optional;
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

    /**
     * Montgomery curves are used for ECDH and Edwards curves for EdDSA; any other curve follows the
     * kind it is used as. Plain EC encryption has no standardized family.
     */
    @Nonnull
    @Override
    public Optional<AlgorithmFamily> getFamily() {
        final INode curve = this.children.get(EllipticCurve.class);
        if (curve instanceof Curve25519 || curve instanceof Curve448) {
            return Optional.of(AlgorithmFamily.ECDH);
        } else if (curve instanceof Edwards25519 || curve instanceof Edwards448) {
            return Optional.of(AlgorithmFamily.EDDSA);
        } else if (this.is(Signature.class)) {
            return Optional.of(AlgorithmFamily.ECDSA);
        } else if (this.is(KeyAgreement.class)) {
            return Optional.of(AlgorithmFamily.ECDH);
        }
        return Optional.empty();
    }
}
