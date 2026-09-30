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
import com.ibm.mapper.model.IPrimitive;
import com.ibm.mapper.model.Mac;
import com.ibm.mapper.utils.DetectionLocation;
import javax.annotation.Nonnull;

/**
 *
 *
 * <h2>{@value #NAME}</h2>
 *
 * <p>Galois message authentication code: the authentication-only use of the GCM mode of a block
 * cipher. A GMAC whose cipher is known is reported as that cipher in {@link
 * com.ibm.mapper.model.mode.GMAC} mode (e.g. {@code AES-128-GMAC}); this node stands for a GMAC
 * whose cipher is not known.
 *
 * <h3>Specification</h3>
 *
 * <ul>
 *   <li>https://doi.org/10.6028/NIST.SP.800-38D
 *   <li>https://cyclonedx.org/schema/cryptography-defs.json (pattern: AES[-(128|192|256)][-GMAC])
 * </ul>
 *
 * <h3>Other Names and Related Standards</h3>
 *
 * <ul>
 *   <li>NIST SP 800-38D
 * </ul>
 */
public final class GMAC extends Algorithm implements Mac {

    public static final String NAME = "GMAC";

    public GMAC(@Nonnull DetectionLocation detectionLocation) {
        super(NAME, Mac.class, detectionLocation);
    }

    private GMAC(@Nonnull GMAC algorithm) {
        super(algorithm);
    }

    @Nonnull
    @Override
    protected GMAC copy() {
        return new GMAC(this);
    }

    public GMAC(@Nonnull final Class<? extends IPrimitive> asKind, @Nonnull GMAC gmac) {
        super(gmac, asKind);
    }

    @Nonnull
    @Override
    public GMAC asKind(@Nonnull Class<? extends IPrimitive> kind) {
        return new GMAC(kind, this);
    }
}
