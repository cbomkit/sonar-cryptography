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
package com.ibm.mapper.model.curves;

import com.ibm.mapper.model.EllipticCurve;
import com.ibm.mapper.utils.DetectionLocation;
import javax.annotation.Nonnull;

public final class Sect409r1 extends EllipticCurve {
    public Sect409r1(@Nonnull DetectionLocation detectionLocation) {
        super("sect409r1", detectionLocation);
    }

    private Sect409r1(@Nonnull Sect409r1 curve) {
        super(curve);
    }

    @Nonnull
    @Override
    protected Sect409r1 copy() {
        return new Sect409r1(this);
    }
}
