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
package com.ibm.mapper.model.functionality;

import com.ibm.mapper.utils.DetectionLocation;
import javax.annotation.Nonnull;

public final class Digest extends Functionality {
    public Digest(@Nonnull DetectionLocation detectionLocation) {
        super(Digest.class, detectionLocation);
    }

    private Digest(@Nonnull Functionality functionality) {
        super(functionality);
    }

    @Nonnull
    @Override
    protected Digest copy() {
        return new Digest(this);
    }
}
