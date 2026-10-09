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
package com.ibm.mapper.model.padding;

import com.ibm.mapper.model.Padding;
import com.ibm.mapper.utils.DetectionLocation;
import javax.annotation.Nonnull;

public final class ANSIX923 extends Padding {

    private static final String NAME = "ANSI X9.23"; // ANSIX923, X9.23

    public ANSIX923(@Nonnull DetectionLocation detectionLocation) {
        super(NAME, detectionLocation);
    }

    private ANSIX923(@Nonnull ANSIX923 padding) {
        super(padding);
    }

    @Nonnull
    @Override
    protected ANSIX923 copy() {
        return new ANSIX923(this);
    }
}
