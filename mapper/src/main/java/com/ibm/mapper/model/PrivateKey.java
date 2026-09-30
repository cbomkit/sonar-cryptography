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

import javax.annotation.Nonnull;

public final class PrivateKey extends Key {
    public PrivateKey(@Nonnull PublicKeyEncryption publicKeyEncryption) {
        super(publicKeyEncryption, PrivateKey.class);
    }

    public PrivateKey(@Nonnull Signature signature) {
        super(signature, PrivateKey.class);
    }

    public PrivateKey(@Nonnull Key key) {
        super(key, key.detectionLocation, PrivateKey.class);
    }

    private PrivateKey(@Nonnull PrivateKey key) {
        super(key);
    }

    @Nonnull
    @Override
    protected PrivateKey copy() {
        return new PrivateKey(this);
    }
}
