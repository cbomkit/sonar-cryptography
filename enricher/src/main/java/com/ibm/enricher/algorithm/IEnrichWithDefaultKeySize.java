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
package com.ibm.enricher.algorithm;

import com.ibm.mapper.model.IAsset;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.KeyLength;
import com.ibm.mapper.model.NodeOrigin;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;

public interface IEnrichWithDefaultKeySize {

    default void applyDefaultKeySizeForJca(@Nonnull IAsset asset, int defaultKeySize) {
        @Nullable INode keyLength = asset.hasChildOfType(KeyLength.class).orElse(null);
        // default key length
        if (keyLength == null
                && asset.getDetectionContext().bundle().getIdentifier().equals("Jca")) {
            keyLength =
                    new KeyLength(defaultKeySize, asset.getDetectionContext(), NodeOrigin.ENRICHED);
            asset.put(keyLength);
        }
    }
}
