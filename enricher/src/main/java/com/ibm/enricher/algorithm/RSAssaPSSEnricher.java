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

import com.ibm.enricher.IEnricher;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.Oid;
import com.ibm.mapper.model.algorithms.RSA;
import com.ibm.mapper.model.algorithms.RSAssaPSS;
import javax.annotation.Nonnull;

public class RSAssaPSSEnricher implements IEnricher {
    @Override
    public @Nonnull INode enrich(@Nonnull INode node) {
        if (node instanceof RSAssaPSS rsaSsaPSS) {
            rsaSsaPSS.put(new Oid("1.2.840.113549.1.1.10", rsaSsaPSS.getDetectionContext()));
            return rsaSsaPSS;
        }
        // An RSA key that signs with PSS is named RSA-PSS (see RSA#asString), and carries the
        // RSASSA-PSS OID like the RSAssaPSS node of an unlinked PSS signature does.
        if (node instanceof RSA rsa && rsa.hasPssPadding()) {
            rsa.put(new Oid("1.2.840.113549.1.1.10", rsa.getDetectionContext()));
            return rsa;
        }
        return node;
    }
}
