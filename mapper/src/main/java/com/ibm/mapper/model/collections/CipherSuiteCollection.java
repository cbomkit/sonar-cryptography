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
package com.ibm.mapper.model.collections;

import com.ibm.mapper.model.CipherSuite;
import com.ibm.mapper.model.INode;
import java.util.List;
import javax.annotation.Nonnull;

public class CipherSuiteCollection extends AbstractAssetCollection<CipherSuite> {

    public CipherSuiteCollection(@Nonnull List<CipherSuite> collection) {
        super(collection, CipherSuiteCollection.class);
    }

    private CipherSuiteCollection(@Nonnull CipherSuiteCollection cipherSuiteCollection) {
        super(cipherSuiteCollection.collection, cipherSuiteCollection.kind);
    }

    @Nonnull
    @Override
    public INode deepCopy() {
        CipherSuiteCollection copy = new CipherSuiteCollection(this);
        for (INode child : this.children.values()) {
            copy.children.put(child.getKind(), child.deepCopy());
        }
        return copy;
    }

    @Override
    public boolean isMergeable() {
        return true;
    }

    @Nonnull
    @Override
    public CipherSuiteCollection createMerged(@Nonnull List<CipherSuite> mergedCollection) {
        return new CipherSuiteCollection(mergedCollection);
    }
}
