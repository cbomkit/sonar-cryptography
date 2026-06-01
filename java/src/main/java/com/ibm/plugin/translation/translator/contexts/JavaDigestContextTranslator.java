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
package com.ibm.plugin.translation.translator.contexts;

import com.ibm.engine.model.Algorithm;
import com.ibm.engine.model.IValue;
import com.ibm.engine.model.Provider;
import com.ibm.engine.model.ValueAction;
import com.ibm.engine.model.context.DetectionContext;
import com.ibm.engine.model.context.IDetectionContext;
import com.ibm.mapper.mapper.bc.BcDigestMapper;
import com.ibm.mapper.mapper.jca.JcaMessageDigestMapper;
import com.ibm.mapper.model.DigestSize;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.MessageDigest;
import com.ibm.mapper.model.algorithms.MGF1;
import com.ibm.mapper.model.collections.MergeableCollection;
import com.ibm.mapper.model.functionality.Digest;
import com.ibm.mapper.utils.DetectionLocation;
import java.util.List;
import java.util.Optional;
import javax.annotation.Nonnull;
import org.sonar.plugins.java.api.tree.Tree;

public final class JavaDigestContextTranslator extends JavaAbstractLibraryTranslator {

    @Override
    protected @Nonnull Optional<INode> translateJCA(
            @Nonnull IValue<Tree> value,
            @Nonnull IDetectionContext detectionContext,
            @Nonnull DetectionLocation detectionLocation) {
        if (value instanceof Algorithm<Tree>) {
            JcaMessageDigestMapper messageDigestMapper = new JcaMessageDigestMapper();
            return messageDigestMapper
                    .parse(value.asString(), detectionLocation)
                    .map(
                            algo -> {
                                algo.put(new Digest(detectionLocation));
                                return algo;
                            });
        } else if (value instanceof Provider<Tree> provider) {
            return Optional.of(
                    new com.ibm.mapper.model.Provider(provider.get(), detectionLocation));
        }
        return Optional.empty();
    }

    @Override
    protected @Nonnull Optional<INode> translateBC(
            @Nonnull IValue<Tree> value,
            @Nonnull IDetectionContext detectionContext,
            @Nonnull DetectionLocation detectionLocation) {
        if (value instanceof ValueAction && detectionContext instanceof DetectionContext context) {
            String kind = context.get("kind").orElse("");
            switch (kind) {
                case "MGF1" -> {
                    BcDigestMapper bcDigestsMapper = new BcDigestMapper();
                    return bcDigestsMapper
                            .parse(value.asString(), detectionLocation)
                            .filter(MessageDigest.class::isInstance)
                            .map(digest -> new MGF1((MessageDigest) digest));
                }
                case "ASSET_COLLECTION" -> {
                    BcDigestMapper bcDigestsMapper = new BcDigestMapper();
                    return bcDigestsMapper
                            .parse(value.asString(), detectionLocation)
                            .map(digest -> new MergeableCollection(List.of(digest)));
                }
                default -> {
                    BcDigestMapper bcDigestsMapper = new BcDigestMapper();
                    return bcDigestsMapper.parse(value.asString(), detectionLocation).map(f -> f);
                }
            }
        } else if (value instanceof com.ibm.engine.model.DigestSize<Tree> digestSize) {
            return Optional.of(new DigestSize(digestSize.getValue(), detectionLocation));
        }
        return Optional.empty();
    }
}
