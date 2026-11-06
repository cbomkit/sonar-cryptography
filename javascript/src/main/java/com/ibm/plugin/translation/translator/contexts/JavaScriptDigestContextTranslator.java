/*
 * Sonar Cryptography Plugin
 * Copyright (C) 2026 PQCA
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
import com.ibm.engine.model.context.DetectionContext;
import com.ibm.engine.rule.IBundle;
import com.ibm.mapper.IContextTranslation;
import com.ibm.mapper.mapper.jca.JcaMessageDigestMapper;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.functionality.Digest;
import com.ibm.mapper.utils.DetectionLocation;
import com.ibm.plugin.javascript.tree.JavaScriptTree;
import java.util.Optional;
import javax.annotation.Nonnull;

/**
 * Translates {@link com.ibm.engine.model.context.DigestContext} detections for Node.js.
 *
 * <p>Node passes the algorithm to {@code createHash} as an OpenSSL digest name ({@code "sha256"},
 * {@code "sha512"}, {@code "md5"}), which {@link JcaMessageDigestMapper} already understands
 * case-insensitively. The {@code update}/{@code digest} actions carry no information beyond the
 * algorithm and so produce no node of their own.
 */
public final class JavaScriptDigestContextTranslator
        implements IContextTranslation<JavaScriptTree> {

    @Override
    public @Nonnull Optional<INode> translate(
            @Nonnull IBundle bundleIdentifier,
            @Nonnull IValue<JavaScriptTree> value,
            @Nonnull DetectionContext detectionContext,
            @Nonnull DetectionLocation detectionLocation) {
        if (value instanceof Algorithm<JavaScriptTree>) {
            return new JcaMessageDigestMapper()
                    .parse(value.asString(), detectionLocation)
                    .map(
                            digest -> {
                                digest.put(new Digest(detectionLocation));
                                return digest;
                            });
        }
        return Optional.empty();
    }
}
