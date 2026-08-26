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

import com.ibm.engine.language.csharp.tree.CSharpTree;
import com.ibm.engine.model.Algorithm;
import com.ibm.engine.model.IValue;
import com.ibm.engine.model.ValueAction;
import com.ibm.engine.model.context.IDetectionContext;
import com.ibm.engine.rule.IBundle;
import com.ibm.mapper.IContextTranslation;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.Mac;
import com.ibm.mapper.model.algorithms.DESede;
import com.ibm.mapper.model.algorithms.HMAC;
import com.ibm.mapper.model.algorithms.KMAC;
import com.ibm.mapper.model.algorithms.MD5;
import com.ibm.mapper.model.algorithms.RIPEMD;
import com.ibm.mapper.model.algorithms.SHA;
import com.ibm.mapper.model.algorithms.SHA2;
import com.ibm.mapper.model.algorithms.SHA3;
import com.ibm.mapper.utils.DetectionLocation;
import java.util.Optional;
import javax.annotation.Nonnull;

/** Translates {@link com.ibm.engine.model.context.MacContext} detections for .NET APIs. */
public final class CSharpMacContextTranslator implements IContextTranslation<CSharpTree> {

    @Override
    public @Nonnull Optional<INode> translate(
            @Nonnull IBundle bundleIdentifier,
            @Nonnull IValue<CSharpTree> value,
            @Nonnull IDetectionContext detectionContext,
            @Nonnull DetectionLocation detectionLocation) {

        if (value instanceof ValueAction<?>) {
            return switch (value.asString().toUpperCase().trim()) {
                case "HMACSHA1" -> Optional.of(new HMAC(new SHA(detectionLocation)));
                case "HMACSHA256" -> Optional.of(new HMAC(new SHA2(256, detectionLocation)));
                case "HMACSHA384" -> Optional.of(new HMAC(new SHA2(384, detectionLocation)));
                case "HMACSHA512" -> Optional.of(new HMAC(new SHA2(512, detectionLocation)));
                case "HMACMD5" -> Optional.of(new HMAC(new MD5(detectionLocation)));
                case "HMACRIPEMD160" -> Optional.of(new HMAC(new RIPEMD(160, detectionLocation)));
                case "HMACSHA3_256" -> Optional.of(new HMAC(new SHA3(256, detectionLocation)));
                case "HMACSHA3_384" -> Optional.of(new HMAC(new SHA3(384, detectionLocation)));
                case "HMACSHA3_512" -> Optional.of(new HMAC(new SHA3(512, detectionLocation)));
                // Kmac128/KmacXof128 and Kmac256/KmacXof256 both reuse the existing KMAC mapper
                // model (already used by the BouncyCastle KMAC mapper). The model has no concept
                // distinguishing the fixed-output KMAC construction from the true
                // extendable-output KMACXOF construction, so both collapse to the identical
                // translated node per security-strength pair — see DotNetKMAC javadoc "Known
                // modeling gap" section for the full rationale.
                case "KMAC128", "KMACXOF128" -> Optional.of(new KMAC(128, detectionLocation));
                case "KMAC256", "KMACXOF256" -> Optional.of(new KMAC(256, detectionLocation));
                // MACTripleDES is not HMAC-based (see DotNetHMAC javadoc); reuse the DESede
                // algorithm model "as" a Mac kind, the same idiom used elsewhere in this codebase
                // to reinterpret DESede as a KeyWrap (JcaCipherMapper / BcWrapperMapper).
                case "MACTRIPLEDES" ->
                        Optional.of(new DESede(Mac.class, new DESede(detectionLocation)));
                default -> Optional.empty();
            };
        } else if (value instanceof Algorithm<?>) {
            // KeyedHashAlgorithm.Create(string) / HMAC.Create(string) — both methods document the
            // identical string table, verified against the official API reference
            // (learn.microsoft.com), see DotNetAlgorithmFactory javadoc. Unlike the ValueAction
            // branch above (fixed per-class identity), the concrete MAC here is resolved purely
            // from the captured runtime string.
            return switch (value.asString().toUpperCase().trim()) {
                case "HMACSHA1",
                        "SYSTEM.SECURITY.CRYPTOGRAPHY.HMACSHA1",
                        "SYSTEM.SECURITY.CRYPTOGRAPHY.HMAC",
                        "SYSTEM.SECURITY.CRYPTOGRAPHY.KEYEDHASHALGORITHM" ->
                        Optional.of(new HMAC(new SHA(detectionLocation)));
                case "HMACSHA256", "SYSTEM.SECURITY.CRYPTOGRAPHY.HMACSHA256" ->
                        Optional.of(new HMAC(new SHA2(256, detectionLocation)));
                case "HMACSHA384", "SYSTEM.SECURITY.CRYPTOGRAPHY.HMACSHA384" ->
                        Optional.of(new HMAC(new SHA2(384, detectionLocation)));
                case "HMACSHA512", "SYSTEM.SECURITY.CRYPTOGRAPHY.HMACSHA512" ->
                        Optional.of(new HMAC(new SHA2(512, detectionLocation)));
                case "HMACMD5", "SYSTEM.SECURITY.CRYPTOGRAPHY.HMACMD5" ->
                        Optional.of(new HMAC(new MD5(detectionLocation)));
                case "HMACRIPEMD160", "SYSTEM.SECURITY.CRYPTOGRAPHY.HMACRIPEMD160" ->
                        Optional.of(new HMAC(new RIPEMD(160, detectionLocation)));
                // Same DESede-as-Mac idiom as the ValueAction branch above.
                case "MACTRIPLEDES", "SYSTEM.SECURITY.CRYPTOGRAPHY.MACTRIPLEDES" ->
                        Optional.of(new DESede(Mac.class, new DESede(detectionLocation)));
                default -> Optional.empty();
            };
        }

        return Optional.empty();
    }
}
