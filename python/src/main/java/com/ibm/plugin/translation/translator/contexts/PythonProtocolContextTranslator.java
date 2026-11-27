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

import com.ibm.engine.model.IValue;
import com.ibm.engine.model.ValueAction;
import com.ibm.engine.model.context.DetectionContext;
import com.ibm.engine.rule.IBundle;
import com.ibm.mapper.IContextTranslation;
import com.ibm.mapper.mapper.ssl.SSLVersionMapper;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.Protocol;
import com.ibm.mapper.model.protocol.TLS;
import com.ibm.mapper.utils.DetectionLocation;
import java.util.Optional;
import javax.annotation.Nonnull;
import org.sonar.plugins.python.api.tree.Tree;

/**
 * Translates protocol findings of the Python medical-imaging rules (pynetdicom).
 *
 * <p>DICOM names no cryptography of its own: what a call reveals is which standard is spoken and
 * whether the transport beneath it is protected. The call itself is reported as a {@code DICOM}
 * protocol, and an argument that can only mean TLS (pynetdicom's {@code ssl_context} and {@code
 * tls_args}) as a {@code TLS} protocol beneath it. A connection made without them is a DICOM
 * component with nothing beneath, which is the honest statement. The TLS version is added only
 * where the code states it on the {@code ssl.SSLContext} ({@link PythonTlsVersionResolver}); no
 * cipher suite or version is invented.
 */
public final class PythonProtocolContextTranslator implements IContextTranslation<Tree> {

    @Nonnull
    @Override
    public Optional<INode> translate(
            @Nonnull IBundle bundleIdentifier,
            @Nonnull IValue<Tree> value,
            @Nonnull DetectionContext detectionContext,
            @Nonnull DetectionLocation detectionLocation) {
        if (value instanceof ValueAction<Tree> valueAction) {
            return Optional.of(new Protocol(valueAction.asString(), detectionLocation));
        }
        if (value instanceof com.ibm.engine.model.Protocol<Tree> protocol
                && "TLS".equals(protocol.asString())) {
            // the value is located at the argument that carries the SSLContext
            return Optional.of(
                    PythonTlsVersionResolver.resolve(protocol.getLocation())
                            .flatMap(v -> new SSLVersionMapper().parse(v, detectionLocation))
                            .map(TLS::new)
                            .orElseGet(() -> new TLS(detectionLocation)));
        }
        return Optional.empty();
    }
}
