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
package com.ibm.engine.model.factory;

import com.ibm.engine.detection.ResolvedValue;
import com.ibm.engine.model.IValue;
import java.util.Optional;
import java.util.function.Function;

public interface IValueFactory<T> extends Function<ResolvedValue<Object, T>, Optional<IValue<T>>> {

    /**
     * Whether this factory states something by the argument merely being there, without reading its
     * value.
     *
     * <p>Almost every factory answers no: it turns a resolved constant into a value, and an
     * argument whose value cannot be resolved has to stay unreported, because inventing one is the
     * failure mode this engine is built to avoid. A few APIs put the statement in the parameter
     * itself -- fo-dicom's {@code DicomClientFactory.Create(host, port, ITlsInitiator, ...)}
     * documents TLS as off exactly when the initiator is null, so an initiator in that slot is the
     * statement whatever object it happens to be. Such a factory ignores its input and returns a
     * constant, and the engine then calls it once for the expression that was bound, instead of
     * never calling it at all.
     *
     * <p>A factory may only answer yes when its answer does not depend on the input, and only where
     * the parameter is typed tightly enough that nothing else can bind there: the argument binder's
     * type check is all that stands between this and a value attached to the wrong parameter.
     */
    default boolean isPresenceBased() {
        return false;
    }
}
