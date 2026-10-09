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

import com.ibm.mapper.model.INode;
import java.util.List;
import javax.annotation.Nonnull;

/**
 * Protocol versions set on a protocol, each a protocol node of its version: the versions {@link
 * Disabled disabled} on it, e.g. by the {@code SSL_OP_NO_TLSv1} option of an OpenSSL context, and
 * its {@link Minimum minimum} and {@link Maximum maximum} version. The settings made on the same
 * protocol add up: the settings of a kind appended to a protocol are merged into one, and the
 * settings of all kinds together bound the range of versions the protocol uses (see {@code
 * ProtocolVersionReorganizer}).
 */
public abstract sealed class ProtocolVersionSettings extends AbstractAssetCollection<INode>
        permits ProtocolVersionSettings.Disabled,
                ProtocolVersionSettings.Minimum,
                ProtocolVersionSettings.Maximum {

    protected ProtocolVersionSettings(
            @Nonnull List<INode> versions, @Nonnull Class<? extends ProtocolVersionSettings> kind) {
        super(versions, kind);
    }

    @Override
    public boolean isMergeable() {
        return true;
    }

    /** The versions disabled on the protocol. */
    public static final class Disabled extends ProtocolVersionSettings {
        public Disabled(@Nonnull List<INode> versions) {
            super(versions, Disabled.class);
        }

        @Nonnull
        @Override
        public Disabled createMerged(@Nonnull List<INode> mergedCollection) {
            return new Disabled(mergedCollection);
        }
    }

    /** The minimum versions set on the protocol. */
    public static final class Minimum extends ProtocolVersionSettings {
        public Minimum(@Nonnull List<INode> versions) {
            super(versions, Minimum.class);
        }

        @Nonnull
        @Override
        public Minimum createMerged(@Nonnull List<INode> mergedCollection) {
            return new Minimum(mergedCollection);
        }
    }

    /** The maximum versions set on the protocol. */
    public static final class Maximum extends ProtocolVersionSettings {
        public Maximum(@Nonnull List<INode> versions) {
            super(versions, Maximum.class);
        }

        @Nonnull
        @Override
        public Maximum createMerged(@Nonnull List<INode> mergedCollection) {
            return new Maximum(mergedCollection);
        }
    }
}
