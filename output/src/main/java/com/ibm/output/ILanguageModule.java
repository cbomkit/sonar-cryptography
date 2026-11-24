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
package com.ibm.output;

import com.ibm.mapper.model.INode;
import java.util.List;
import javax.annotation.Nonnull;

/**
 * One supported language, as the plugin sees it. Each language module registers its implementation
 * as a {@link java.util.ServiceLoader} service in {@code
 * META-INF/services/com.ibm.output.ILanguageModule}, so the plugin supports exactly the languages
 * whose module is packaged into it.
 *
 * <p>An implementation must load without the language's analyzer: it must not refer to the
 * analyzer's API in its signatures or fields, only in method bodies that run after {@link
 * #isAvailable()} returned {@code true}.
 */
public interface ILanguageModule {

    /** Display name of the language, for example {@code "Java"}. */
    @Nonnull
    String name();

    /** Position in the CBOM and in the extension list; lower comes first. */
    int order();

    /** Whether the language's analyzer is loaded in the current analysis. */
    boolean isAvailable();

    /**
     * Extensions registered whether or not the analyzer is loaded, such as rule definitions. They
     * must not use the analyzer's API.
     */
    @Nonnull
    List<Object> serverExtensions();

    /**
     * Extensions registered only if {@link #isAvailable()}, such as check registrars and sensors.
     */
    @Nonnull
    List<Object> scannerExtensions();

    /** The nodes detected so far. Only called if {@link #isAvailable()}. */
    @Nonnull
    List<INode> detectedNodes();

    /** Forgets the nodes detected so far. Only called if {@link #isAvailable()}. */
    void reset();
}
