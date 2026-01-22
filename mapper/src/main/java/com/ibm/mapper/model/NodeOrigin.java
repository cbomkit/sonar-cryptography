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
package com.ibm.mapper.model;

/**
 * Indicates the origin of a node's value, distinguishing between values that were actually detected
 * in source code versus values that were added as defaults or through enrichment.
 */
public enum NodeOrigin {
    /** Value was detected in the analyzed source code. */
    DETECTED,

    /** Value was added as a default by algorithm constructors (e.g., DES default key length). */
    DEFAULT,

    /** Value was added during the enrichment phase. */
    ENRICHED
}
