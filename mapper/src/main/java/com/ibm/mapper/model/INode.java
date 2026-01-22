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

import java.util.Map;
import java.util.Optional;
import javax.annotation.Nonnull;

public interface INode {
    void put(@Nonnull INode child);

    /**
     * Returns the origin of this node's value.
     *
     * @return the origin indicating whether the value was detected, is a default, or was enriched
     */
    @Nonnull
    NodeOrigin getOrigin();

    boolean hasChildren();

    @Nonnull
    Map<Class<? extends INode>, INode> getChildren();

    boolean is(@Nonnull final Class<? extends INode> type);

    @Nonnull
    Class<? extends INode> getKind();

    @Nonnull
    String asString();

    @Nonnull
    Optional<INode> hasChildOfType(@Nonnull Class<? extends INode> nodeType);

    void removeChildOfType(@Nonnull Class<? extends INode> nodeType);

    @Nonnull
    INode deepCopy();

    @Nonnull
    default Optional<INode> find(@Nonnull INode node) {
        if (this.equals(node)) {
            return Optional.of(this);
        }

        INode child = this.getChildren().get(node.getKind());
        if (child != null && child.equals(node)) {
            return Optional.of(child);
        } else {
            for (INode childNode : this.getChildren().values()) {
                Optional<INode> possibleFinding = childNode.find(node);
                if (possibleFinding.isPresent()) {
                    return possibleFinding;
                }
            }
        }
        return Optional.empty();
    }
}
