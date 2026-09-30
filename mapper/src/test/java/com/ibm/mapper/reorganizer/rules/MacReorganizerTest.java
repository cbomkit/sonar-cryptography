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
package com.ibm.mapper.reorganizer.rules;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

import com.ibm.mapper.model.Algorithm;
import com.ibm.mapper.model.AuthenticatedEncryption;
import com.ibm.mapper.model.BlockCipher;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.KeyLength;
import com.ibm.mapper.model.Mac;
import com.ibm.mapper.model.Mode;
import com.ibm.mapper.model.Oid;
import com.ibm.mapper.model.algorithms.AES;
import com.ibm.mapper.model.functionality.Tag;
import com.ibm.mapper.model.mode.GCM;
import com.ibm.mapper.model.mode.GMAC;
import com.ibm.mapper.reorganizer.IReorganizerRule;
import com.ibm.mapper.utils.DetectionLocation;
import com.ibm.mapper.utils.Utils;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;

class MacReorganizerTest {

    private final DetectionLocation location = mock(DetectionLocation.class);
    private final IReorganizerRule rule = MacReorganizer.MERGE_GMAC_PARENT_AND_GCM_CIPHER_CHILD;

    @Test
    void gmacWithAGcmCipherBecomesTheCipherAsAMacInGmacMode() {
        INode gmac = new com.ibm.mapper.model.algorithms.GMAC(location);
        gmac.put(new Tag(location));
        gmac.put(aes128Gcm());
        List<INode> roots = new ArrayList<>(List.of(gmac));

        assertThat(rule.match(gmac, null, roots)).isTrue();
        List<INode> result = rule.applyReorganization(gmac, null, roots);

        assertThat(result).hasSize(1);
        INode mac = result.get(0);
        assertThat(mac).isInstanceOf(AES.class);
        assertThat(mac.getKind()).isEqualTo(Mac.class);
        assertThat(mac.asString()).isEqualTo("AES-128-GMAC");
        assertThat(mac.getChildren().get(Mode.class)).isInstanceOf(GMAC.class);
        assertThat(mac.getChildren().get(KeyLength.class).asString()).isEqualTo("128");
        assertThat(mac.hasChildOfType(Tag.class)).isPresent();
        assertThat(mac.hasChildOfType(Oid.class)).isEmpty();
        assertThat(mac.hasChildOfType(AuthenticatedEncryption.class)).isEmpty();
    }

    @Test
    void gmacUnderAParentIsReplacedInTheParent() {
        INode gmac = new com.ibm.mapper.model.algorithms.GMAC(location);
        gmac.put(aes128Gcm());
        INode parent = new Algorithm("parent", AuthenticatedEncryption.class, location);
        parent.put(gmac);
        List<INode> roots = new ArrayList<>(List.of(parent));

        assertThat(rule.match(gmac, parent, roots)).isTrue();
        List<INode> result = rule.applyReorganization(gmac, parent, roots);

        assertThat(result).containsExactly(parent);
        INode mac = parent.getChildren().get(Mac.class);
        assertThat(((Algorithm) mac).getName()).isEqualTo("AES");
        assertThat(mac.getChildren().get(Mode.class)).isInstanceOf(GMAC.class);
    }

    @Test
    void gmacWithABlockCipherInGcmModeBecomesTheCipherAsAMacInGmacMode() {
        // before enrichment, AES in GCM mode is still a block cipher
        INode gmac = new com.ibm.mapper.model.algorithms.GMAC(location);
        gmac.put(new AES(128, new GCM(location), location));
        List<INode> roots = new ArrayList<>(List.of(gmac));

        assertThat(rule.match(gmac, null, roots)).isTrue();
        INode mac = rule.applyReorganization(gmac, null, roots).get(0);

        assertThat(mac.getKind()).isEqualTo(Mac.class);
        assertThat(((Algorithm) mac).getName()).isEqualTo("AES");
        assertThat(mac.getChildren().get(Mode.class)).isInstanceOf(GMAC.class);
        assertThat(mac.hasChildOfType(BlockCipher.class)).isEmpty();
    }

    @Test
    void aMacOtherThanGmacDoesNotMatch() {
        INode mac = Utils.unknown(Mac.class, location);
        mac.put(aes128Gcm());

        assertThat(rule.match(mac, null, List.of(mac))).isFalse();
    }

    @Test
    void aCopiedGmacStillMatches() {
        // the translation copies a tree for each alternative value found in it
        INode gmac = new com.ibm.mapper.model.algorithms.GMAC(location);
        gmac.put(aes128Gcm());
        INode copy = gmac.deepCopy();

        assertThat(rule.match(copy, null, List.of(copy))).isTrue();
    }

    @Test
    void gmacWithoutACipherDoesNotMatch() {
        INode gmac = new com.ibm.mapper.model.algorithms.GMAC(location);

        assertThat(rule.match(gmac, null, List.of(gmac))).isFalse();
    }

    @Test
    void theGmacIsReplacedInTheTreeOfItsRoot() {
        // an equal GMAC of another tree comes before it among the roots
        INode first = new com.ibm.mapper.model.algorithms.GMAC(location);
        first.put(aesGcm(128));
        INode second = new com.ibm.mapper.model.algorithms.GMAC(location);
        second.put(aesGcm(256));
        assertThat(first).isEqualTo(second);
        List<INode> roots = new ArrayList<>(List.of(first, second));

        List<INode> result = rule.applyReorganization(second, null, roots);

        assertThat(result).hasSize(2);
        assertThat(result.get(0)).isSameAs(first);
        assertThat(result.get(1).getChildren().get(KeyLength.class).asString()).isEqualTo("256");
    }

    @Test
    void theUnknownMacIsReplacedInTheTreeOfItsRoot() {
        // an equal MAC of another tree comes before it among the roots
        INode first = Utils.unknown(Mac.class, location);
        first.put(new AES(128, location));
        INode second = Utils.unknown(Mac.class, location);
        second.put(new AES(256, location));
        assertThat(first).isEqualTo(second);
        List<INode> roots = new ArrayList<>(List.of(first, second));

        List<INode> result =
                MacReorganizer.MERGE_UNKNOWN_MAC_PARENT_AND_CIPHER_CHILD.applyReorganization(
                        second, null, roots);

        assertThat(result).hasSize(2);
        assertThat(result.get(0)).isSameAs(first);
        assertThat(result.get(1)).isInstanceOf(AES.class);
        assertThat(result.get(1).getKind()).isEqualTo(Mac.class);
        assertThat(result.get(1).getChildren().get(KeyLength.class).asString()).isEqualTo("256");
    }

    private INode aesGcm(int keyLength) {
        return new AES(
                AuthenticatedEncryption.class, new AES(keyLength, new GCM(location), location));
    }

    private INode aes128Gcm() {
        AES aes = new AES(128, new GCM(location), location);
        aes.put(new Oid("2.16.840.1.101.3.4.1.6", location));
        return new AES(AuthenticatedEncryption.class, aes);
    }
}
