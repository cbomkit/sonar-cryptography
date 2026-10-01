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
package com.ibm.output.cyclonedx;

import static org.assertj.core.api.Assertions.assertThat;

import com.ibm.engine.rule.IBundle;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.utils.DetectionLocation;
import com.ibm.mapper.utils.Utils;
import com.ibm.output.Constants;
import com.ibm.output.cyclondx.CBOMOutputFile;
import com.ibm.output.cyclondx.serializer.CycloneDx17JsonGenerator;
import java.lang.reflect.Field;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.function.Consumer;
import java.util.function.Supplier;
import javax.annotation.Nonnull;
import org.cyclonedx.Version;
import org.cyclonedx.exception.GeneratorException;
import org.cyclonedx.generators.json.BomJsonGenerator;
import org.cyclonedx.model.Bom;
import org.cyclonedx.model.Evidence;
import org.cyclonedx.model.OrganizationalEntity;
import org.cyclonedx.model.Service;
import org.cyclonedx.model.component.evidence.Occurrence;
import org.cyclonedx.model.metadata.ToolInformation;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public abstract class TestBase {
    private static final Logger LOGGER = LoggerFactory.getLogger(TestBase.class);

    protected final String filePath = "test.java";
    protected final int lineNumber = 1;
    protected final int offset = 1;
    protected final IBundle bundle = () -> "Test";
    protected final DetectionLocation detectionLocation =
            new DetectionLocation(filePath, lineNumber, offset, Collections.emptyList(), bundle);

    public void assertsNode(
            @Nonnull Supplier<INode> nodeSupplier, @Nonnull Consumer<Bom> assertThat) {
        this.assertsNodes(() -> List.of(nodeSupplier.get()), assertThat);
    }

    public void assertsNodes(
            @Nonnull Supplier<Collection<INode>> nodeSupplier, @Nonnull Consumer<Bom> assertThat) {
        Utils.printNodeTree("tree", nodeSupplier.get().stream().toList());
        // create bom
        final CBOMOutputFile outputFile = new CBOMOutputFile();
        nodeSupplier.get().forEach(node -> outputFile.add(List.of(node)));
        final Bom bom = outputFile.getBom();
        this.printBom(bom);
        // check bom header
        assertThat(bom.getMetadata().getToolChoice()).isNotNull();
        final ToolInformation toolInformation = bom.getMetadata().getToolChoice();
        assertThat(toolInformation.getServices()).hasSize(1);
        final Service service = toolInformation.getServices().get(0);
        assertThat(service.getName()).isEqualTo(Constants.SCANNER_NAME);
        assertThat(service.getProvider()).isNotNull();
        final OrganizationalEntity entity = service.getProvider();
        assertThat(entity.getName()).isEqualTo(Constants.SCANNER_VENDOR);
        // assert bom content
        assertThat.accept(bom);
    }

    protected void asserts(@Nonnull Evidence evidence) {
        assertThat(evidence.getOccurrences()).hasSize(1);
        final Occurrence occurrence = evidence.getOccurrences().get(0);
        assertThat(occurrence.getLocation()).isEqualTo(filePath);
        assertThat(occurrence.getLine()).isEqualTo(lineNumber);
        assertThat(occurrence.getOffset()).isEqualTo(offset);
        assertThat(occurrence.getAdditionalContext()).isNull();
    }

    private void printBom(@Nonnull Bom bom) {
        final BomJsonGenerator bomGenerator = new CycloneDx17JsonGenerator(bom, Version.VERSION_17);
        try {
            Field specVersionField = Bom.class.getDeclaredField("specVersion");
            specVersionField.setAccessible(true);
            specVersionField.set(bom, "1.7");
            final String bomString = bomGenerator.toJsonString();
            assertThat(bomString).contains("\"specVersion\" : \"1.7\"");
            LOGGER.info(bomString);
        } catch (GeneratorException e) {
            LOGGER.error(e.getMessage());
            throw new AssertionError("Could not generate CBOM", e);
        } catch (Exception e) {
            LOGGER.error("Could not set specVersion: {}", e.getMessage());
            throw new AssertionError("Could not set specVersion", e);
        }
    }
}
