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
package com.ibm.plugin;

import com.ibm.output.cyclondx.CBOMOutputFileFactory;
import java.io.File;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.sonar.api.batch.postjob.PostJob;
import org.sonar.api.batch.postjob.PostJobContext;
import org.sonar.api.batch.postjob.PostJobDescriptor;

public class OutputFileJob implements PostJob {
    private static final Logger LOGGER = LoggerFactory.getLogger(OutputFileJob.class);

    @Override
    public void describe(PostJobDescriptor postJobDescriptor) {
        postJobDescriptor.name("Output generation");
    }

    @Override
    public void execute(PostJobContext postJobContext) {
        final String cbomFilename =
                postJobContext
                        .config()
                        .get(Constants.CBOM_OUTPUT_NAME)
                        .orElse(Constants.CBOM_OUTPUT_NAME_DEFAULT);
        ScannerManager scannerManager = new ScannerManager(new CBOMOutputFileFactory());
        final File cbom = new File(cbomFilename + ".json");
        scannerManager.getOutputFile().saveTo(cbom);
        LOGGER.info("CBOM was successfully generated '{}'.", cbom.getAbsolutePath());
        scannerManager.getStatistics().print(LOGGER::info);
        scannerManager.reset();
    }
}
