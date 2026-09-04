package com.ibm.plugin.rules.detection.nodecrypto;

import javax.annotation.Nonnull;

class NodeCryptoKDFTest extends NodeCryptoRuleTestBase {
    @Override
    @Nonnull
    protected String fixturePath() {
        return "rules/detection/nodecrypto/NodeCryptoKDFTestFile.js";
    }
}
