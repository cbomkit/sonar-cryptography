import json

def optional(value):
    if value == "" or value == "-":
        return "null"
    else:
        return "\"" + value + "\""

# Hash names that can end a TLS 1.3 suite name, longest first so a shorter suffix never wins.
TLS13_HASH_ALGORITHMS = (
    "ASCONHASH256",
    "SHA3_256",
    "SHA3_384",
    "SHA3_512",
    "SHA256",
    "SHA384",
    "SHA512",
    "SM3",
)

# The ciphersuite.info API splits some TLS 1.3 names across kex/auth and leaves enc/hash empty.
# TLS 1.3 has no negotiable kex/auth, so recover enc/hash from the name instead. Matched against
# the known hashes above rather than the last "_" token, which would mis-split SHA3_256.
def resolve_unparsed_tls13_fields(name, struct):
    if struct["enc_algorithm"] or struct["hash_algorithm"]:
        return
    if "TLS1.3" not in struct.get("tls_version", []) or not name.startswith("TLS_"):
        return

    body = name[len("TLS_"):]
    for hash_algorithm in TLS13_HASH_ALGORITHMS:
        suffix = "_" + hash_algorithm
        if body.endswith(suffix) and len(body) > len(suffix):
            struct["kex_algorithm"] = "-"
            struct["auth_algorithm"] = "-"
            struct["enc_algorithm"] = body[: -len(suffix)].replace("_", " ")
            struct["hash_algorithm"] = hash_algorithm
            return

    print(f"WARNING: cannot normalize TLS 1.3 cipher suite '{name}'; enc/hash left unset")

with open("./ciphersuites.json", "r") as stream:
    cipherList = list()

    data = json.load(stream)
    cipherSuites = data["ciphersuites"]
    for cipherSuite in cipherSuites:
        name, *_ = cipherSuite.keys()
        struct, *_ = cipherSuite.values()
        struct["name"] = name
        resolve_unparsed_tls13_fields(name, struct)
        cipherList.append(struct)


    code = """
package com.ibm.mapper.mapper.ssl.json;

import java.util.Map;

@SuppressWarnings("java:S1192")
public final class JsonCipherSuites {

    private JsonCipherSuites() {
        // nothing
    }

    public static final Map<String, JsonCipherSuite> CIPHER_SUITES = Map.<String, JsonCipherSuite>ofEntries(
    """

    for i, cipherSuite in enumerate(cipherSuites):
        name, *_ = cipherSuite.keys()
        struct, *_ = cipherSuite.values()

        gnutlsName = optional(struct["gnutls_name"])
        openSSLName = optional(struct["openssl_name"])

        hex1 = struct["hex_byte_1"]
        hex2 = struct["hex_byte_2"]

        idsStr = ""
        if hex1 is not None or hex2 is not None:
            if hex1 is not None and hex2 is not None:
                idsStr = 'new String[]{ "'+hex1+'", "'+hex2+'" }'
            elif hex1 is not None and hex2 is None:
                idsStr = 'new String[]{ "'+hex1+'" }'
            elif hex1 is None and hex2 is not None:
                idsStr = 'new String[]{ "'+hex2+'" }'
        else:
            idsStr = 'null'

        keyExchangeAlgo = optional(struct["kex_algorithm"])
        authenticationAlgorithm = optional(struct["auth_algorithm"])
        encryptionAlgorithm = optional(struct["enc_algorithm"])
        hashAlgorithm = optional(struct["hash_algorithm"])

        code += f"""    Map.entry(\"{name}\", new JsonCipherSuite(\"{name}\", {gnutlsName}, {openSSLName}, {idsStr}, {keyExchangeAlgo}, {authenticationAlgorithm}, {encryptionAlgorithm}, {hashAlgorithm}))"""

        if i != len(cipherSuites) -1:
            code += ",\n"

    code += """
    );
}
    """
with open("./src/main/java/com/ibm/mapper/mapper/ssl/json/JsonCipherSuites.java", "w") as outfile:
    outfile.write(code)