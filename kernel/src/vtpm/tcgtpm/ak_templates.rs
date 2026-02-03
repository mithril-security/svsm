// SPDX-License-Identifier: MIT
//
// Copyright (C) Coconut-SVSM authors
//
// Author: Dionna Glaze <dionnaglaze@google.com>
//

// All constants are defined in TCG Trusted Platform Module Library Part 2 - Structures
// with the names stated in comments.
//
// Table 9. definition of TPM_ALG_ID constants:
// TPM_ALG_RSA     (0x0001)
// TPM_ALG_AES     (0x0006)
// TPM_ALG_SHA256  (0x000B)
// TPM_ALG_NULL    (0x0010)
// TPM_ALG_CFB     (0x0043)
//
// Table 33. TPMA_OBJECT bits
// fixedTPM(1)
// fixedParent(4)
// sensitiveDataOrigin(5)
// userWithAuth(6)
// restricted(16)
// decrypt(17)

pub const PUBLIC_AREA_AK: [u8; 24] = [
    0x0, 0x23, // type TPM_ALG_ECC
    0x0, 0xb,  // alg TPM_ALG_SHA256
    0x0, 0x4, 0x4, 0x72, // objectAttributes { sign userWithAuth
    // sensitiveDataOrigin fixedParent fixedTpm noda }
    0x0, 0x0,   // empty authPolicy 
    // TPMS_ECC_PARMS {
    0x0, 0x10,   // symmetric: TPM_ALG_NULL
    0x0, 0x18,  // scheme:  TPMT_ECC_SCHEME{ scheme: TPM_ALG_ECDSA
    0x0, 0xb,   //                           scheme-halg: TPM_ALG_SHA256 }  TPMT_ECC_SCHEME
    0x0, 0x3,   // curveID: TPM_ECC_NIST_P256
    0x0, 0x10,  // kdf: TPM_ALG_NULL } TPMS_ECC_PARMS
    0x0, 0x0, 0x0, 0x0,
];