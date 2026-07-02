/* asn.c
 *
 * Copyright (C) 2006-2026 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * wolfSSL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */

/*
 * DESCRIPTION
 * This library provides the interface to Abstract Syntax Notation One (ASN.1)
 * objects.
 * ASN.1 is a standard interface description language for defining data
 * structures that can be serialized and deserialized in a cross-platform way.
 *
 * Encoding of ASN.1 is either using Basic Encoding Rules (BER) or
 * Distinguished Encoding Rules (DER). DER has only one possible encoding for a
 * ASN.1 description and the data.
 * Encode using DER and decode BER or DER.
 *
 * Provides routines to convert BER into DER. Replaces indefinite length
 * encoded items with explicit lengths.
 */

#include <wolfssl/wolfcrypt/libwolfssl_sources.h>

/*
ASN Options:
 * NO_ASN_TIME_CHECK: Disables ASN time checks (avoiding the ASN_BEFORE_DATE_E
 * and ASN_AFTER_DATE_E errors). Safer ways to avoid date errors would be to
 * set the WOLFSSL_LOAD_FLAG_DATE_ERR_OKAY flag when calling the _ex versions of
 * cert loading functions or to define the WOLFSSL_NO_OCSP_DATE_CHECK macro to
 * skip OCSP date errors. Defining NO_ASN_TIME_CHECK will skip ALL date checks
 * and could pose a security risk.
 * NO_ASN_TIME: Disables time parts of the ASN code for systems without an RTC
    or wishing to save space.
 * IGNORE_NAME_CONSTRAINTS: Skip ASN name checks.
 * ASN_DUMP_OID: Allows dump of OID information for debugging.
 * RSA_DECODE_EXTRA: Decodes extra information in RSA public key.
 * WOLFSSL_CERT_GEN: Cert generation. Saves extra certificate info in GetName.
 * WOLFSSL_NO_ASN_STRICT: Disable strict RFC compliance checks to
    restore 3.13.0 behavior.
 * WOLFSSL_ASN_ALLOW_0_SERIAL: Even if WOLFSSL_NO_ASN_STRICT is not defined,
    allow a length=1, but zero value serial number.
 * WOLFSSL_NO_OCSP_OPTIONAL_CERTS: Skip optional OCSP certs (responder issuer
    must still be trusted)
 * WOLFSSL_NO_TRUSTED_CERTS_VERIFY: Workaround for situation where entire cert
    chain is not loaded. This only matches on subject and public key and
    does not perform a PKI validation, so it is not a secure solution.
    Only enabled for OCSP.
 * WOLFSSL_NO_OCSP_ISSUER_CHECK: Can be defined for backwards compatibility to
    disable checking of https://www.rfc-editor.org/rfc/rfc6960#section-4.2.2.2.
 * WOLFSSL_SMALL_CERT_VERIFY: Verify the certificate signature without using
    DecodedCert. Doubles up on some code but allows smaller dynamic memory
    usage.
 * WOLFSSL_NO_OCSP_DATE_CHECK: Disable date checks for OCSP responses. This
    may be required when the system's real-time clock is not very accurate.
    It is recommended to enforce the nonce check instead if possible.
 * WOLFSSL_NO_CRL_DATE_CHECK: Disable date checks for CRL's.
 * WOLFSSL_NO_CRL_NEXT_DATE: Do not fail if CRL next date is missing
 * WOLFSSL_FORCE_OCSP_NONCE_CHECK: Require nonces to be available in OCSP
    responses. The nonces are optional and may not be supported by all
    responders. If it can be ensured that the used responder sends nonces this
    option may improve security.
 * WOLFSSL_ASN_TEMPLATE: Encoding and decoding using a template.
 * WOLFSSL_DEBUG_ASN_TEMPLATE: Enables debugging output when using ASN.1
    templates.
 * WOLFSSL_ASN_TEMPLATE_TYPE_CHECK: Use ASN functions to better test compiler
    type issues for testing
 * CRLDP_VALIDATE_DATA: For ASN template only, validates the reason data
 * WOLFSSL_AKID_NAME: Enable support for full AuthorityKeyIdentifier extension.
    Only supports copying full AKID from an existing certificate.
 * WOLFSSL_CUSTOM_OID: Enable custom OID support for subject and request
    extensions
 * WOLFSSL_HAVE_ISSUER_NAMES: Store pointers to issuer name components and their
    lengths and encodings.
 * WOLFSSL_SUBJ_DIR_ATTR: Enable support for SubjectDirectoryAttributes
    extension.
 * WOLFSSL_SUBJ_INFO_ACC: Enable support for SubjectInfoAccess extension.
 * WOLFSSL_FPKI: Enable support for FPKI (Federal PKI) extensions.
 * WOLFSSL_CERT_NAME_ALL: Adds more certificate name capability at the
    cost of taking up more memory. Adds initials, givenname, dnQualifer for
    example.
 * WC_ASN_HASH_SHA256: Force use of SHA2-256 for the internal hash ID calcs.
 * WOLFSSL_ALLOW_ENCODING_CA_FALSE: Allow encoding BasicConstraints CA:FALSE
 *  which is discouraged by X.690 specification - default values shall not
 *  be encoded.
 * NO_TIME_SIGNEDNESS_CHECK: Disabled the time_t signedness check.
 * WOLFSSL_ECC_SIGALG_PARAMS_NULL_ALLOWED: Allows the ECDSA/EdDSA signature
 *  algorithms in certificates to have NULL parameter instead of empty.
 *  DO NOT enable this unless required for interoperability.
 * WOLFSSL_ASN_EXTRA: Make more ASN.1 APIs available regardless of internal
 *  usage.
 * WOLFSSL_ALLOW_AKID_SKID_MATCH: By default cert issuer is found using hash
 * of cert subject hash with signers subject hash. This option allows fallback
 * to using AKID and SKID matching.
 *
 * Certificate Generation/Parsing:
 * WOLFSSL_CERT_REQ:         Enable certificate request (CSR) support
 * WOLFSSL_CERT_EXT:         Enable certificate extension support
 * WOLFSSL_CERT_PIV:         Enable PIV certificate support
 * WOLFSSL_CERT_GEN_CACHE:   Cache DER for cert generation
 * WOLFSSL_CERT_SIGN_CB:     Enable certificate signing callback
 * WOLFSSL_CERT_NAME_ALL:    Store all certificate name components
 * WOLFSSL_MULTI_ATTRIB:     Enable multi-valued RDN attributes
 * WOLFSSL_DER_TO_PEM:       Enable DER to PEM conversion
 * WOLFSSL_PEM_TO_DER:       Enable PEM to DER conversion
 * WOLFSSL_PUB_PEM_TO_DER:   Enable public key PEM to DER conversion
 * WOLFSSL_KEY_TO_DER:       Enable key to DER encoding
 * WOLFSSL_ENCRYPTED_KEYS:   Enable encrypted private key support (PKCS#8)
 * ASN_BER_TO_DER:           Enable BER to DER conversion
 * WOLFSSL_DUP_CERTPOL:      Allow duplicate certificate policies
 * WOLFSSL_NAMES_STATIC:     Use static allocation for name strings
 * WOLFSSL_SIGNER_DER_CERT:  Store signer DER cert in cert manager
 *
 * Certificate Validation:
 * NO_VERIFY_OID:            Skip OID verification
 * NO_CHECK_PRIVATE_KEY:     Skip private key pair check
 * NO_SKID:                  Disable Subject Key Identifier
 * NO_STRICT_ECDSA_LEN:      Allow non-strict ECDSA signature length
 * NO_WOLFSSL_CM_VERIFY:     Disable cert manager verify callback
 * NO_WOLFSSL_SKIP_TRAILING_PAD: Don't skip trailing padding
 * ALLOW_SELFSIGNED_INVALID_CERTSIGN: Allow self-signed certs
 *                            without keyCertSign in keyUsage
 * ALLOW_V1_EXTENSIONS:      Allow extensions in v1 certificates
 * USE_WOLF_VALIDDATE:       Use wolfSSL date validation
 * WC_ASN_RUNTIME_DATE_CHECK_CONTROL: Runtime control of date checking
 * WOLFSSL_AFTER_DATE_CLOCK_SKEW: Clock skew tolerance for after-date
 * WOLFSSL_BEFORE_DATE_CLOCK_SKEW: Clock skew tolerance for before-date
 * WOLFSSL_TRUST_PEER_CERT:  Enable trusted peer certificate support
 *
 * Extensions:
 * WOLFSSL_ALT_NAMES:        Enable Subject Alternative Names
 * WOLFSSL_ALT_NAMES_NO_REV: Alt names without reverse order
 * WOLFSSL_IP_ALT_NAME:      Enable IP address in SAN
 * WOLFSSL_RID_ALT_NAME:     Enable Registered ID in SAN
 * WOLFSSL_SEP:              Enable SubjectEntryPoint extension
 * WOLFSSL_EKU_OID:          Enable Extended Key Usage OID support
 * WOLFSSL_ACERT:            Enable attribute certificate support
 * IGNORE_KEY_EXTENSIONS:    Ignore key usage extensions
 * IGNORE_NETSCAPE_CERT_TYPE: Ignore Netscape cert type extension
 * WOLFSSL_ALLOW_CRIT_AIA:   Allow critical Authority Info Access
 * WOLFSSL_ALLOW_CRIT_AKID:  Allow critical Auth Key Identifier
 * WOLFSSL_ALLOW_CRIT_SKID:  Allow critical Subject Key Identifier
 * WC_ASN_UNKNOWN_EXT_CB:    Callback for unknown extensions
 *
 * ASN.1 Parsing:
 * WOLFSSL_ASN_ALL:          Enable all ASN.1 features
 * WOLFSSL_ASN_CA_ISSUER:    Enable CA Issuer in AIA parsing
 * WOLFSSL_ASN_PRINT:        Enable ASN.1 structure printing
 * WOLFSSL_ASN_INT_LEAD_0_ANY: Allow any leading zero in ASN integers
 * WOLFSSL_ASN_PARSE_KEYUSAGE: Parse key usage extension
 * WOLFSSL_ASN_TIME_STRING:  Enable ASN time to string conversion
 * ASN_TEMPLATE_SKIP_ISCA_CHECK: Skip isCA check in ASN template
 *
 * OID:
 * HAVE_OID_ENCODING:        Enable OID encoding support
 * HAVE_OID_DECODING:        Enable OID decoding support
 * WOLFSSL_OLD_OID_SUM:      Use old OID sum calculation
 *
 * CRL:
 * HAVE_CRL:                 Enable Certificate Revocation Lists
 * CRL_STATIC_REVOKED_LIST:  Use static list for revoked certs
 *
 * OCSP:
 * HAVE_OCSP:                Enable OCSP support
 * HAVE_OCSP_RESPONDER:      Enable OCSP responder support
 * WOLFSSL_OCSP_PARSE_STATUS: Parse OCSP response status
 *
 * PKCS:
 * HAVE_PKCS8:               Enable PKCS#8 support
 * HAVE_PKCS12:              Enable PKCS#12 support
 *
 * Algorithms (ASN encoding/decoding):
 * HAVE_DILITHIUM:           Enable Dilithium ASN support
 * WOLFSSL_DILITHIUM_NO_ASN1: Disable Dilithium ASN.1 encoding
 * WOLFSSL_DILITHIUM_FIPS204_DRAFT: FIPS 204 draft Dilithium
 * WOLFSSL_DILITHIUM_NO_SIGN: Disable Dilithium signing
 * WOLFSSL_DILITHIUM_NO_VERIFY: Disable Dilithium verify
 * HAVE_FALCON:              Enable Falcon ASN support
 * WOLFSSL_HAVE_SLHDSA:      Enable SLH-DSA ASN support
 *
 * Key Import/Export:
 * WC_ENABLE_ASYM_KEY_IMPORT: Enable asymmetric key import
 * WC_ENABLE_ASYM_KEY_EXPORT: Enable asymmetric key export
 *
 * Compatibility:
 * WOLFSSL_APACHE_HTTPD:     Apache HTTPD compatibility
 * WOLFSSL_X509_NAME_AVAILABLE: Enable X509_NAME API
 * WOLFSSL_HAVE_ISSUER_NAMES: Store issuer name components
 * WOLFSSL_ASN_KEY_SIZE_ENUM: Use enum for AES key size in ASN
 * WOLFSSL_SM3:              Enable SM3 hash ASN support
 * HAVE_SMIME:               Enable S/MIME support
 * HAVE_LIBZ:                Enable zlib compression for certs
 * WC_RC2:                   Enable RC2 for PKCS#12
 * WOLFSSL_MD2:              Enable MD2 hash (legacy)
*/



/* Functions that parse, but are not using ASN.1 */




#undef ERROR_OUT
