/* Copyright 2022 NXP
 * SPDX-License-Identifier: Apache-2.0
 */

#include "sa_qi_auth.h"

/* clang-format off */
const uint8_t gecc_der_header_nist256[] = {
    0x30, 0x59, 0x30, 0x13,     0x06, 0x07, 0x2A, 0x86,
    0x48, 0xCE, 0x3D, 0x02,     0x01, 0x06, 0x08, 0x2A,
    0x86, 0x48, 0xCE, 0x3D,     0x03, 0x01, 0x07, 0x03,
    0x42, 0x00 };
/* clang-format on */

size_t const der_ecc_nistp256_header_len = sizeof(gecc_der_header_nist256);

/*
 This is a simple function to insert a TLV into a buffer.
 params:
    tag             - ASN.1 Tag
    component       - byte array to be inserted
    componentLen    - Size of component to be inserted
    key             - Buffer into which component will be inserted
    keyLen          - Size of the buffer (key).

 Note : This function inserts the component at the end of the buffer and updates the
        keyLen to where the component is inserted with tag. (Points to the tag)
*/
static int SetASNTLV(uint8_t tag, uint8_t *component, const size_t componentLen, uint8_t *key, size_t *keyLen)
{
    if (componentLen <= 0) {
        return -1;
    }

    if (*keyLen < componentLen) {
        return -1;
    }

    *keyLen = *keyLen - componentLen;
    memcpy(&key[*keyLen], component, componentLen);

    if (componentLen <= 127) {
        if (*keyLen < 1) {
            return -1;
        }
        *keyLen      = *keyLen - 1;
        key[*keyLen] = (uint8_t)componentLen;
    }
    else if (componentLen <= 255) {
        if (*keyLen < 2) {
            return -1;
        }
        *keyLen          = *keyLen - 2;
        key[*keyLen]     = 0x81;
        key[*keyLen + 1] = (uint8_t)componentLen;
    }
    else {
        if (*keyLen < 3) {
            return -1;
        }
        *keyLen          = *keyLen - 3;
        key[*keyLen]     = 0x82;
        key[*keyLen + 1] = (componentLen & 0x00FF00) >> 8;
        key[*keyLen + 2] = (componentLen & 0x00FF);
    }
    if (*keyLen < 1) {
        return -1;
    }
    *keyLen = *keyLen - 1;

    key[*keyLen] = tag;

    return 0;
}

/** @brief Ec RandS To Signature.
 * This function generates signature from RandS.
 *
 * @param rands - Pointer to a location where rands recieved.
 * @param rands_len - Length in bytes of generated rands.
 * @param output - Output buffer containing the signature data.
 * @param outputLen - Size of the output in bytes.
 * 
 * @returns Status of the operation
 * @retval  0 The operation has completed successfully.
 * @retval -1 The requested function could not be performed.
 */

static int EcRandSToSignature(uint8_t *rands, const size_t rands_len, uint8_t *output, size_t *outputLen)
{
    int xResult            = -1;
    uint8_t signature[256] = {0};
    size_t signatureLen    = sizeof(signature);
    size_t componentLen    = (rands_len) / 2;
    uint8_t tag            = MBEDTLS_ASN1_INTEGER;
    size_t totalLen;

    xResult = SetASNTLV(tag, &rands[componentLen], componentLen, signature, &signatureLen);
    if (xResult != 0) {
        goto exit;
    }

    xResult = SetASNTLV(tag, &rands[0], componentLen, signature, &signatureLen);
    if (xResult != 0) {
        goto exit;
    }

    totalLen = sizeof(signature) - signatureLen;

    if (totalLen <= 127) {
        if (signatureLen < 1) {
            xResult = -1;
            goto exit;
        }
        signatureLen = signatureLen - 1;

        signature[signatureLen] = (uint8_t)totalLen;
    }
    else if (totalLen <= 255) {
        if (signatureLen < 2) {
            xResult = -1;
            goto exit;
        }
        signatureLen = signatureLen - 2;

        signature[signatureLen]     = 0x81;
        signature[signatureLen + 1] = (uint8_t)totalLen;
    }
    else {
        if (signatureLen < 3) {
            xResult = -1;
            goto exit;
        }
        signatureLen = signatureLen - 3;

        signature[signatureLen]     = 0x82;
        signature[signatureLen + 1] = (totalLen & 0x00FF00) >> 8;
        signature[signatureLen + 2] = (totalLen & 0x00FF);
    }
    if (signatureLen < 1) {
        return -1;
    }
    signatureLen = signatureLen - 1;

    signature[signatureLen] = MBEDTLS_ASN1_SEQUENCE | MBEDTLS_ASN1_CONSTRUCTED;

    totalLen = sizeof(signature) - signatureLen;
    memcpy(&output[0], &signature[signatureLen], totalLen);
    *outputLen = totalLen;

    xResult = 0;

exit:
    return xResult;
}

static void parseCertGetTBS(uint8_t *pCert, size_t certLen, uint8_t *pgetTbs, size_t *pTbslen)
{
    int ret             = -1;
    unsigned char *p    = pCert;
    unsigned char *pTbs = NULL;
    unsigned char *end  = pCert + certLen;
    size_t len          = 0;
    size_t length       = 0;

    /* Parse first sequence tag */
    ret = mbedtls_asn1_get_tag(&p, end, &len, MBEDTLS_ASN1_SEQUENCE | MBEDTLS_ASN1_CONSTRUCTED);
    if (ret != 0) {
        LOG_E("Error parsing ASN.1 data : %d", __LINE__);
    }

    /* p is now pointing to TBS */
    pTbs = p;
    p++;

    if ((*p & 0x80) == 0x80) {
        if ((*p & 0x7F) == 0x01) {
            length = *(p + 1) + 3;
        }
        else if ((*(p)&0x7F) == 0x02) {
            length = ((*(p + 1) << 8) + *(p + 2)) + 4;
        }
    }

    if (length > 0) {
        memcpy(pgetTbs, pTbs, length);
    }
    *pTbslen = length;
}

static void parseCertGetSignature(uint8_t *pCert, size_t certLen, uint8_t *pSignature, size_t *pSignaturelen)
{
    int ret            = -1;
    unsigned char *p   = pCert;
    unsigned char *end = pCert + certLen;
    size_t len         = 0;

    /* Parse first sequence tag */
    ret = mbedtls_asn1_get_tag(&p, end, &len, MBEDTLS_ASN1_SEQUENCE | MBEDTLS_ASN1_CONSTRUCTED);

    if (ret != 0) {
        LOG_E("Error parsing ASN.1 data : %d", __LINE__);
    }
    /* p now points to TBS bytes */
    /* Parse sequence tag of TBSCertificate */
    ret = mbedtls_asn1_get_tag(&p, end, &len, MBEDTLS_ASN1_SEQUENCE | MBEDTLS_ASN1_CONSTRUCTED);

    if (ret != 0) {
        LOG_E("Error parsing ASN.1 data : %d", __LINE__);
    }
    p += len;

    /* p now points to Certificate signature algorithm */
    /* Parse sequence tag of Certificate signature algorithm */
    ret = mbedtls_asn1_get_tag(&p, end, &len, MBEDTLS_ASN1_SEQUENCE | MBEDTLS_ASN1_CONSTRUCTED);
    if (ret != 0) {
        LOG_E("Error parsing ASN.1 data : %d", __LINE__);
    }
    p += len;

    /* p now points to Certificate signature*/
    /* Parse sequence tag of Certificate signature */
    ret = mbedtls_asn1_get_tag(&p, end, &len, MBEDTLS_ASN1_BIT_STRING);
    if (ret != 0) {
        LOG_E("Error parsing ASN.1 data : %d", __LINE__);
    }
    if (*p == 0x00) {
        p++;
        len--;
    }
    if (len > 0) {
        memcpy(pSignature, p, len);
    }
    *pSignaturelen = len;
}

static int get_digest(const uint8_t *message, size_t messageLen, uint8_t *digest, size_t *digestLen)
{
    int ret                         = -1;
    const mbedtls_md_info_t *mdinfo = NULL;
    mbedtls_md_type_t md_type       = MBEDTLS_MD_SHA256;
    *digestLen                      = 32;

    mdinfo = mbedtls_md_info_from_type(md_type);

    ret = mbedtls_md(mdinfo, message, messageLen, digest);

    if (ret != 0) {
        LOG_E("mbedtls_md failed");
        *digestLen = 0;
        goto exit;
    }
    return ret;

exit:

    return ret;
}

static int verify_digest(
    uint8_t *digest, size_t digestLen, uint8_t *signature, size_t signatureLen, uint8_t *publicKey, size_t publicKeyLen)
{
    int ret;
    size_t base64_olen;
    char pem_format[200];
    mbedtls_md_type_t md_alg = MBEDTLS_MD_SHA256;
    mbedtls_pk_context pk;
    uint8_t base64_format[150] = {0};

    mbedtls_pk_init(&pk);

    ret = mbedtls_base64_encode(base64_format, sizeof(base64_format), &base64_olen, publicKey, publicKeyLen);
    if (ret != 0) {
        LOG_W("mbedtls_base64_encode failed");
        goto exit;
    }

    snprintf(pem_format, sizeof(pem_format), BEGIN_PUBLIC "%s" END_PUBLIC, base64_format);
    ret = mbedtls_pk_parse_public_key(&pk, (const uint8_t *)pem_format, strlen(pem_format) + 1);
    if (ret != 0) {
        LOG_W("mbedtls_pk_parse_public_key failed");
        goto exit;
    }

    ret = mbedtls_pk_verify(&pk, md_alg, digest, digestLen, signature, signatureLen);
    if (ret != 0) {
        LOG_W("mbedtls_pk_verify failed");
        goto exit;
    }

    mbedtls_pk_free(&pk);

    return ret;
exit:
    mbedtls_pk_free(&pk);

    return ret;
}

static int hostVerifySignature(
    uint8_t *publicKey, size_t publicKeyLen, uint8_t *input, size_t inputLen, uint8_t *signature, size_t signatureLen)
{
    uint8_t digest[DIGEST_SIZE_BYTES] = {0};
    size_t digestLen                  = sizeof(digest);
    int ret                           = -1;

    ret = get_digest(input, inputLen, digest, &digestLen);
    if (ret != 0) {
        LOG_W("get_digest failed");
        goto cleanup;
    }

    ret = verify_digest(digest, digestLen, signature, signatureLen, publicKey, publicKeyLen);
    if (ret != 0) {
        LOG_W("verify_digest failed");
        goto cleanup;
    }

    return ret;
cleanup:
    return ret;
}

static void parseCertGetPublicKey(uint8_t *pCert, size_t certLen, uint8_t *pPucPublicKey, size_t *pucPublicKeylen)
{
    int ret            = -1;
    unsigned char *p   = pCert;
    unsigned char *end = pCert + certLen;
    size_t len         = 0;

    /* Parse first sequence tag */
    ret = mbedtls_asn1_get_tag(&p, end, &len, MBEDTLS_ASN1_SEQUENCE | MBEDTLS_ASN1_CONSTRUCTED);
    if (ret != 0) {
        LOG_E("Error parsing ASN.1 data : %d", __LINE__);
    }
    /* p now points to TBS bytes */
    /* Parse sequence tag of TBSCertificate */
    ret = mbedtls_asn1_get_tag(&p, end, &len, MBEDTLS_ASN1_SEQUENCE | MBEDTLS_ASN1_CONSTRUCTED);
    if (ret != 0) {
        LOG_E("Error parsing ASN.1 data : %d", __LINE__);
    }
    /* p now points to Certificate version */
    /* Parse 0xA0 tag of Certificate version */
    ret = mbedtls_asn1_get_tag(&p, end, &len, MBEDTLS_ASN1_CONTEXT_SPECIFIC | MBEDTLS_ASN1_CONSTRUCTED);
    if (ret != 0) {
        LOG_E("Error parsing ASN.1 data : %d", __LINE__);
    }
    p += len;
    /* p now points to Certificate serial number */
    /* Parse MBEDTLS_ASN1_INTEGER tag of Certificate version */
    ret = mbedtls_asn1_get_tag(&p, end, &len, MBEDTLS_ASN1_INTEGER);
    if (ret != 0) {
        LOG_E("Error parsing ASN.1 data : %d", __LINE__);
    }
    p += len;
    /* p now points to Certificate signature algorithm */
    /* Parse sequence tag of Certificate version */
    ret = mbedtls_asn1_get_tag(&p, end, &len, MBEDTLS_ASN1_SEQUENCE | MBEDTLS_ASN1_CONSTRUCTED);
    if (ret != 0) {
        LOG_E("Error parsing ASN.1 data : %d", __LINE__);
    }
    p += len;
    /* p now points to Certificate Issuer */
    /* Parse sequence tag of Certificate version */
    ret = mbedtls_asn1_get_tag(&p, end, &len, MBEDTLS_ASN1_SEQUENCE | MBEDTLS_ASN1_CONSTRUCTED);
    if (ret != 0) {
        LOG_E("Error parsing ASN.1 data : %d", __LINE__);
    }
    p += len;
    /* p now points to Certificate Validity */
    /* Parse sequence tag of Certificate version */
    ret = mbedtls_asn1_get_tag(&p, end, &len, MBEDTLS_ASN1_SEQUENCE | MBEDTLS_ASN1_CONSTRUCTED);
    if (ret != 0) {
        LOG_E("Error parsing ASN.1 data : %d", __LINE__);
    }
    p += len;
    /* p now points to Certificate Subject */
    /* Parse sequence tag of Certificate version */
    ret = mbedtls_asn1_get_tag(&p, end, &len, MBEDTLS_ASN1_SEQUENCE | MBEDTLS_ASN1_CONSTRUCTED);
    if (ret != 0) {
        LOG_E("Error parsing ASN.1 data : %d", __LINE__);
    }
    p += len;
    /* p now points to Certificate Subject Public Key Info */
    /* Parse sequence tag of Certificate version */
    ret = mbedtls_asn1_get_tag(&p, end, &len, MBEDTLS_ASN1_SEQUENCE | MBEDTLS_ASN1_CONSTRUCTED);
    if (ret != 0) {
        LOG_E("Error parsing ASN.1 data : %d", __LINE__);
    }
    /* p now points to Certificate Public Key algorithm */
    /* Parse sequence tag of Certificate version */
    ret = mbedtls_asn1_get_tag(&p, end, &len, MBEDTLS_ASN1_SEQUENCE | MBEDTLS_ASN1_CONSTRUCTED);
    if (ret != 0) {
        LOG_E("Error parsing ASN.1 data : %d", __LINE__);
    }
    p += len;
    /* p now points to Certificate Public Key */
    /* Parse sequence tag of Certificate version */
    ret = mbedtls_asn1_get_tag(&p, end, &len, MBEDTLS_ASN1_BIT_STRING);
    if (ret != 0) {
        LOG_E("Error parsing ASN.1 data : %d", __LINE__);
    }
    if (*p == 0x00) {
        p++;
        len--;
    }
    p++;
    len--;

    if (len > 0) {
        memcpy((void *)pPucPublicKey, (void *)p, len);
    }
    *pucPublicKeylen = len;
}

static int hostVerifyPuc(
    uint8_t *response_buffer, size_t response_size, uint16_t pucCertOffset, uint16_t manufacturerCertLenOffset)
{
    int ret                          = -1;
    uint8_t publicKeyWithHeader[100] = {0};
    uint8_t mcertPublicKey[71]       = {0};
    size_t mcertpublicKeylen         = sizeof(mcertPublicKey);
    uint8_t pucSignature[80]         = {0};
    size_t pucSignaturelen           = sizeof(pucSignature);
    uint8_t pucTbs[1024]             = {0};
    size_t pucTbslen                 = sizeof(pucTbs);

    /* Certificate chain verification */
    parseCertGetTBS(&response_buffer[pucCertOffset], (size_t)(response_size - pucCertOffset), pucTbs, &pucTbslen);

    parseCertGetSignature(
        &response_buffer[pucCertOffset], (size_t)(response_size - pucCertOffset), pucSignature, &pucSignaturelen);

    parseCertGetPublicKey(&response_buffer[manufacturerCertLenOffset],
        (size_t)(pucCertOffset - manufacturerCertLenOffset),
        &mcertPublicKey[1],
        &mcertpublicKeylen);
    if (mcertpublicKeylen > DIGEST_SIZE_BYTES) {
        /* Uncompressed key */
        mcertPublicKey[0] = 0x04;
        mcertpublicKeylen++;
    }
    else {
        LOG_W(
            "Compressed key found in manufacturer certificate. Cannot verify certificate chain\n\t\
Add your implementation to create uncompressed key from a compressed key at %s:%d",
            __FUNCTION__,
            __LINE__);
        return -1;
    }

    if ((der_ecc_nistp256_header_len + mcertpublicKeylen) > sizeof(publicKeyWithHeader)) {
        LOG_W("Insufficient buffer");
        return -1;
    }
    if (mcertpublicKeylen > sizeof(mcertPublicKey)) {
        LOG_W("Invalid key length");
        return -1;
    }
    memcpy(publicKeyWithHeader, gecc_der_header_nist256, der_ecc_nistp256_header_len);
    memcpy(&publicKeyWithHeader[der_ecc_nistp256_header_len], mcertPublicKey, mcertpublicKeylen);
    ret = hostVerifySignature(publicKeyWithHeader,
        mcertpublicKeylen + der_ecc_nistp256_header_len,
        pucTbs,
        pucTbslen,
        pucSignature,
        pucSignaturelen);
    if (ret != 0) {
        LOG_W("Failed to verify PUC certificate");
        return -1;
    }
    else {
        LOG_I("PUC successfully verified");
    }

    return 0;
}

static int hostVerifyMcert(
    uint8_t *response_buffer, size_t response_size, uint16_t pucCertOffset, uint16_t manufacturerCertLenOffset)
{
    int ret                          = -1;
    uint8_t publicKeyWithHeader[100] = {0};
    uint8_t rootcaPublicKey[71]      = {0};
    size_t rootcapublicKeylen        = sizeof(rootcaPublicKey);
    uint8_t mcertSignature[80]       = {0};
    size_t mcertSignaturelen         = sizeof(mcertSignature);
    uint8_t mcertTbs[1024]           = {0};
    size_t mcertTbslen               = sizeof(mcertTbs);

    /* Certificate chain verification */
    parseCertGetTBS(&response_buffer[manufacturerCertLenOffset],
        (size_t)(pucCertOffset - manufacturerCertLenOffset),
        mcertTbs,
        &mcertTbslen);

    parseCertGetSignature(&response_buffer[manufacturerCertLenOffset],
        (size_t)(pucCertOffset - manufacturerCertLenOffset),
        mcertSignature,
        &mcertSignaturelen);

    parseCertGetPublicKey(qi_rootca_cert, (size_t)(qi_rootca_cert_len), &rootcaPublicKey[1], &rootcapublicKeylen);
    if (rootcapublicKeylen > DIGEST_SIZE_BYTES) {
        /* Uncompressed key */
        rootcaPublicKey[0] = 0x04;
        rootcapublicKeylen++;
    }
    else {
        LOG_W("Compressed key found in root CA certificate. Cannot verify certificate chain");
        return -1;
    }

    if ((der_ecc_nistp256_header_len + rootcapublicKeylen) > sizeof(publicKeyWithHeader)) {
        LOG_W("Insufficient buffer");
        return -1;
    }
    if (rootcapublicKeylen > sizeof(rootcaPublicKey)) {
        LOG_W("Invalid key length");
        return -1;
    }
    memcpy(publicKeyWithHeader, gecc_der_header_nist256, der_ecc_nistp256_header_len);
    memcpy(&publicKeyWithHeader[der_ecc_nistp256_header_len], rootcaPublicKey, rootcapublicKeylen);
    ret = hostVerifySignature(publicKeyWithHeader,
        rootcapublicKeylen + der_ecc_nistp256_header_len,
        mcertTbs,
        mcertTbslen,
        mcertSignature,
        mcertSignaturelen);
    if (ret != 0) {
        LOG_W("Failed to verify MCERT certificate");
        return -1;
    }
    else {
        LOG_I("Manufacturer certificate successfully verified");
    }

    return 0;
}

static int hostVerifyCertificateChain(
    uint8_t *response_buffer, size_t response_size, uint16_t pucCertOffset, uint16_t manufacturerCertLenOffset)
{
    int ret = -1;

    if (0 != hostVerifyPuc(response_buffer, response_size, pucCertOffset, manufacturerCertLenOffset)) {
        LOG_W("Failed to verify PUC certificate");
        goto exit;
    }

    if (0 != hostVerifyMcert(response_buffer, response_size, pucCertOffset, manufacturerCertLenOffset)) {
        LOG_W("Failed to verify Manufacturer certificate. Did you update RootCA certificate in sa_qi_rootcert.c?");
        goto exit;
    }

    ret = 0;

exit:
    return ret;
}

static int hostVerifyChallenge(uint8_t *pPublicKey,
    size_t publicKeyLen,
    uint8_t *pCertificateChainHash,
    uint8_t *pChallengeRequest,
    uint8_t *pChallengeResponse)
{
    int ret                               = -1;
    uint8_t publicKeyWithHeader[100]      = {0};
    uint8_t tbsAuth[TBS_AUTH_BUFFER_SIZE] = {0};
    uint8_t *pTbsAuth                     = &tbsAuth[0];
    uint8_t asn1Signature[72]             = {0};
    size_t asn1SignatureLen               = sizeof(asn1Signature);
    memcpy(publicKeyWithHeader, gecc_der_header_nist256, der_ecc_nistp256_header_len);
    memcpy(&publicKeyWithHeader[der_ecc_nistp256_header_len], pPublicKey, publicKeyLen);

    *pTbsAuth++ = CHALLENGE_AUTH_RESPONSE_PREFIX;
    memcpy(pTbsAuth, pCertificateChainHash, DIGEST_SIZE_BYTES);
    pTbsAuth += DIGEST_SIZE_BYTES;
    memcpy(pTbsAuth, pChallengeRequest, MAX_CMD_SIZE_CHALLENGE);
    pTbsAuth += MAX_CMD_SIZE_CHALLENGE;
    memcpy(pTbsAuth, pChallengeResponse, 3);

    if (0 != EcRandSToSignature(&pChallengeResponse[3], DIGEST_SIZE_BYTES * 2, asn1Signature, &asn1SignatureLen)) {
        LOG_E("Cannot create ASN.1 signature");
        goto cleanup;
    }

    LOG_MAU8_I("TBSAuth", tbsAuth, sizeof(tbsAuth));

    ret = hostVerifySignature(publicKeyWithHeader,
        publicKeyLen + der_ecc_nistp256_header_len,
        tbsAuth,
        TBS_AUTH_BUFFER_SIZE,
        asn1Signature,
        asn1SignatureLen);
    if (ret == 0) {
        LOG_I("Challenge successfully verified");
    }

cleanup:
    return ret;
}

static int getRandom(uint8_t *pBuf, size_t bufLen)
{
    return sys_csrand_get((void *)pBuf, bufLen);
}

/* doc:start:qi-auth-port */
/* Port to implement RNG to get 16 byte nonce value
 * for authentication operation.
 * This API does not guarantee the randomness of the RNG.
 * User should make sure that the RNG seed is from a trusted source
 * and that the randomness of the source is NIST compliant
 */
int port_getRandomNonce(uint8_t *nonce, size_t *pNonceLen)
{
    int ret              = 0;
    size_t random_length = (*pNonceLen > NONCE_LEN) ? NONCE_LEN : (*pNonceLen);
    *pNonceLen           = random_length;
    ret                  = getRandom(nonce, random_length);
    if (0 != ret) {
        *pNonceLen = 0;
    }
    return ret;
}

/* Port to implement function which will 
 * parse an X.509 certificate and extract the public key 
 * from it.
 */
void port_parseCertGetPublicKey(uint8_t *pCert, size_t certLen, uint8_t *pPublicKey, size_t *publicKeylen)
{
    parseCertGetPublicKey(pCert, certLen, pPublicKey, publicKeylen);
}

/* Port to implement function which will 
 * verify the complete certificate chain as passed in certificate_chain
 */
int port_hostVerifyCertificateChain(uint8_t *certificate_chain,
    size_t certificate_chain_size,
    uint16_t pucCertOffset,
    uint16_t manufacturerCertLenOffset)
{
    return hostVerifyCertificateChain(
        certificate_chain, certificate_chain_size, pucCertOffset, manufacturerCertLenOffset);
}

/* Port to implement function which will 
 * verify CHALLENGE on host
 */
int port_hostVerifyChallenge(uint8_t *pPublicKey,
    size_t publicKeyLen,
    uint8_t *pCertificateChainHash,
    uint8_t *pChallengeRequest,
    uint8_t *pChallengeResponse)
{
    return hostVerifyChallenge(pPublicKey, publicKeyLen, pCertificateChainHash, pChallengeRequest, pChallengeResponse);
}
/* doc:end:qi-auth-port */
