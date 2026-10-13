package com.spyaware.network;

import java.nio.charset.StandardCharsets;

/**
 * Parses the plaintext TLS ClientHello record to extract the Server Name
 * Indication (SNI) hostname, per RFC 6066. This never touches encrypted
 * data -- the ClientHello is sent unencrypted by design so the server
 * knows which certificate to present.
 *
 * All parsing is defensive: a malformed or truncated buffer (e.g. a
 * ClientHello split across multiple TCP segments, which we don't
 * reassemble) simply yields null, never a crash or a guessed value.
 */
public class TlsSniParser {

    public static String parseServerName(byte[] data) {
        try {
            if (data == null || data.length < 6) return null;

            int pos = 0;
            int contentType = data[pos] & 0xFF; pos++;
            if (contentType != 0x16) return null; // not a TLS handshake record

            pos += 2; // record version, unused
            pos += 2; // record length, unused (we trust data.length instead)

            if (pos + 4 > data.length) return null;
            int handshakeType = data[pos] & 0xFF; pos++;
            if (handshakeType != 0x01) return null; // not a ClientHello

            pos += 3; // handshake length, unused

            if (pos + 2 + 32 + 1 > data.length) return null;
            pos += 2;  // client_version
            pos += 32; // random

            int sessionIdLen = data[pos] & 0xFF; pos++;
            pos += sessionIdLen;
            if (pos + 2 > data.length) return null;

            int cipherSuitesLen = u16(data, pos); pos += 2;
            pos += cipherSuitesLen;
            if (pos + 1 > data.length) return null;

            int compMethodsLen = data[pos] & 0xFF; pos++;
            pos += compMethodsLen;
            if (pos + 2 > data.length) return null; // no extensions present

            int extensionsLen = u16(data, pos); pos += 2;
            int extensionsEnd = Math.min(data.length, pos + extensionsLen);

            while (pos + 4 <= extensionsEnd) {
                int extType = u16(data, pos); pos += 2;
                int extLen = u16(data, pos); pos += 2;
                if (pos + extLen > data.length) break; // truncated, stop cleanly

                if (extType == 0x0000) { // server_name extension
                    String host = parseServerNameExtension(data, pos, extLen);
                    if (host != null) return host;
                }
                pos += extLen;
            }
        } catch (Exception e) {
            // Any unexpected shape -> no result, never a crash.
        }
        return null;
    }

    private static String parseServerNameExtension(byte[] data, int off, int len) {
        try {
            int pos = off;
            int end = off + len;
            if (pos + 2 > end) return null;

            int listLen = u16(data, pos); pos += 2;
            int listEnd = Math.min(end, pos + listLen);

            while (pos + 3 <= listEnd) {
                int nameType = data[pos] & 0xFF; pos++;
                int nameLen = u16(data, pos); pos += 2;
                if (pos + nameLen > data.length) return null;

                if (nameType == 0) { // host_name
                    return new String(data, pos, nameLen, StandardCharsets.US_ASCII);
                }
                pos += nameLen;
            }
        } catch (Exception e) {
            // fall through to null
        }
        return null;
    }

    private static int u16(byte[] d, int off) {
        return ((d[off] & 0xFF) << 8) | (d[off + 1] & 0xFF);
    }
}