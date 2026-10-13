package com.spyaware.network;

import java.nio.charset.StandardCharsets;

/**
 * Parses the question name out of a raw DNS query packet (RFC 1035).
 * This is plaintext protocol data -- DNS has no encryption in the classic
 * UDP:53 case we're reading here (DoH/DoT, which are encrypted, are simply
 * not parseable by this and are left alone).
 */
public class DnsQueryParser {

    public static String parseQueryName(byte[] data) {
        try {
            if (data == null || data.length < 13) return null;

            int pos = 12; // skip the 12-byte DNS header
            StringBuilder sb = new StringBuilder();

            while (pos < data.length) {
                int len = data[pos] & 0xFF;
                if (len == 0) { pos++; break; }              // end of name
                if ((len & 0xC0) == 0xC0) return null;        // compression pointer -- shouldn't appear in the first question, bail safely
                pos++;
                if (pos + len > data.length) return null;     // truncated, don't guess

                if (sb.length() > 0) sb.append('.');
                sb.append(new String(data, pos, len, StandardCharsets.US_ASCII));
                pos += len;
            }

            return sb.length() == 0 ? null : sb.toString();
        } catch (Exception e) {
            return null; // any unexpected shape -> no result, never a crash
        }
    }
}