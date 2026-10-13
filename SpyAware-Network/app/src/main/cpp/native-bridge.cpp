#include <jni.h>
#include <android/log.h>
#include <unistd.h>
#include <cstring>
#include <cstdio>
#include <cerrno>
#include <cstdint>
#include <ctime>
#include <atomic>
#include <arpa/inet.h>
#include <sys/select.h>
extern "C" {
#include "zdtun.h"
}

#define TAG "SpyAwareNative"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)

static volatile bool g_running = false;

static std::atomic<long> g_from_tun(0);
static std::atomic<long> g_parse_fail(0);
static std::atomic<long> g_lookup_fail(0);
static std::atomic<long> g_fwd_fail(0);
static std::atomic<long> g_to_tun(0);
static std::atomic<long> g_protect_ok(0);
static std::atomic<long> g_protect_fail(0);

static std::atomic<int> g_last_parse_rc(0);
static std::atomic<int> g_last_fwd_rc(0);
static std::atomic<int> g_last_errno(0);
static std::atomic<int> g_bad_ver(0);
static std::atomic<int> g_bad_proto(0);
static std::atomic<int> g_bad_len(0);

struct NativeContext {
    int tun_fd;
    JNIEnv *env;
    jobject vpn_service;
    jmethodID protect_method;
};

static jclass g_packetLogClass = nullptr;
static jmethodID g_onPacket = nullptr;

static jclass g_payloadAnalyzerClass = nullptr;
static jmethodID g_onNativePayload = nullptr;
static jmethodID g_onTlsClientHello = nullptr;
static jmethodID g_onDnsQuery = nullptr;   // NEW
static const int PAYLOAD_PREFIX_LEN = 16;
static const int DNS_PREFIX_LEN = 512;

static int send_to_tun_callback(zdtun_t *tun, zdtun_pkt_t *pkt, const zdtun_conn_t *conn_info) {
    NativeContext *ctx = (NativeContext *) zdtun_userdata(tun);
    ssize_t written = write(ctx->tun_fd, pkt->buf, pkt->len);
    if (written == pkt->len) {
        g_to_tun++;
        return 0;
    }
    return -1;
}

static void on_socket_open_callback(zdtun_t *tun, socket_t socket) {
    NativeContext *ctx = (NativeContext *) zdtun_userdata(tun);
    jboolean ok = ctx->env->CallBooleanMethod(ctx->vpn_service, ctx->protect_method, (jint) socket);
    if (ok) g_protect_ok++; else g_protect_fail++;
}

static int on_connection_open_callback(zdtun_t *tun, zdtun_conn_t *conn_info) {
    return 0;
}

static void on_connection_close_callback(zdtun_t *tun, const zdtun_conn_t *conn_info) {
    // Our userdata marker is a raw sentinel value, nothing to free.
}

// Stage 5 (+ Stage 10 payload hook + SNI hook + DNS hook)
static void account_packet_callback(zdtun_t *tun, const struct zdtun_pkt *pkt,
                                    uint8_t to_zdtun, const zdtun_conn_t *conn_info) {
    if (!g_onPacket || !conn_info) return;

    NativeContext *ctx = (NativeContext *) zdtun_userdata(tun);
    JNIEnv *env = ctx->env;

    const zdtun_5tuple_t *t = zdtun_conn_get_5tuple(conn_info);
    if (!t) return;

    char src[INET6_ADDRSTRLEN] = "?";
    char dst[INET6_ADDRSTRLEN] = "?";
    if (t->ipver == 4) {
        inet_ntop(AF_INET, &t->src_ip.ip4, src, sizeof(src));
        inet_ntop(AF_INET, &t->dst_ip.ip4, dst, sizeof(dst));
    } else {
        inet_ntop(AF_INET6, &t->src_ip.ip6, src, sizeof(src));
        inet_ntop(AF_INET6, &t->dst_ip.ip6, dst, sizeof(dst));
    }

    jstring jsrc = env->NewStringUTF(src);
    jstring jdst = env->NewStringUTF(dst);
    jint jSrcPort = (jint) ntohs(t->src_port);
    jint jDstPort = (jint) ntohs(t->dst_port);
    jint jProto = (jint) t->ipproto;
    jboolean jOutbound = (jboolean) (to_zdtun ? JNI_TRUE : JNI_FALSE);

    env->CallStaticVoidMethod(g_packetLogClass, g_onPacket,
                              jsrc, jSrcPort, jdst, jDstPort,
                              jProto, (jint) pkt->len, jOutbound);

    // Stage 10, Level 2: short payload prefix for magic-byte checking.
    if (g_onNativePayload && pkt->l7 != nullptr && pkt->l7_len > 0) {
        int copyLen = pkt->l7_len < PAYLOAD_PREFIX_LEN ? pkt->l7_len : PAYLOAD_PREFIX_LEN;
        jbyteArray jpayload = env->NewByteArray(copyLen);
        if (jpayload != nullptr) {
            env->SetByteArrayRegion(jpayload, 0, copyLen, (const jbyte *) pkt->l7);
            env->CallStaticVoidMethod(g_payloadAnalyzerClass, g_onNativePayload,
                                      jsrc, jSrcPort, jdst, jDstPort,
                                      jProto, jpayload, jOutbound);
            env->DeleteLocalRef(jpayload);
        }
    }

    // SNI: first outbound packet of each TCP connection only, if it looks
    // like a TLS ClientHello. Plaintext handshake data, never decrypted.
    if (g_onTlsClientHello && to_zdtun && pkt->l7 != nullptr && pkt->l7_len > 0) {
        void *marker = zdtun_conn_get_userdata(conn_info);
        if (marker == nullptr) {
            if (pkt->l7_len >= 6 &&
                (unsigned char) pkt->l7[0] == 0x16 &&
                (unsigned char) pkt->l7[5] == 0x01) {

                jbyteArray jhello = env->NewByteArray((jsize) pkt->l7_len);
                if (jhello != nullptr) {
                    env->SetByteArrayRegion(jhello, 0, (jsize) pkt->l7_len, (const jbyte *) pkt->l7);
                    env->CallStaticVoidMethod(g_payloadAnalyzerClass, g_onTlsClientHello,
                                              jsrc, jSrcPort, jdst, jDstPort,
                                              jProto, jhello, jOutbound);
                    env->DeleteLocalRef(jhello);
                }
            }
            zdtun_conn_t *mutableConn = const_cast<zdtun_conn_t *>(conn_info);
            zdtun_conn_set_userdata(mutableConn, (void *) (intptr_t) 1);
        }
    }

    // NEW: DNS query name extraction. Outbound UDP:53 packets only --
    // plaintext DNS protocol data, nothing decrypted.
    if (g_onDnsQuery && to_zdtun && jProto == 17 && jDstPort == 53
        && pkt->l7 != nullptr && pkt->l7_len > 0) {
        int copyLen = pkt->l7_len < DNS_PREFIX_LEN ? pkt->l7_len : DNS_PREFIX_LEN;
        jbyteArray jdns = env->NewByteArray(copyLen);
        if (jdns != nullptr) {
            env->SetByteArrayRegion(jdns, 0, copyLen, (const jbyte *) pkt->l7);
            env->CallStaticVoidMethod(g_payloadAnalyzerClass, g_onDnsQuery,
                                      jsrc, jSrcPort, jdst, jDstPort,
                                      jProto, jdns, jOutbound);
            env->DeleteLocalRef(jdns);
        }
    }

    env->DeleteLocalRef(jsrc);
    env->DeleteLocalRef(jdst);
}

static void remember_bad_packet(const char *buf, int len) {
    g_bad_ver = ((unsigned char) buf[0]) >> 4;
    g_bad_proto = (g_bad_ver == 4 && len > 9) ? (unsigned char) buf[9] : -1;
    g_bad_len = len;
}

extern "C"
JNIEXPORT void JNICALL
Java_com_spyaware_network_NativeBridge_runLoop(JNIEnv *env, jclass clazz, jint tun_fd, jobject vpn_service) {
    g_running = true;
    g_from_tun = 0; g_parse_fail = 0; g_lookup_fail = 0; g_fwd_fail = 0;
    g_to_tun = 0; g_protect_ok = 0; g_protect_fail = 0;
    g_last_parse_rc = 0; g_last_fwd_rc = 0; g_last_errno = 0;
    g_bad_ver = 0; g_bad_proto = 0; g_bad_len = 0;

    jclass vpnServiceClass = env->GetObjectClass(vpn_service);
    jmethodID protectMethod = env->GetMethodID(vpnServiceClass, "protect", "(I)Z");
    if (protectMethod == nullptr) {
        LOGE("Could not find VpnService.protect(int)");
        return;
    }

    jclass packetLogCls = env->FindClass("com/spyaware/network/PacketLog");
    if (packetLogCls == nullptr) {
        LOGE("PacketLog class not found");
        return;
    }
    g_packetLogClass = (jclass) env->NewGlobalRef(packetLogCls);
    g_onPacket = env->GetStaticMethodID(g_packetLogClass, "onPacket",
                                        "(Ljava/lang/String;ILjava/lang/String;IIIZ)V");
    if (g_onPacket == nullptr) {
        LOGE("PacketLog.onPacket not found");
        return;
    }

    jclass payloadCls = env->FindClass("com/spyaware/network/PayloadAnalyzer");
    if (payloadCls == nullptr) {
        LOGE("PayloadAnalyzer class not found");
        return;
    }
    g_payloadAnalyzerClass = (jclass) env->NewGlobalRef(payloadCls);
    g_onNativePayload = env->GetStaticMethodID(g_payloadAnalyzerClass, "onNativePayload",
                                               "(Ljava/lang/String;ILjava/lang/String;II[BZ)V");
    if (g_onNativePayload == nullptr) {
        LOGE("PayloadAnalyzer.onNativePayload not found");
        return;
    }

    g_onTlsClientHello = env->GetStaticMethodID(g_payloadAnalyzerClass, "onNativeTlsClientHello",
                                                "(Ljava/lang/String;ILjava/lang/String;II[BZ)V");
    if (g_onTlsClientHello == nullptr) {
        LOGE("PayloadAnalyzer.onNativeTlsClientHello not found");
        return;
    }

    // NEW
    g_onDnsQuery = env->GetStaticMethodID(g_payloadAnalyzerClass, "onNativeDnsQuery",
                                          "(Ljava/lang/String;ILjava/lang/String;II[BZ)V");
    if (g_onDnsQuery == nullptr) {
        LOGE("PayloadAnalyzer.onNativeDnsQuery not found");
        return;
    }

    NativeContext ctx;
    ctx.tun_fd = tun_fd;
    ctx.env = env;
    ctx.vpn_service = vpn_service;
    ctx.protect_method = protectMethod;

    zdtun_callbacks_t callbacks = {};
    callbacks.send_client = send_to_tun_callback;
    callbacks.on_socket_open = on_socket_open_callback;
    callbacks.on_connection_open = on_connection_open_callback;
    callbacks.on_connection_close = on_connection_close_callback;
    callbacks.account_packet = account_packet_callback;

    zdtun_t *tun = zdtun_init(&callbacks, &ctx);
    if (!tun) {
        LOGE("zdtun_init failed");
        return;
    }
    zdtun_set_mtu(tun, 1500);

    LOGI("zdtun run loop starting, tun_fd=%d", tun_fd);

    char buffer[65535];
    time_t last_purge = time(nullptr);

    while (g_running) {
        fd_set rd_fds, wr_fds;
        int max_fd = 0;

        FD_ZERO(&rd_fds);
        FD_ZERO(&wr_fds);

        zdtun_fds(tun, &max_fd, &rd_fds, &wr_fds);

        FD_SET(tun_fd, &rd_fds);
        if (tun_fd > max_fd) max_fd = tun_fd;

        struct timeval tv = {1, 0};
        int rv = select(max_fd + 1, &rd_fds, &wr_fds, nullptr, &tv);

        if (rv < 0) {
            if (errno == EINTR) continue;
            LOGE("select() error: %s", strerror(errno));
            break;
        }

        if (rv > 0) {
            if (FD_ISSET(tun_fd, &rd_fds)) {
                ssize_t len = read(tun_fd, buffer, sizeof(buffer));
                if (len > 0) {
                    g_from_tun++;

                    zdtun_pkt_t pkt;
                    int rc = zdtun_parse_pkt(tun, buffer, (uint16_t) len, &pkt);
                    if (rc != 0) {
                        g_parse_fail++;
                        g_last_parse_rc = rc;
                        remember_bad_packet(buffer, (int) len);
                    } else {
                        errno = 0;
                        zdtun_conn_t *conn = zdtun_lookup(tun, &pkt.tuple, 1);
                        if (!conn) {
                            g_lookup_fail++;
                            g_last_errno = errno;
                            remember_bad_packet(buffer, (int) len);
                        } else {
                            errno = 0;
                            int frc = zdtun_forward(tun, &pkt, conn);
                            if (frc != 0) {
                                g_fwd_fail++;
                                g_last_fwd_rc = frc;
                                g_last_errno = errno;
                                remember_bad_packet(buffer, (int) len);
                                zdtun_conn_close(tun, conn, CONN_STATUS_ERROR);
                            }
                        }
                    }
                }
            }
            zdtun_handle_fd(tun, &rd_fds, &wr_fds);
        }

        time_t now = time(nullptr);
        if (now - last_purge > 10) {
            zdtun_purge_expired(tun);
            last_purge = now;
        }
    }

    zdtun_finalize(tun);

    env->DeleteGlobalRef(g_packetLogClass);
    g_packetLogClass = nullptr;
    g_onPacket = nullptr;

    env->DeleteGlobalRef(g_payloadAnalyzerClass);
    g_payloadAnalyzerClass = nullptr;
    g_onNativePayload = nullptr;
    g_onTlsClientHello = nullptr;
    g_onDnsQuery = nullptr;

    LOGI("zdtun run loop stopped");
}

extern "C"
JNIEXPORT void JNICALL
Java_com_spyaware_network_NativeBridge_stopLoop(JNIEnv *env, jclass clazz) {
    g_running = false;
}

extern "C"
JNIEXPORT jstring JNICALL
Java_com_spyaware_network_NativeBridge_getStats(JNIEnv *env, jclass clazz) {
    char buf[512];
    snprintf(buf, sizeof(buf),
             "TUN->zdtun: %ld\n"
             "parse fail: %ld (rc %d)\n"
             "lookup fail: %ld\n"
             "forward fail: %ld (rc %d)\n"
             "errno: %d (%s)\n"
             "bad pkt: ipver %d, proto %d, len %d\n"
             "protect ok: %ld, fail: %ld\n"
             "zdtun->TUN: %ld",
             g_from_tun.load(),
             g_parse_fail.load(), g_last_parse_rc.load(),
             g_lookup_fail.load(),
             g_fwd_fail.load(), g_last_fwd_rc.load(),
             g_last_errno.load(), strerror(g_last_errno.load()),
             g_bad_ver.load(), g_bad_proto.load(), g_bad_len.load(),
             g_protect_ok.load(), g_protect_fail.load(),
             g_to_tun.load());
    return env->NewStringUTF(buf);
}