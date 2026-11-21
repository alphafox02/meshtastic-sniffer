/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * JNI bridge between the Android app (org.meshsniffer.android.Native) and
 * the sniffer library:
 *   - start/stop: sniffer_main() on its own thread, stderr to logcat + a file
 *   - push: int8 I/Q from hackrf_android into the --external-source backend
 *   - TX: tx.c's player calls back into Java to play I/Q on the HackRF
 */
#define _GNU_SOURCE
#include <jni.h>
#include <android/log.h>

#include "ext_src.h"
#include "mesh_tx.h"
#include "meshtastic.h"
#include "tx.h"

#include <fcntl.h>
#include <math.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define TAG "meshsniffer"
#define LOG_MAX_BYTES (2 * 1024 * 1024)

static JavaVM   *g_vm;
static jclass    g_native_cls;     /* org/meshsniffer/android/Native (global ref) */
static jmethodID g_tx_play;        /* static String txPlay(byte[], long, int, int, boolean) */

static pthread_t g_main_thread, g_log_thread;
static int       g_main_started, g_main_done, g_main_rc;
static char    **g_argv;
static int       g_argc;
static char      g_log_path[512];

JNIEXPORT jint JNI_OnLoad(JavaVM *vm, void *reserved)
{
    (void)reserved;
    g_vm = vm;
    JNIEnv *env;
    if ((*vm)->GetEnv(vm, (void **)&env, JNI_VERSION_1_6) != JNI_OK) return JNI_ERR;
    jclass cls = (*env)->FindClass(env, "org/meshsniffer/android/Native");
    if (!cls) return JNI_ERR;
    g_native_cls = (*env)->NewGlobalRef(env, cls);
    g_tx_play = (*env)->GetStaticMethodID(env, cls, "txPlay", "([BJIIZ)Ljava/lang/String;");
    if (!g_tx_play) return JNI_ERR;
    return JNI_VERSION_1_6;
}

/* stderr -> logcat + a size-capped log file the app can show */
static void *log_thread(void *arg)
{
    int fd = (int)(intptr_t)arg;
    FILE *in = fdopen(fd, "r");
    char line[2048];
    while (in && fgets(line, sizeof(line), in)) {
        __android_log_write(ANDROID_LOG_INFO, TAG, line);
        struct stat st;
        if (g_log_path[0] && stat(g_log_path, &st) == 0 && st.st_size > LOG_MAX_BYTES)
            truncate(g_log_path, 0);
        FILE *f = g_log_path[0] ? fopen(g_log_path, "a") : NULL;
        if (f) { fputs(line, f); fclose(f); }
    }
    return NULL;
}

static void *main_thread(void *arg)
{
    (void)arg;
    g_main_rc = sniffer_main(g_argc, g_argv);
    fprintf(stderr, "[android] sniffer stopped (rc=%d)\n", g_main_rc);
    fflush(stderr);
    g_main_done = 1;
    return NULL;
}

/* tx.c player: play I/Q on the app's HackRF (Java), RX paused meanwhile */
static int jni_player(const int8_t *iq, size_t n, uint64_t lo_hz, uint32_t rate, int gain, int amp,
                      char *err, size_t errlen)
{
    JNIEnv *env;
    int attached = 0;
    if ((*g_vm)->GetEnv(g_vm, (void **)&env, JNI_VERSION_1_6) != JNI_OK) {
        if ((*g_vm)->AttachCurrentThread(g_vm, &env, NULL) != JNI_OK) {
            snprintf(err, errlen, "JNI attach failed");
            return -1;
        }
        attached = 1;
    }
    int rc = -1;
    jbyteArray arr = (*env)->NewByteArray(env, (jsize)n);
    if (arr) {
        (*env)->SetByteArrayRegion(env, arr, 0, (jsize)n, (const jbyte *)iq);
        ext_src_set_paused(1);
        jstring res = (jstring)(*env)->CallStaticObjectMethod(env, g_native_cls, g_tx_play, arr,
                                                               (jlong)lo_hz, (jint)rate, (jint)gain,
                                                               (jboolean)(amp != 0));
        ext_src_set_paused(0);
        if ((*env)->ExceptionCheck(env)) {
            (*env)->ExceptionClear(env);
            snprintf(err, errlen, "TX failed in Java");
        } else if (res) {
            const char *s = (*env)->GetStringUTFChars(env, res, NULL);
            /* the message ends up in a JSON string: keep it free of quotes */
            size_t w = 0;
            for (const char *p = s; p && *p && w + 1 < errlen; ++p)
                err[w++] = (*p == '"' || *p == '\\' || (unsigned char)*p < 0x20) ? '\'' : *p;
            err[w] = 0;
            (*env)->ReleaseStringUTFChars(env, res, s);
        } else {
            rc = 0;
        }
        (*env)->DeleteLocalRef(env, arr);
    } else {
        (*env)->ExceptionClear(env);
        snprintf(err, errlen, "out of memory for the TX buffer");
    }
    if (attached) (*g_vm)->DetachCurrentThread(g_vm);
    return rc;
}

static void set_env_dir(JNIEnv *env, const char *name, jstring v)
{
    if (!v) return;
    const char *s = (*env)->GetStringUTFChars(env, v, NULL);
    setenv(name, s, 1);
    (*env)->ReleaseStringUTFChars(env, v, s);
}

JNIEXPORT jint JNICALL
Java_org_meshsniffer_android_Native_start(JNIEnv *env, jclass cls, jobjectArray args,
                                          jstring log_path, jstring home, jstring tmp)
{
    (void)cls;
    if (g_main_started) return -1;     /* one sniffer per process */
    set_env_dir(env, "HOME", home);
    set_env_dir(env, "XDG_CONFIG_HOME", home);
    set_env_dir(env, "XDG_CACHE_HOME", tmp);
    set_env_dir(env, "TMPDIR", tmp);
    if (log_path) {
        const char *s = (*env)->GetStringUTFChars(env, log_path, NULL);
        snprintf(g_log_path, sizeof(g_log_path), "%s", s);
        (*env)->ReleaseStringUTFChars(env, log_path, s);
        truncate(g_log_path, 0);
    }
    /* stdout (the JSON event feed) is not needed: the dashboard shows it */
    int devnull = open("/dev/null", O_WRONLY);
    if (devnull >= 0) { dup2(devnull, 1); close(devnull); }
    int p[2];
    if (pipe(p) == 0) {
        dup2(p[1], 2);
        close(p[1]);
        setvbuf(stderr, NULL, _IOLBF, 0);
        pthread_create(&g_log_thread, NULL, log_thread, (void *)(intptr_t)p[0]);
        pthread_detach(g_log_thread);
    }

    int n = (*env)->GetArrayLength(env, args);
    g_argv = calloc((size_t)n + 2, sizeof(char *));
    g_argv[0] = strdup("meshtastic-sniffer");
    for (int i = 0; i < n; ++i) {
        jstring a = (jstring)(*env)->GetObjectArrayElement(env, args, i);
        const char *s = (*env)->GetStringUTFChars(env, a, NULL);
        g_argv[i + 1] = strdup(s);
        (*env)->ReleaseStringUTFChars(env, a, s);
        (*env)->DeleteLocalRef(env, a);
    }
    g_argc = n + 1;

    tx_set_player(jni_player, "android-hackrf");
    g_main_started = 1;
    if (pthread_create(&g_main_thread, NULL, main_thread, NULL) != 0) {
        g_main_started = 0;
        return -1;
    }
    return 0;
}

/* Ask the sniffer to stop and wait for it. Returns its exit code. */
JNIEXPORT jint JNICALL
Java_org_meshsniffer_android_Native_stop(JNIEnv *env, jclass cls)
{
    (void)env; (void)cls;
    if (!g_main_started) return 0;
    sniffer_request_stop();
    pthread_join(g_main_thread, NULL);
    return g_main_rc;
}

JNIEXPORT jboolean JNICALL
Java_org_meshsniffer_android_Native_isRunning(JNIEnv *env, jclass cls)
{
    (void)env; (void)cls;
    return (jboolean)(g_main_started && !g_main_done);
}

/* Returns 0 if the samples were queued, -1 if not accepted (starting up,
 * stopped, or paused for TX). */
JNIEXPORT jint JNICALL
Java_org_meshsniffer_android_Native_push(JNIEnv *env, jclass cls, jbyteArray buf, jint len)
{
    (void)cls;
    jbyte *p = (*env)->GetPrimitiveArrayCritical(env, buf, NULL);
    if (!p) return -1;
    int rc = ext_src_push((const int8_t *)p, (size_t)len);
    (*env)->ReleasePrimitiveArrayCritical(env, buf, p, JNI_ABORT);
    return rc;
}

/* Centre frequency (Hz) of a preset's channel slot in a region: the
 * firmware's djb2 hash of the channel name (preset name when empty).
 * Returns 0 for unknown names. */
JNIEXPORT jlong JNICALL
Java_org_meshsniffer_android_Native_channelFreq(JNIEnv *env, jclass cls, jstring region,
                                                jstring preset, jstring channel)
{
    (void)cls;
    const char *r = (*env)->GetStringUTFChars(env, region, NULL);
    const char *p = (*env)->GetStringUTFChars(env, preset, NULL);
    const char *c = channel ? (*env)->GetStringUTFChars(env, channel, NULL) : NULL;
    jlong f = 0;
    const mesh_region_t *reg = mesh_lookup_region(r);
    const mesh_preset_def_t *pre = mesh_lookup_preset(p);
    if (reg && pre && !reg->wide_lora) {
        int bw = pre->bw_hz_narrow, n = mesh_channel_count(reg, bw);
        const char *name = (c && *c) ? c : pre->channel_name;
        if (n > 0) f = (jlong)mesh_channel_freq_hz(reg, bw, (int)(mesh_tx_djb2(name) % (uint32_t)n));
    }
    if (c) (*env)->ReleaseStringUTFChars(env, channel, c);
    (*env)->ReleaseStringUTFChars(env, preset, p);
    (*env)->ReleaseStringUTFChars(env, region, r);
    return f;
}
