/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (c) 2026 CEMAXECUTER LLC
 *
 * meshtastic-sniffer: MQTT publisher.
 *
 * Connects to a broker (libmosquitto) and publishes one JSON line per
 * decoded packet. Topic defaults to meshtastic/<station-id>; user can
 * override with --mqtt-topic.
 *
 * Compiled in only when libmosquitto is found at configure time
 * (HAVE_MQTT define). When it isn't, the symbols below are stubs.
 *
 */

#include "options.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef HAVE_MQTT

#include <mosquitto.h>

static struct mosquitto *g_mq = NULL;
static char             *g_topic = NULL;

void mqtt_init(void)
{
    if (!opt_mqtt_host) return;
    mosquitto_lib_init();
    g_mq = mosquitto_new(NULL, true, NULL);
    if (!g_mq) {
        fprintf(stderr, "mqtt: mosquitto_new failed\n");
        return;
    }
    int rc = mosquitto_connect(g_mq, opt_mqtt_host, opt_mqtt_port, 60);
    if (rc != MOSQ_ERR_SUCCESS) {
        fprintf(stderr, "mqtt: connect %s:%d failed: %s\n",
                opt_mqtt_host, opt_mqtt_port, mosquitto_strerror(rc));
        mosquitto_destroy(g_mq); g_mq = NULL;
        return;
    }
    /* mosquitto_loop_start() runs reads/writes in a background thread. */
    mosquitto_loop_start(g_mq);

    if (opt_mqtt_topic) {
        g_topic = strdup(opt_mqtt_topic);
    } else {
        const char *st = opt_station_id ? opt_station_id : "default";
        size_t n = strlen("meshtastic/") + strlen(st) + 1;
        g_topic = malloc(n);
        snprintf(g_topic, n, "meshtastic/%s", st);
    }
    if (verbose) fprintf(stderr, "mqtt: connected %s:%d topic %s\n",
                          opt_mqtt_host, opt_mqtt_port, g_topic);
}

void mqtt_publish(const char *json, size_t len)
{
    if (!g_mq || !g_topic) return;
    /* QoS 0 (fire-and-forget), retain off. */
    mosquitto_publish(g_mq, NULL, g_topic, (int)len, json, 0, false);
}

void mqtt_shutdown(void)
{
    if (g_mq) {
        mosquitto_loop_stop(g_mq, true);
        mosquitto_disconnect(g_mq);
        mosquitto_destroy(g_mq);
        g_mq = NULL;
    }
    free(g_topic); g_topic = NULL;
    mosquitto_lib_cleanup();
}

#else  /* !HAVE_MQTT */

void mqtt_init(void) {}
void mqtt_publish(const char *json, size_t len) { (void)json; (void)len; }
void mqtt_shutdown(void) {}

#endif
