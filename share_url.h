/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (c) 2026 CEMAXECUTER LLC
 */

#ifndef SHARE_URL_H
#define SHARE_URL_H

#include "keyset.h"

/* Decode a Meshtastic channel-share URL or bare base64-url payload and add
 * each channel PSK to the keyset. Returns channels added, or -1 on parse
 * error. */
int decode_channel_share(keyset_t *ks, const char *url_or_b64);

#endif
