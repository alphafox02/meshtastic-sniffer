/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (c) 2026 CEMAXECUTER LLC
 *
 * Network utility helpers
 *
 */

#ifndef NET_UTIL_H
#define NET_UTIL_H

#include <arpa/inet.h>
#include <netdb.h>
#include <string.h>

/*
 * Resolve a hostname or numeric IP to an IPv4 address.
 * Tries inet_pton first (numeric), falls back to getaddrinfo (DNS).
 * Returns 0 on success, -1 on failure.
 */
static inline int resolve_host_ipv4(const char *host, struct in_addr *out)
{
    if (inet_pton(AF_INET, host, out) == 1)
        return 0;

    struct addrinfo hints = { .ai_family = AF_INET, .ai_socktype = SOCK_DGRAM };
    struct addrinfo *res = NULL;
    if (getaddrinfo(host, NULL, &hints, &res) != 0 || !res)
        return -1;

    *out = ((struct sockaddr_in *)res->ai_addr)->sin_addr;
    freeaddrinfo(res);
    return 0;
}

#endif
