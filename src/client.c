#define _XOPEN_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include "common.h"
#include "tls_utils.h"
#include "proto.h"

int main(int argc, char** argv) {
    const char* host = (argc > 1) ? argv[1] : APP_HOST_DEFAULT;
    const char* port = (argc > 2) ? argv[2] : APP_PORT_DEFAULT;
    const char* ca   = (argc > 3) ? argv[3] : "../certs/server.crt.pem";

    int fd;
    mbedtls_ssl_context ssl;
    if (tls_client_connect(host, port, ca, &fd, &ssl) != 0) {
        fprintf(stderr, "client connect failed\n");
        return 1;
    }

    // -------- Baseline: send an echo message --------
    // TODO: Replace this to build and send your PT time message.
    // Build the Pacific-time message and send over TLS
    char line[MAX_LINE];
    proto_build_client_message(line, sizeof line);
    if (tls_send_line(&ssl, line) < 0) {
        fprintf(stderr, "send failed\n");
        goto cleanup;
    }

    // -------- Baseline: print the echoed content --------
    // TODO: Replace this to parse ET message and print readable ET time + offset.
    char resp[MAX_LINE];
    int n = tls_recv_line(&ssl, resp, sizeof resp);
    if (n <= 0) {
        fprintf(stderr, "recv failed (%d)\n", n);
        goto cleanup;
    }

    struct tm et_tm;
    int et_offset;
    if (proto_parse_et(resp, &et_tm, &et_offset) == 0) {
        printf("Server replied with Eastern Time: ET: %04d-%02d-%02dT%02d:%02d:%02d%+03d:%02d\n",
               et_tm.tm_year + 1900, et_tm.tm_mon + 1, et_tm.tm_mday,
               et_tm.tm_hour, et_tm.tm_min, et_tm.tm_sec,
               et_offset / 60, abs(et_offset % 60));
    } else {
        printf("Server replied: %s\n", resp);
    }

 // Cleanup TLS session
    cleanup:
    mbedtls_ssl_close_notify(&ssl);
    close(fd);
    mbedtls_ssl_free(&ssl);
    return 0;
}
