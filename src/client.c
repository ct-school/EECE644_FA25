
#include <stdio.h>
#include <string.h>
#include <unistd.h>
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
    char msg[MAX_LINE];
    proto_build_client_message(msg, sizeof msg);
    tls_send_line(&ssl, msg);

    // -------- Baseline: print the echoed content --------
    // TODO: Replace this to parse ET message and print readable ET time + offset.
    char resp[MAX_LINE];
    if (tls_recv_line(&ssl, resp, sizeof resp) > 0)
        printf("Server replied with Eastern Time: %s\n", resp);
    else
        fprintf(stderr, "No reply from server\n");


 // Cleanup TLS session
    mbedtls_ssl_close_notify(&ssl);
    close(fd);
    mbedtls_ssl_free(&ssl);
    return 0;
}
