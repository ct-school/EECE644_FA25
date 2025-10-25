#define _XOPEN_SOURCE 700
#include <stdlib.h>
#include "proto.h"
#include <stdio.h>
#include <string.h>
#include <time.h>


// ---------------- Baseline: TLS ECHO ----------------

// Build a simple message for the echo baseline.
// TODO: (Optional) change the payload content (e.g., include your name or a counter).
//  CLIENT-SIDE: build a PT time message
int proto_build_client_message(char* out, size_t outsz) {
 // Force timezone to Pacific and refresh system TZ info
    setenv("TZ", "America/Los_Angeles", 1);
    tzset();

    time_t now = time(NULL);
    struct tm pt_tm;
    localtime_r(&now, &pt_tm);

    // Format timestamp as ISO-8601 without offset 
    strftime(out, outsz, "%Y-%m-%dT%H:%M:%S PT", &pt_tm);
    return 0;
}

// Server handler for baseline: just echo back the same line.
// TODO: Replace this logic with PT->ET conversion per assignment spec.
// SERVER-SIDE: handle PT→ET conversion and reply
int proto_handle_server_request(const char* in_line, char* out_line, size_t outsz) {
    struct tm pt_tm = {0};

    // Parse incoming ISO8601 "YYYY-MM-DDTHH:MM:SS"
    strptime(in_line, "%Y-%m-%dT%H:%M:%S", &pt_tm);

    struct tm et_tm;
    convert_pt_to_et(&pt_tm, &et_tm, NULL);

    // Format ET time string to send back
    strftime(out_line, outsz, "%Y-%m-%dT%H:%M:%S ET", &et_tm);
    return 0;
}

// Guidance for time-converter functions is in proto.h (see TODOs).
//  HELPER: convert a Pacific-time struct tm to Eastern-time struct tm
int convert_pt_to_et(const struct tm* pt_tm_in, struct tm* out_et_tm, int* out_et_offset_minutes) {
    setenv("TZ", "America/Los_Angeles", 1);
    tzset();

    time_t t = mktime((struct tm*)pt_tm_in);  // interpret as PT
    if (t == (time_t)-1) return -1;

    // Switch to Eastern zone and re-interpret
    setenv("TZ", "America/New_York", 1);
    tzset();

    struct tm* tmp = localtime(&t);
    if (!tmp) return -1;
    *out_et_tm = *tmp;

    if (out_et_offset_minutes) *out_et_offset_minutes = 0; 
    return 0;
}

