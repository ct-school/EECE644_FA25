#define _GNU_SOURCE
#include <stdlib.h>
#include <time.h>
#include <stdio.h>
#include <string.h>
#include "proto.h"
#include "common.h"


// ---------------- Baseline: TLS ECHO ----------------

// Build a simple message for the echo baseline.
// TODO: (Optional) change the payload content (e.g., include your name or a counter).
//  CLIENT-SIDE: build a PT time message
int proto_build_client_message(char* out, size_t outsz) {
 snprintf(out, outsz, "HELLO FROM CLIENT");
    return 0;
}

// Server handler for baseline: just echo back the same line.
// TODO: Replace this logic with PT->ET conversion per assignment spec.
int proto_handle_server_request(const char* in_line, char* out_line, size_t outsz) {
    snprintf(out_line, outsz, "%s", in_line);
    return 0;
}

// Guidance for time-converter functions is in proto.h (see TODOs).

// Format Pacific Time (client side)
int proto_format_pt(char* out, size_t outsz, const struct tm* pt_tm, int utc_offset_minutes) {
    int hours = utc_offset_minutes / 60;
    int mins = abs(utc_offset_minutes % 60);

    return snprintf(out, outsz, "PT: %04d-%02d-%02dT%02d:%02d:%02d%+03d:%02d", pt_tm->tm_year + 1900, pt_tm->tm_mon + 1, pt_tm->tm_mday, pt_tm->tm_hour, pt_tm->tm_min, pt_tm->tm_sec, hours, mins);
}

// Parse Pacific Time message from client (server side)
int proto_parse_pt(const char* line, struct tm* out_tm, int* out_offset_minutes) {
    if (strncmp(line, "PT:", 3) != 0) return -1;

    const char* body = line + 3;
     if (!strptime(body, "%Y-%m-%dT%H:%M:%S", out_tm)) return -1;

    if (out_offset_minutes) *out_offset_minutes = -480; // UTC-8 for PT
    return 0;
}

// Format Eastern Time result for client
int proto_format_et(char* out, size_t outsz, const struct tm* et_tm, int utc_offset_minutes) {
    int hours = utc_offset_minutes / 60;
    int mins  = abs(utc_offset_minutes % 60);

    return snprintf(out, outsz, "ET: %04d-%02d-%02dT%02d:%02d:%02d%+03d:%02d", et_tm->tm_year + 1900, et_tm->tm_mon + 1, et_tm->tm_mday, et_tm->tm_hour, et_tm->tm_min, et_tm->tm_sec, hours, mins);
}

// Convert Pacific Time -> Eastern Time (add 3 hours)
int convert_pt_to_et(const struct tm* pt_tm_in, struct tm* out_et_tm, int* out_et_offset_minutes) {
    if (!pt_tm_in || !out_et_tm) return -1;

    // Copy input and get epoch assuming PT is UTC−8
    struct tm pt_tm_copy = *pt_tm_in;
    time_t pt_epoch = timegm(&pt_tm_copy);

    // Pacific (UTC−8) -> Eastern Standard (UTC−5)
    time_t et_epoch = pt_epoch + (3 * 3600);

    // Convert back to UTC calendar time
    struct tm *et_tm = gmtime(&et_epoch);
    *out_et_tm = *et_tm;

    // Force UTC−5 (EST), not −4
    if (out_et_offset_minutes)
        *out_et_offset_minutes = -300;

    return 0;
}
