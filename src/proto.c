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
    if (!out) return -1;
    setenv("TZ", "America/Los_Angeles", 1);
    tzset();

    time_t now = time(NULL);
    struct tm pt_tm = *localtime(&now);
    return proto_format_pt(out, outsz, &pt_tm, 0);
}

//Format PT string (client-side)
int proto_format_pt(char* out, size_t outsz, const struct tm* pt_tm, int utc_offset_minutes) {
     // Convert offset (e.g., -420 for PT → "-07:00")
    int hours = utc_offset_minutes / 60;
    int minutes = abs(utc_offset_minutes % 60);

    snprintf(out, outsz,"PT: %04d-%02d-%02dT%02d:%02d:%02d%+03d:%02d", pt_tm->tm_year + 1900, pt_tm->tm_mon + 1, pt_tm->tm_mday, pt_tm->tm_hour, pt_tm->tm_min, pt_tm->tm_sec,  hours, minutes);
    return 0;
}



// Server handler for baseline: just echo back the same line.
// TODO: Replace this logic with PT->ET conversion per assignment spec.
//Parse PT string (server-side)
int proto_parse_pt(const char* line, struct tm* out_tm, int* out_offset_minutes) {
    if (!line || !out_tm) return -1;
    memset(out_tm, 0, sizeof(*out_tm));
    strptime(line, "%Y-%m-%dT%H:%M:%S", out_tm);
    if (out_offset_minutes) *out_offset_minutes = 0;
    return 0;
}

//Format ET string (server-side)
int proto_format_et(char* out, size_t outsz, const struct tm* et_tm, int utc_offset_minutes) {
   int hours = utc_offset_minutes / 60;
    int minutes = abs(utc_offset_minutes % 60);

    snprintf(out, outsz,"ET: %04d-%02d-%02dT%02d:%02d:%02d%+03d:%02d", et_tm->tm_year + 1900, et_tm->tm_mon + 1, et_tm->tm_mday, et_tm->tm_hour, et_tm->tm_min, et_tm->tm_sec, hours, minutes);
    return 0;
}

// Handle Server Request (Echo ->Time Converter)
int proto_handle_server_request(const char* in_line, char* out_line, size_t outsz) {
    
    if (!in_line || !out_line) return -1;

    // Keep baseline ECHO working for test_echo.py
    if (strstr(in_line, "HELLO FROM CLIENT")) {
        snprintf(out_line, outsz, "%s", in_line);
        return 0;
    }

    struct tm pt_tm = {0};
    proto_parse_pt(in_line, &pt_tm, NULL);

    struct tm et_tm;
    convert_pt_to_et(&pt_tm, &et_tm, NULL);

    proto_format_et(out_line, outsz, &et_tm, 0);
    return 0;
}

// Guidance for time-converter functions is in proto.h (see TODOs).
//  HELPER: convert a Pacific-time struct tm to Eastern-time struct tm
int convert_pt_to_et(const struct tm* pt_tm_in, struct tm* out_et_tm, int* out_et_offset_minutes) {
    if (!pt_tm_in || !out_et_tm) return -1;

    setenv("TZ", "America/Los_Angeles", 1);
    tzset();
    time_t t = mktime((struct tm*)pt_tm_in);
    if (t == (time_t)-1) return -1;

    setenv("TZ", "America/New_York", 1);
    tzset();
    struct tm* tmp = localtime(&t);
    if (!tmp) return -1;

    *out_et_tm = *tmp;
    if (out_et_offset_minutes) *out_et_offset_minutes = 0;
    return 0;
}

