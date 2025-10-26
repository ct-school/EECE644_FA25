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
    //Start with current UTC time
    time_t now_utc = time(NULL);
    struct tm utc_tm;
    gmtime_r(&now_utc, &utc_tm);

    //Switch to Pacific Time
    setenv("TZ", "America/Los_Angeles", 1);
    tzset();

    //Convert UTC time to Pacific local time
    struct tm pt_tm;
    localtime_r(&now_utc, &pt_tm);

    int offset_min = (int)(pt_tm.tm_gmtoff / 60);

    return proto_format_pt(out, outsz, &pt_tm, offset_min);
}

// Server handler for baseline: just echo back the same line.
// TODO: Replace this logic with PT->ET conversion per assignment spec.
int proto_handle_server_request(const char* in_line, char* out_line, size_t outsz) {
    struct tm pt_tm;
    int pt_offset_min;

    //Parse PT line 
    if (proto_parse_pt(in_line, &pt_tm, &pt_offset_min) != 0) {
        snprintf(out_line, outsz, "ERROR: invalid PT format");
        return -1;
    }

    //Convert to ET
    struct tm et_tm;
    int et_offset_min;
    if (convert_pt_to_et(&pt_tm, &et_tm, &et_offset_min) != 0) {
        snprintf(out_line, outsz, "ERROR: conversion failed");
        return -1;
    }

    proto_format_et(out_line, outsz, &et_tm, et_offset_min);
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

    int year, mon, day, hour, min, sec, offh, offm;
    if (sscanf(line + 3, " %d-%d-%dT%d:%d:%d%3d:%2d",
               &year, &mon, &day, &hour, &min, &sec, &offh, &offm) != 8)
        return -1;

    memset(out_tm, 0, sizeof(*out_tm));
    out_tm->tm_year = year - 1900;
    out_tm->tm_mon  = mon - 1;
    out_tm->tm_mday = day;
    out_tm->tm_hour = hour;
    out_tm->tm_min  = min;
    out_tm->tm_sec  = sec;
    *out_offset_minutes = offh * 60 + ((offh >= 0) ? offm : -offm);
    return 0;
}

// Format Eastern Time result for client
int proto_format_et(char* out, size_t outsz, const struct tm* et_tm, int utc_offset_minutes) {
    int hours = utc_offset_minutes / 60;
    int mins  = abs(utc_offset_minutes % 60);

    return snprintf(out, outsz, "ET: %04d-%02d-%02dT%02d:%02d:%02d%+03d:%02d", et_tm->tm_year + 1900, et_tm->tm_mon + 1, et_tm->tm_mday, et_tm->tm_hour, et_tm->tm_min, et_tm->tm_sec, hours, mins);
}

// Parse ET message
int proto_parse_et(const char* line, struct tm* out_tm, int* out_offset_minutes) {
    if (strncmp(line, "ET:", 3) != 0) return -1;
    int year, mon, day, hour, min, sec, offh, offm;
    if (sscanf(line + 3, " %d-%d-%dT%d:%d:%d%3d:%2d",
               &year, &mon, &day, &hour, &min, &sec, &offh, &offm) != 8)
        return -1;
    memset(out_tm, 0, sizeof(*out_tm));
    out_tm->tm_year = year - 1900;
    out_tm->tm_mon  = mon - 1;
    out_tm->tm_mday = day;
    out_tm->tm_hour = hour;
    out_tm->tm_min  = min;
    out_tm->tm_sec  = sec;
    *out_offset_minutes = offh * 60 + ((offh >= 0) ? offm : -offm);
    return 0;
}

// Convert Pacific Time -> Eastern Time (add 3 hours)
int convert_pt_to_et(const struct tm* pt_tm_in, struct tm* out_et_tm, int* out_et_offset_minutes) {
  // Interpret pt_tm_in as Pacific local time
    setenv("TZ", "America/Los_Angeles", 1);
    tzset();

    struct tm pt_copy = *pt_tm_in;

    // Convert Pacific local time to UTC epoch (mktime already adjusts for tm_gmtoff)
    time_t utc_epoch = mktime(&pt_copy);

    // Convert UTC epoch to Eastern local time
    setenv("TZ", "America/New_York", 1);
    tzset();
    localtime_r(&utc_epoch, out_et_tm);

    // Record ET UTC offset
    *out_et_offset_minutes = (int)(out_et_tm->tm_gmtoff / 60);
    return 0;
}