/*
 * Skeleton for AES round-function oracle
 * - Enforces the CLI contract from the assignment
 * - Students fill in SubBytes/InvSubBytes, ShiftRows/InvShiftRows,
 *   MixColumns/InvMixColumns (AddRoundKey is provided).
 *
 * Build:   make
 * Run:     ./AES_Functions
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>
#include <stdbool.h>


// FIPS-197 S-box

// Sbox taken from https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.197.pdf on pg 16 and 22




/* =========================
   Required function signatures
   ========================= */
void SubBytes(uint8_t state[16]);
void InvSubBytes(uint8_t state[16]);

void ShiftRows(uint8_t state[16]);
void InvShiftRows(uint8_t state[16]);

void MixColumns(uint8_t state[16]);
void InvMixColumns(uint8_t state[16]);

void AddRoundKey(uint8_t state[16], const uint8_t roundKey[16]);

/* =========================
   Helpful macros & helpers
   Column-major mapping: idx = c*4 + r
   ========================= */
#define IDX(r,c) ((c)*4 + (r))
#define LINE_MAX_LEN 256

static inline void trim_trailing_newline(char *s) {
    size_t n = strlen(s);
    if (n && s[n-1] == '\n') s[n-1] = '\0';
}

static inline void to_upper_hex(char *s) {
    for (; *s; ++s) *s = (char)toupper((unsigned char)*s);
}

static bool is_hex_string(const char *s) {
    if (!s || !*s) return false;
    for (const char *p = s; *p; ++p) {
        if (!isxdigit((unsigned char)*p)) return false;
    }
    return true;
}

/* Parse hex string (0..32 hex chars), pad with zeros to 16 bytes.
   If >32 hex chars, truncate to first 32.
   Returns true on success, false on invalid format (e.g., odd length) */
static bool parse_hex_to_16(const char *hex, uint8_t out16[16]) {
    size_t L = strlen(hex);
    if (L > 32) L = 32;                      // truncate
    if (L % 2 != 0) return false;            // must be even length
    if (L == 0) {                            // allow empty => all zeros
        memset(out16, 0, 16);
        return true;
    }
    if (!is_hex_string(hex)) return false;

    // parse pairs
    size_t bytes = L / 2;
    for (size_t i = 0; i < bytes; ++i) {
        char buf[3] = { hex[2*i], hex[2*i+1], '\0' };
        out16[i] = (uint8_t)strtoul(buf, NULL, 16);
    }
    // pad
    for (size_t i = bytes; i < 16; ++i) out16[i] = 0x00;
    return true;
}

static void print_state_line(const uint8_t state[16]) {
    // STATE=<32 uppercase hex>, no spaces
    fputs("STATE=", stdout);
    for (int i = 0; i < 16; ++i) {
        printf("%02X", state[i]);
    }
    fputc('\n', stdout);
    fflush(stdout);
}

/* Read a line; returns true if a line was read. */
static bool read_line(char buf[LINE_MAX_LEN]) {
    if (!fgets(buf, LINE_MAX_LEN, stdin)) return false;
    trim_trailing_newline(buf);
    return true;
}

/* =========================
   Command handling
   ========================= */
static void print_help(void) {
    puts("Commands:");
    puts("  HELP");
    puts("  SUB");
    puts("  INV_SUB");
    puts("  SHIFT");
    puts("  INV_SHIFT");
    puts("  MIX");
    puts("  INV_MIX");
    puts("  XOR <32-hex>");     // AddRoundKey
    puts("  RESET <0..32 hex>");// load new state (padded with zeros)
    puts("  PRINT");
    puts("  EXIT");
}

/* =========================
   AES round functions
   NOTE: Students should replace the TODO bodies with real implementations.
   ========================= */

void SubBytes(uint8_t state[16]) {
    /* TODO:
     *   - Define SBOX[256] table from FIPS-197
     *   - For i in 0..15: state[i] = SBOX[state[i]];
     */
     uint8_t SBOX[256] = {
        0x63,0x7C,0x77,0x7B,0xF2,0x6B,0x6F,0xC5,0x30,0x01,0x67,0x2B,0xFE,0xD7,0xAB,0x76,
        0xCA,0x82,0xC9,0x7D,0xFA,0x59,0x47,0xF0,0xAD,0xD4,0xA2,0xAF,0x9C,0xA4,0x72,0xC0,
        0xB7,0xFD,0x93,0x26,0x36,0x3F,0xF7,0xCC,0x34,0xA5,0xE5,0xF1,0x71,0xD8,0x31,0x15,
        0x04,0xC7,0x23,0xC3,0x18,0x96,0x05,0x9A,0x07,0x12,0x80,0xE2,0xEB,0x27,0xB2,0x75,
        0x09,0x83,0x2C,0x1A,0x1B,0x6E,0x5A,0xA0,0x52,0x3B,0xD6,0xB3,0x29,0xE3,0x2F,0x84,
        0x53,0xD1,0x00,0xED,0x20,0xFC,0xB1,0x5B,0x6A,0xCB,0xBE,0x39,0x4A,0x4C,0x58,0xCF,
        0xD0,0xEF,0xAA,0xFB,0x43,0x4D,0x33,0x85,0x45,0xF9,0x02,0x7F,0x50,0x3C,0x9F,0xA8,
        0x51,0xA3,0x40,0x8F,0x92,0x9D,0x38,0xF5,0xBC,0xB6,0xDA,0x21,0x10,0xFF,0xF3,0xD2,
        0xCD,0x0C,0x13,0xEC,0x5F,0x97,0x44,0x17,0xC4,0xA7,0x7E,0x3D,0x64,0x5D,0x19,0x73,
        0x60,0x81,0x4F,0xDC,0x22,0x2A,0x90,0x88,0x46,0xEE,0xB8,0x14,0xDE,0x5E,0x0B,0xDB,
        0xE0,0x32,0x3A,0x0A,0x49,0x06,0x24,0x5C,0xC2,0xD3,0xAC,0x62,0x91,0x95,0xE4,0x79,
        0xE7,0xC8,0x37,0x6D,0x8D,0xD5,0x4E,0xA9,0x6C,0x56,0xF4,0xEA,0x65,0x7A,0xAE,0x08,
        0xBA,0x78,0x25,0x2E,0x1C,0xA6,0xB4,0xC6,0xE8,0xDD,0x74,0x1F,0x4B,0xBD,0x8B,0x8A,
        0x70,0x3E,0xB5,0x66,0x48,0x03,0xF6,0x0E,0x61,0x35,0x57,0xB9,0x86,0xC1,0x1D,0x9E,
        0xE1,0xF8,0x98,0x11,0x69,0xD9,0x8E,0x94,0x9B,0x1E,0x87,0xE9,0xCE,0x55,0x28,0xDF,
        0x8C,0xA1,0x89,0x0D,0xBF,0xE6,0x42,0x68,0x41,0x99,0x2D,0x0F,0xB0,0x54,0xBB,0x16
    };
    for(int i = 0; i < 16; i++)
    {
        state[i] = SBOX[state[i]];
    }

    //(void)state; // remove after implementing
}

void InvSubBytes(uint8_t state[16]) {
    /* TODO:
     *   - Define INV_SBOX[256]
     *   - For i in 0..15: state[i] = INV_SBOX[state[i]];
     */
    static const uint8_t INV_SBOX[256] = {
        0x52,0x09,0x6A,0xD5,0x30,0x36,0xA5,0x38,0xBF,0x40,0xA3,0x9E,0x81,0xF3,0xD7,0xFB,
        0x7C,0xE3,0x39,0x82,0x9B,0x2F,0xFF,0x87,0x34,0x8E,0x43,0x44,0xC4,0xDE,0xE9,0xCB,
        0x54,0x7B,0x94,0x32,0xA6,0xC2,0x23,0x3D,0xEE,0x4C,0x95,0x0B,0x42,0xFA,0xC3,0x4E,
        0x08,0x2E,0xA1,0x66,0x28,0xD9,0x24,0xB2,0x76,0x5B,0xA2,0x49,0x6D,0x8B,0xD1,0x25,
        0x72,0xF8,0xF6,0x64,0x86,0x68,0x98,0x16,0xD4,0xA4,0x5C,0xCC,0x5D,0x65,0xB6,0x92,
        0x6C,0x70,0x48,0x50,0xFD,0xED,0xB9,0xDA,0x5E,0x15,0x46,0x57,0xA7,0x8D,0x9D,0x84,
        0x90,0xD8,0xAB,0x00,0x8C,0xBC,0xD3,0x0A,0xF7,0xE4,0x58,0x05,0xB8,0xB3,0x45,0x06,
        0xD0,0x2C,0x1E,0x8F,0xCA,0x3F,0x0F,0x02,0xC1,0xAF,0xBD,0x03,0x01,0x13,0x8A,0x6B,
        0x3A,0x91,0x11,0x41,0x4F,0x67,0xDC,0xEA,0x97,0xF2,0xCF,0xCE,0xF0,0xB4,0xE6,0x73,
        0x96,0xAC,0x74,0x22,0xE7,0xAD,0x35,0x85,0xE2,0xF9,0x37,0xE8,0x1C,0x75,0xDF,0x6E,
        0x47,0xF1,0x1A,0x71,0x1D,0x29,0xC5,0x89,0x6F,0xB7,0x62,0x0E,0xAA,0x18,0xBE,0x1B,
        0xFC,0x56,0x3E,0x4B,0xC6,0xD2,0x79,0x20,0x9A,0xDB,0xC0,0xFE,0x78,0xCD,0x5A,0xF4,
        0x1F,0xDD,0xA8,0x33,0x88,0x07,0xC7,0x31,0xB1,0x12,0x10,0x59,0x27,0x80,0xEC,0x5F,
        0x60,0x51,0x7F,0xA9,0x19,0xB5,0x4A,0x0D,0x2D,0xE5,0x7A,0x9F,0x93,0xC9,0x9C,0xEF,
        0xA0,0xE0,0x3B,0x4D,0xAE,0x2A,0xF5,0xB0,0xC8,0xEB,0xBB,0x3C,0x83,0x53,0x99,0x61,
        0x17,0x2B,0x04,0x7E,0xBA,0x77,0xD6,0x26,0xE1,0x69,0x14,0x63,0x55,0x21,0x0C,0x7D
    };
     for(int i = 0; i < 16; i++)
     {
        state[i] = INV_SBOX[state[i]];
     }
    //(void)state;
}

void ShiftRows(uint8_t state[16]) {
    /* TODO:
     *   - Treat as 4x4 matrix (row r, column c)
     *   - Left rotate row r by r positions
     *   - Column-major indexing via IDX(r,c)
     */

    // copy the state since the 2 for loops might overwrite a position when its needed later
    uint8_t state_cpy[16];
    for(int i = 0; i < 16; i++)
    {
        state_cpy[i] = state[i];
    }

    for(int r = 0; r < 4; r++)
    {
        for(int c = 0; c < 4; c++)
        {
            // (c + r) % 4 lets us rotate left by row index
            state[IDX(r, c)] = state_cpy[IDX(r, ((c + r) % 4))];
        }
    }
    //(void)state;
}

void InvShiftRows(uint8_t state[16]) {
    /* TODO:
     *   - Right rotate row r by r positions (inverse of ShiftRows)
     */
    
    uint8_t state_cpy[16];
    for(int i = 0; i < 16; i++)
    {
        state_cpy[i] = state[i];
    }

    for(int r = 0; r < 4; r++)
    {
        for(int c = 0; c < 4; c++)
        {
            // (c - r) % 4 lets us rotate right by row index
            // + 4 allows the answer to not be negative
            state[IDX(r, c)] = state_cpy[IDX(r, ((c - r + 4) % 4))];
        }
    }
    //(void)state;
}

/* xtime helper (multiply by 0x02 in GF(2^8)) — useful for MixColumns */
static inline uint8_t xtime(uint8_t x) {
    return (uint8_t)((x & 0x80) ? ((x << 1) ^ 0x1B) : (x << 1));
}
// more helpers for mixing columns
static inline uint8_t mul2(uint8_t x) {
    return xtime(x);
}
static inline uint8_t mul3(uint8_t x) {
    return (uint8_t)(xtime(x) ^ x);
}

static inline uint8_t mul9 (uint8_t x){
    uint8_t x2=xtime(x);
    uint8_t x4=xtime(x2);
    uint8_t x8=xtime(x4);
    return (uint8_t)(x8 ^ x);
}
static inline uint8_t mul11(uint8_t x){
    uint8_t x2=xtime(x);
    uint8_t x4=xtime(x2);
    uint8_t x8=xtime(x4);
    return (uint8_t)(x8 ^ x2 ^ x);
}
static inline uint8_t mul13(uint8_t x){
    uint8_t x2=xtime(x);
    uint8_t x4=xtime(x2);
    uint8_t x8=xtime(x4);
    return (uint8_t)(x8 ^ x4 ^ x);
}
static inline uint8_t mul14(uint8_t x){
    uint8_t x2=xtime(x);
    uint8_t x4=xtime(x2);
    uint8_t x8=xtime(x4);
    return (uint8_t)(x8 ^ x4 ^ x2);
}
void MixColumns(uint8_t state[16]) {
    /* TODO:
     *   - Process each column independently:
     *       For column c, get s0=state[IDX(0,c)]..s3=state[IDX(3,c)]
     *     Use:
     *       mul2(x) = xtime(x)
     *       mul3(x) = xtime(x) ^ x
     *     Then:
     *       s'0 = 02•s0 ⊕ 03•s1 ⊕ 01•s2 ⊕ 01•s3
     *       s'1 = 01•s0 ⊕ 02•s1 ⊕ 03•s2 ⊕ 01•s3
     *       s'2 = 01•s0 ⊕ 01•s1 ⊕ 02•s2 ⊕ 03•s3
     *       s'3 = 03•s0 ⊕ 01•s1 ⊕ 01•s2 ⊕ 02•s3
     *   - Write results back to the same column
     */
    
    for(int c = 0; c < 4; c++)
    {
        uint8_t s0 = state[IDX(0, c)];
        uint8_t s1 = state[IDX(1, c)];
        uint8_t s2 = state[IDX(2, c)];
        uint8_t s3 = state[IDX(3, c)];

        uint8_t r0 = (uint8_t)(mul2(s0) ^ mul3(s1) ^ s2 ^ s3);
        uint8_t r1 = (uint8_t)(s0 ^ mul2(s1) ^ mul3(s2) ^ s3);
        uint8_t r2 = (uint8_t)(s0 ^ s1 ^ mul2(s2) ^ mul3(s3));
        uint8_t r3 = (uint8_t)(mul3(s0) ^ s1 ^ s2 ^ mul2(s3));

        state[IDX(0,c)] = r0;
        state[IDX(1,c)] = r1;
        state[IDX(2,c)] = r2;
        state[IDX(3,c)] = r3;
        
    }
    
    //(void)state;
}

void InvMixColumns(uint8_t state[16]) {
    /* TODO:
     *   - Use inverse matrix with multipliers 0x0E,0x0B,0x0D,0x09
     *   - You may implement mul9/mul11/mul13/mul14 using xtime chains
     */
    
    for(int c = 0; c < 4; c++)
    {
        uint8_t s0 = state[IDX(0, c)];
        uint8_t s1 = state[IDX(1, c)];
        uint8_t s2 = state[IDX(2, c)];
        uint8_t s3 = state[IDX(3, c)];

        uint8_t r0 = (uint8_t)(mul14(s0) ^ mul11(s1) ^ mul13(s2) ^ mul9(s3));
        uint8_t r1 = (uint8_t)(mul9 (s0) ^ mul14(s1) ^ mul11(s2) ^ mul13(s3));
        uint8_t r2 = (uint8_t)(mul13(s0) ^ mul9 (s1) ^ mul14(s2) ^ mul11(s3));
        uint8_t r3 = (uint8_t)(mul11(s0) ^ mul13(s1) ^ mul9 (s2) ^ mul14(s3));

        state[IDX(0,c)] = r0;
        state[IDX(1,c)] = r1;
        state[IDX(2,c)] = r2;
        state[IDX(3,c)] = r3;
        
    }
    (void)state;
}

void AddRoundKey(uint8_t state[16], const uint8_t roundKey[16]) {
    for (int i = 0; i < 16; ++i) state[i] ^= roundKey[i];
}

/* =========================
   Program entry & loop
   ========================= */

int main(void) {
    uint8_t state[16] = {0};

    /* 1) Initial plaintext prompt */
    puts("Enter plaintext hex (0..32 hex chars):");
    char line[LINE_MAX_LEN];
    while (1) {
        if (!read_line(line)) return 0; // EOF
        // Remove spaces
        char hex[LINE_MAX_LEN];
        size_t j = 0;
        for (size_t i = 0; line[i] && j+1 < sizeof(hex); ++i) {
            if (!isspace((unsigned char)line[i])) hex[j++] = line[i];
        }
        hex[j] = '\0';
        to_upper_hex(hex);

        if (strlen(hex) == 0 || (strlen(hex) % 2 == 0 && strlen(hex) <= 32 && is_hex_string(hex))) {
            if (!parse_hex_to_16(hex, state)) {
                puts("ERROR");
                continue;
            }
            print_state_line(state);
            break;
        } else {
            puts("ERROR");
        }
    }

    /* 2) Command loop */
    while (1) {
        puts("CMD? (type HELP)");
        if (!read_line(line)) break;

        // Split first token
        char *cmd = strtok(line, " \t");
        if (!cmd) { puts("ERROR"); continue; }

        // Uppercase command for case-insensitive match
        for (char *p = cmd; *p; ++p) *p = (char)toupper((unsigned char)*p);

        if (strcmp(cmd, "HELP") == 0) {
            print_help();
            continue;
        } else if (strcmp(cmd, "SUB") == 0) {
            SubBytes(state);
            print_state_line(state);
        } else if (strcmp(cmd, "INV_SUB") == 0) {
            InvSubBytes(state);
            print_state_line(state);
        } else if (strcmp(cmd, "SHIFT") == 0) {
            ShiftRows(state);
            print_state_line(state);
        } else if (strcmp(cmd, "INV_SHIFT") == 0) {
            InvShiftRows(state);
            print_state_line(state);
        } else if (strcmp(cmd, "MIX") == 0) {
            MixColumns(state);
            print_state_line(state);
        } else if (strcmp(cmd, "INV_MIX") == 0) {
            InvMixColumns(state);
            print_state_line(state);
        } else if (strcmp(cmd, "XOR") == 0) {
            char *arg = strtok(NULL, " \t");
            if (!arg) { puts("ERROR"); continue; }
            // Remove spaces in key and validate
            char keyhex[LINE_MAX_LEN];
            size_t j = 0;
            for (size_t i = 0; arg[i] && j+1 < sizeof(keyhex); ++i) {
                if (!isspace((unsigned char)arg[i])) keyhex[j++] = arg[i];
            }
            keyhex[j] = '\0';
            to_upper_hex(keyhex);

            if (strlen(keyhex) != 32 || !is_hex_string(keyhex)) {
                puts("ERROR");
                continue;
            }
            uint8_t key[16];
            if (!parse_hex_to_16(keyhex, key)) {
                puts("ERROR");
                continue;
            }
            AddRoundKey(state, key);
            print_state_line(state);
        } else if (strcmp(cmd, "RESET") == 0) {
            char *arg = strtok(NULL, " \t");
            if (!arg) arg = ""; // allow empty => zero state
            // strip spaces in provided hex
            char hex[LINE_MAX_LEN];
            size_t j = 0;
            for (size_t i = 0; arg[i] && j+1 < sizeof(hex); ++i) {
                if (!isspace((unsigned char)arg[i])) hex[j++] = arg[i];
            }
            hex[j] = '\0';
            to_upper_hex(hex);

            if ((strlen(hex) <= 32) && (strlen(hex) % 2 == 0) && (strlen(hex) == 0 || is_hex_string(hex))) {
                if (!parse_hex_to_16(hex, state)) { puts("ERROR"); continue; }
                print_state_line(state);
            } else {
                puts("ERROR");
            }
        } else if (strcmp(cmd, "PRINT") == 0) {
            print_state_line(state);
        } else if (strcmp(cmd, "EXIT") == 0) {
            break;
        } else {
            puts("ERROR");
        }
    }

    return 0;
}
