#include <stdio.h>
#include <stdlib.h>
#include <math.h>

#define MAX_TRACES 100
#define NUM_KEYS   256
#define N_TRACES   100   // expected number of traces in cpa_traces.txt

// ========================= AES S-box =========================
static const unsigned char AES_SBOX[256] = {
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
};

// ====================== Hamming weight =======================
int hw(unsigned char x) {
    int count = 0;
    while (x) {
        count += x & 1;
        x >>= 1;
    }
    return count;
}

// =============== Pearson correlation (TODO) ==================
//
// Implement the Pearson correlation coefficient between
// arrays x[0..n-1] and y[0..n-1]:
//
//   rho = cov(x,y) / (sigma_x * sigma_y)
//
// where
//   cov(x,y) = sum_i (x_i - mean_x)(y_i - mean_y)
//   sigma_x^2 = sum_i (x_i - mean_x)^2
//   sigma_y^2 = sum_i (y_i - mean_y)^2
//
// The constant factors (1/n or 1/(n-1)) cancel out in the ratio.
// Make sure to handle the case sigma_x * sigma_y == 0.
//
double correlation(const double *x, const double *y, int n) {
    // TODO: compute mean_x and mean_y
    // TODO: compute numerator (covariance-like) and denominators
    // TODO: return rho

    // Temporary stub so the code compiles; replace with your implementation.
    if (n <= 1) return 0.0;

    // Means
    double mean_x = 0.0, mean_y = 0.0;
    for (int i = 0; i < n; i++) {
        mean_x += x[i];
        mean_y += y[i];
    }
    mean_x /= (double)n;
    mean_y /= (double)n;

    // Numerator and denominators
    double num = 0.0;
    double den_x = 0.0;
    double den_y = 0.0;

    for (int i = 0; i < n; i++) {
        double dx = x[i] - mean_x;
        double dy = y[i] - mean_y;
        num += dx * dy;
        den_x += dx * dx;
        den_y += dy * dy;
    }

    double denom = sqrt(den_x * den_y);
    if (denom == 0.0) return 0.0;

    return num / denom;
}

int main(void) {
    FILE *f = fopen("cpa_traces.txt", "r");
    if (!f) {
        perror("Error opening cpa_traces.txt");
        return 1;
    }

    unsigned int plaintexts[MAX_TRACES];
    double powers[MAX_TRACES];

    int n = 0;
    //while (n < MAX_TRACES && fscanf(f, "%u %lf", &plaintexts[n]) == 2) {
        // NOTE: the format string above is wrong; corrected below.
        // Keeping this comment so students see what to avoid.
   // }

    // Correct reading loop:
    rewind(f);
    n = 0;
    while (n < MAX_TRACES && fscanf(f, "%u %lf", &plaintexts[n], &powers[n]) == 2) {
        n++;
    }
    fclose(f);

    if (n != N_TRACES) {
        fprintf(stderr, "Warning: expected %d traces, read %d\n", N_TRACES, n);
    }

    double hyp[MAX_TRACES];   // hypothetical leakage for each trace
    double best_corr = 0.0;
    int    best_key  = -1;

    // ===================== CPA (student TODO) =====================
    //
    // For each key hypothesis k in 0..255:
    //   1. For each trace t in 0..n-1:
    //        - Let pt = (unsigned char)plaintexts[t]
    //        - Compute v = AES_SBOX[ pt ^ (unsigned char)k ]
    //        - Set hyp[t] = (double)hw(v)
    //   2. Compute rho = correlation(hyp, powers, n)
    //   3. Keep track of the key with the largest |rho|:
    //        if ( |rho| is better than |best_corr| ) then update best_corr and best_key.
    //
    // After completing the loop over k, best_key should be your recovered key.
    //
    // =================== YOUR CODE STARTS HERE ====================

    // TODO: implement the CPA loop described above.
        for (int k = 0; k < NUM_KEYS; k++) {
        // Build hypothetical leakage for this key guess
        for (int t = 0; t < n; t++) {
            unsigned char pt = (unsigned char)plaintexts[t];
            unsigned char v  = AES_SBOX[ (unsigned char)(pt ^ (unsigned char)k) ];
            hyp[t] = (double)hw(v);
        }

        // Correlate with measured power
        double rho = correlation(hyp, powers, n);

        // Track best |rho|
        if (fabs(rho) > fabs(best_corr)) {
            best_corr = rho;
            best_key = k;
        }
    }


    // ==================== YOUR CODE ENDS HERE =====================

    if (best_key < 0) {
        printf("CPA not implemented yet: best_key is still %d\n", best_key);
        return 0;
    }

    // Print results to the console for your own inspection.
    printf("Recovered key (decimal): %d\n", best_key);
    printf("Recovered key (hex): 0x%02X\n", best_key);
    printf("Correlation: %f\n", best_corr);

    // ================== Write key to student_key.txt ==============
    //
    // The grading script grade_cpa.py will, by default, read your
    // recovered key from student_key.txt. Here we write the key as
    // a decimal integer followed by a newline.
    //
    FILE *out = fopen("student_key.txt", "w");
    if (!out) {
        perror("Error opening student_key.txt for writing");
        return 1;
    }
    fprintf(out, "%d\n", best_key);
    fclose(out);

    printf("Wrote recovered key to student_key.txt\n");

    return 0;
}
