/*
 * PS2 EE MMI correctness + isolated crypto timing.
 * Regression KATs and differential checks are NEVER timed.
 * Benchmarks use identical deterministic inputs and calls in three
 * separately linked namespaces (MMI, scalar, fused Poly1305).
 */
#include <debug.h>
#include <kernel.h>
#include <stdio.h>
#include <stdint.h>
#ifndef PS2_CONFIG_CHACHA
# define PS2_CONFIG_CHACHA 0
#endif
#ifndef PS2_CONFIG_SHA
# define PS2_CONFIG_SHA 0
#endif
#ifndef PS2_CONFIG_GHASH
# define PS2_CONFIG_GHASH 0
#endif
#ifndef PS2_CONFIG_AES
# define PS2_CONFIG_AES 0
#endif
#ifndef PS2_CONFIG_BN
# define PS2_CONFIG_BN 0
#endif
#ifdef PS2_AB
#include <timer.h>
#endif

typedef int (*test_fn)(int, char **);
int ps2_test_chacha20(int, char **);
int ps2_test_sha256(int, char **);
int ps2_test_poly1305(int, char **);
int ps2_test_aes(int, char **);
int ps2_test_ghash(int, char **);
int ps2_test_bn_mont(int, char **);
int ps2_test_x25519(int, char **);
int ps2_test_rsa(int, char **);
int ps2_test_p256_ecdh(int, char **);
int ps2_test_aes_gcm(int, char **);

#ifndef PS2_AB
static int run(const char *name, test_fn test)
{
    char *argv[] = { (char *)name, NULL };
    int result;
    scr_printf("%-12s RUNNING\n", name);
    printf("PS2 MMI: running %s\n", name);
    fflush(stdout);
    result = test(1, argv);
    scr_printf("             %s (code %d)\n", result ? "FAIL" : "PASS", result);
    printf("PS2 MMI: %s %s (code %d)\n", name,
           result ? "FAIL" : "PASS", result);
    fflush(stdout);
    return result != 0;
}

int main(void)
{
    int failures = 0;
    init_scr();
    scr_printf("OpenSSL PS2 EE MMI regression tests\n");
    scr_printf("10 standalone suites / R5900 assembly\n\n");
    failures += run("ChaCha20", ps2_test_chacha20);
    failures += run("SHA224/256", ps2_test_sha256);
    failures += run("Poly1305", ps2_test_poly1305);
    failures += run("AES", ps2_test_aes);
    failures += run("GHASH", ps2_test_ghash);
    failures += run("BN Mont", ps2_test_bn_mont);
    failures += run("X25519", ps2_test_x25519);
    failures += run("RSA", ps2_test_rsa);
    failures += run("P256 ECDH", ps2_test_p256_ecdh);
    failures += run("AES-GCM", ps2_test_aes_gcm);
    scr_printf("\n%s failures=%d\n",
               failures ? "TEST: FAIL!" : "TEST: OK!", failures);
    fflush(stdout);
    SleepThread();
    return failures != 0;
}
#else
#define SAMPLES 6

int b_ps2_test_chacha20(int, char **);
int b_ps2_test_sha256(int, char **);
int b_ps2_test_poly1305(int, char **);
int b_ps2_test_aes(int, char **);
int b_ps2_test_ghash(int, char **);
int b_ps2_test_bn_mont(int, char **);
int b_ps2_test_x25519(int, char **);
int b_ps2_test_rsa(int, char **);
int b_ps2_test_p256_ecdh(int, char **);
int b_ps2_test_aes_gcm(int, char **);
int f_ps2_test_poly1305(int, char **);

int ps2_bench_prepare(void);
void ps2_bench_reset(unsigned int);
int ps2_bench_run(unsigned int, unsigned int);
uint32_t ps2_bench_digest(unsigned int);
int b_ps2_bench_prepare(void);
void b_ps2_bench_reset(unsigned int);
int b_ps2_bench_run(unsigned int, unsigned int);
uint32_t b_ps2_bench_digest(unsigned int);
int f_ps2_bench_prepare(void);
void f_ps2_bench_reset(unsigned int);
int f_ps2_bench_run(unsigned int, unsigned int);
uint32_t f_ps2_bench_digest(unsigned int);

struct suite {
    const char *name;
    test_fn tests[3];
    unsigned int reps;
};
static const struct suite suites[] = {
    {"ChaCha20", {ps2_test_chacha20,b_ps2_test_chacha20,NULL}, 12},
    {"SHA224/256",{ps2_test_sha256,b_ps2_test_sha256,NULL}, 6},
    {"Poly1305", {ps2_test_poly1305,b_ps2_test_poly1305,
                   f_ps2_test_poly1305}, 12},
    {"AES",      {ps2_test_aes,b_ps2_test_aes,NULL}, 5},
    {"GHASH",    {ps2_test_ghash,b_ps2_test_ghash,NULL}, 4},
    {"BN Mont",  {ps2_test_bn_mont,b_ps2_test_bn_mont,NULL}, 8},
    {"X25519",   {ps2_test_x25519,b_ps2_test_x25519,NULL}, 1},
    {"RSA",      {ps2_test_rsa,b_ps2_test_rsa,NULL}, 1},
    {"P256 ECDH",{ps2_test_p256_ecdh,b_ps2_test_p256_ecdh,NULL}, 1},
    {"AES-GCM",  {ps2_test_aes_gcm,b_ps2_test_aes_gcm,NULL}, 2}
};
static const unsigned int suite_count =
    (unsigned int)(sizeof(suites) / sizeof(suites[0]));

struct backend {
    int (*prepare)(void);
    void (*reset)(unsigned int);
    int (*run)(unsigned int, unsigned int);
    uint32_t (*digest)(unsigned int);
};
static const struct backend backends[3] = {
    {ps2_bench_prepare,ps2_bench_reset,ps2_bench_run,ps2_bench_digest},
    {b_ps2_bench_prepare,b_ps2_bench_reset,b_ps2_bench_run,
     b_ps2_bench_digest},
    {f_ps2_bench_prepare,f_ps2_bench_reset,f_ps2_bench_run,
     f_ps2_bench_digest}
};

/* Median of six samples avoids locking all benchmarks into an A-first
 * thermal/cache ordering. Sampling order is AB, BA, AB, BA etc.; for
 * Poly1305 A/B/F each order appears twice as the first candidate. */
static double median6(u64 data[SAMPLES])
{
    u64 temp[SAMPLES], v;
    unsigned int i, j;
    for (i = 0; i < SAMPLES; ++i)
        temp[i] = data[i];
    for (i = 1; i < SAMPLES; ++i) {
        v = temp[i];
        j = i;
        while (j > 0 && temp[j-1] > v) {
            temp[j] = temp[j-1];
            --j;
        }
        temp[j] = v;
    }
    return ((double)temp[2] + (double)temp[3]) / 2.0;
}

static int validate_all(void)
{
    unsigned int i, mode;
    int failures = 0;
    init_scr();
    scr_printf("OpenSSL PS2 correctness (NOT timed)\n");
    scr_printf("A: PMULTUW/MMI B: scalar F: fused Poly\n\n");
    for (i = 0; i < suite_count; ++i) {
        for (mode = 0; mode < (i == 2 ? 3U : 2U); ++mode) {
            char *argv[] = {(char *)suites[i].name,NULL};
            int code;
            printf("VALIDATE %s %c start\n",suites[i].name,
                   mode == 2 ? 'F' : 'A'+(int)mode);
            fflush(stdout);
            code = suites[i].tests[mode](1,argv);
            if (code != 0)
                ++failures;
            printf("VALIDATE %s %c %s (code=%d)\n",
                   suites[i].name,mode == 2 ? 'F' : 'A'+(int)mode,
                   code ? "FAIL" : "PASS", code);
            fflush(stdout);
        }
        scr_setfontcolor(0x00ffffff);
        scr_printf("%-12s regression done\n", suites[i].name);
    }
    scr_printf("\nValidation failures: %d\n", failures);
    printf("VALIDATION RESULT: %d failures\n", failures);
    return failures == 0;
}

static int benchmark_one(unsigned int suite)
{
    u64 samples[3][SAMPLES] = {{0}};
    uint32_t digests[3];
    double med[3], milliseconds[3];
    unsigned int sample, step, mode, variants = suite == 2 ? 3U : 2U;
    unsigned int reps = suites[suite].reps;
    unsigned int baseline;
    int row = 3 + (int)suite * 2;

    scr_setXY(0,row);
    scr_setfontcolor(0x00ffffff);
    scr_printf("%-12s %3u rep x %d  ", suites[suite].name,
               reps, SAMPLES);

    for (sample = 0; sample < SAMPLES; ++sample) {
        uint32_t canonical = 0;
        for (step = 0; step < variants; ++step) {
            /* For 2 variants: AB/BA, for 3: ABF/BFA/FAB. */
            if (variants == 2)
                mode = (step + sample) & 1U;
            else
                mode = (step + sample) % 3U;
            backends[mode].reset(suite);
            {
                u64 start = GetTimerSystemTime();
                int worked = backends[mode].run(suite,reps);
                u64 elapsed = GetTimerSystemTime() - start;
                /* The digest and result check happen AFTER the timer. */
                digests[mode] = backends[mode].digest(suite);
                if (!worked || elapsed == 0) {
                    printf("BENCH FAIL: %s mode %u sample %u run/timer\n",
                           suites[suite].name,mode,sample);
                    return 0;
                }
                samples[mode][sample] = elapsed;
            }
        }
        baseline = 0;
        canonical = digests[baseline];
        for (mode = 1; mode < variants; ++mode) {
            if (digests[mode] != canonical) {
                printf("BENCH FAIL: %s sample %u A=%08lx B=%08lx F=%08lx\n",
                       suites[suite].name,sample,
                       (unsigned long)digests[0],
                       (unsigned long)digests[1],
                       (unsigned long)(variants == 3 ? digests[2] : 0));
                return 0;
            }
        }
    }
    for (mode = 0; mode < variants; ++mode) {
        med[mode] = median6(samples[mode]);
        milliseconds[mode] = med[mode] * 1000.0 / kBUSCLK;
    }
    scr_setXY(0,row+1);
    scr_setfontcolor(0x0000ff00);
    if (variants == 3)
        scr_printf("A:%7.2f B:%7.2f F:%7.2f ms ",
                   milliseconds[0],milliseconds[1],milliseconds[2]);
    else
        scr_printf("A:%9.3f B:%9.3f ms ",
                   milliseconds[0],milliseconds[1]);
    printf("BENCH %s reps=%u n=%d A=%.6f ms B=%.6f ms "
           "B/A=%.4fx checksum=%08lx\n",
           suites[suite].name,reps,SAMPLES,milliseconds[0],
           milliseconds[1],med[1]/med[0],
           (unsigned long)digests[0]);
    if (variants == 3)
        printf("BENCH Poly1305 fused F=%.6f ms B/F=%.4fx A/F=%.4fx\n",
               milliseconds[2],med[1]/med[2],med[0]/med[2]);
    fflush(stdout);
    return 1;
}

int main(void)
{
    unsigned int i;
    int failures = 0;
    if (!validate_all()) {
        scr_printf("\nTEST: FAIL! No benchmark on invalid results.\n");
        SleepThread();
        return 1;
    }
    for (i = 0; i < 3; ++i)
        if (!backends[i].prepare()) {
            printf("BENCH FAIL: mode %u preparation failed\n",i);
            SleepThread();
            return 1;
        }

    init_scr();
    scr_printf("OpenSSL PS2 crypto-only timings\n");
    scr_printf("A:MMI  B:scalar  F:Poly PMADDUW\n");
    scr_printf("C%d S%d G%d K%d BN%d med6\n",
               PS2_CONFIG_CHACHA,PS2_CONFIG_SHA,
               PS2_CONFIG_GHASH,PS2_CONFIG_AES,PS2_CONFIG_BN);
    printf("PS2 SCHEDULE C=%d S=%d G=%d K=%d BN=%d (A only)\n",
           PS2_CONFIG_CHACHA,PS2_CONFIG_SHA,
           PS2_CONFIG_GHASH,PS2_CONFIG_AES,PS2_CONFIG_BN);
    for (i = 0; i < suite_count; ++i) {
        if (!benchmark_one(i)) {
            ++failures;
            scr_setXY(0,3+(int)i*2+1);
            scr_setfontcolor(0x000000ff);
            scr_printf("BENCH FAIL - see stdout       ");
        }
    }
    scr_setXY(0,23);
    scr_setfontcolor(failures ? 0x000000ff : 0x0000ff00);
    scr_printf("%s regression=OK benchmark_failures=%d\n",
               failures ? "TEST: FAIL!" : "TEST: OK!",failures);
    printf("PS2 BENCH RESULT: %d failures\n",failures);
    fflush(stdout);
    SleepThread();
    return failures != 0;
}
#endif
