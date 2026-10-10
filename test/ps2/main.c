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

#define EE_WHITE 0x00ffffffU
#define EE_GREEN 0x0000ff00U
#if defined(PS2_AB) && !defined(PS2_SELECTED)
#define FIRST_TEST_ROW 1
#else
#define FIRST_TEST_ROW 4
#endif
static int result_row = 22;
static void ee_print_status(int row, const char *name, const char *status,
                            const char *detail)
{
    scr_setfontcolor(EE_WHITE);
    scr_setXY(0,row);
    scr_printf("%-12.12s %-6s %-47s", name, "", detail);
    scr_setXY(13,row);
    scr_setfontcolor(status[0]=='P' ? EE_GREEN : EE_WHITE);
    scr_printf("%-6.6s", status);
    scr_setfontcolor(EE_WHITE);
}
static void ee_print_result(int failed, unsigned int passed, unsigned int total)
{
    scr_setXY(0,result_row); scr_setfontcolor(EE_WHITE);
    scr_printf("RESULT: %-6s | CHECK+BENCH %2u/%2u | FAILURES=%d      ",
               "", passed, total, failed);
    scr_setXY(8,result_row);
    scr_setfontcolor(failed?EE_WHITE:EE_GREEN);
    scr_printf("%-6s", failed?"FAIL":"PASS");
    scr_setfontcolor(EE_WHITE);
}
#ifndef PS2_AB
static int run(unsigned int index, const char *name, test_fn test)
{
    char *argv[] = { (char *)name, NULL };
    int result;
    scr_setXY(0,FIRST_TEST_ROW+(int)index);
    scr_setfontcolor(0x00ffffff);
    scr_printf("%-12.12s %-6s %-15s", name, "RUN", "checking...");
    printf("VALIDATE %-12s START\n",name);
    fflush(stdout);
    result = test(1, argv);
    ee_print_status(FIRST_TEST_ROW+(int)index,name,result?"FAIL":"PASS","no benchmark");
    printf("VALIDATE %-12s %s (code=%d)\n",name,
           result ? "FAIL" : "PASS",result);
    fflush(stdout);
    return result != 0;
}
int main(void)
{
    unsigned int i;
    int failures = 0;
    static const struct { const char *name; test_fn fn; } tests[] = {
        {"ChaCha20",ps2_test_chacha20},{"SHA224/256",ps2_test_sha256},
        {"Poly1305",ps2_test_poly1305},{"AES",ps2_test_aes},
        {"GHASH",ps2_test_ghash},{"BN Mont",ps2_test_bn_mont},
        {"X25519",ps2_test_x25519},{"RSA",ps2_test_rsa},
        {"P256 ECDH",ps2_test_p256_ecdh},{"AES-GCM",ps2_test_aes_gcm}
    };
    init_scr();
    scr_setCursor(0);
    scr_setXY(0,0);scr_printf("OPENSSL RETRO | PS2 EE MMI | VALIDATION");
    scr_setXY(0,1);scr_printf("A=MMI | 10 suites | untimed correctness checks");
    scr_setXY(0,3);scr_printf("%-12s %-6s %s","FUNCTION","TEST","BENCHMARK");
    for(i=0;i<10;i++){
        scr_setXY(0,FIRST_TEST_ROW+(int)i);
        scr_printf("%-12.12s %-6s %-15s",tests[i].name,"WAIT","--");
    }
    for(i=0;i<10;i++) failures+=run(i,tests[i].name,tests[i].fn);
    ee_print_result(failures,10U-(unsigned int)failures,10U);
    printf("PS2 VALIDATION RESULT: failures=%d\n",failures);
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
#ifdef PS2_EXPERIMENTS
int r_ps2_test_bn_mont(int, char **);
int r_ps2_test_rsa(int, char **);
int r_ps2_test_p256_ecdh(int, char **);
int h_ps2_test_poly1305(int, char **);
int s_ps2_test_sha256(int, char **);
int g_ps2_test_ghash(int, char **);
int k_ps2_test_aes(int, char **);
int c_ps2_test_aes_gcm(int, char **);
int d_ps2_test_bn_mont(int, char **);
int d_ps2_test_rsa(int, char **);
int p_ps2_test_poly1305(int, char **);
int q_ps2_test_bn_mont(int, char **);
int q_ps2_test_rsa(int, char **);
int e_ps2_test_poly1305(int, char **);
int n_ps2_test_bn_mont(int, char **);
int n_ps2_test_rsa(int, char **);
int w_ps2_test_chacha20(int, char **);
#endif

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
#ifdef PS2_EXPERIMENTS
#define DECLARE_EXPERIMENT(prefix) \
    int prefix##_ps2_bench_prepare(void); \
    void prefix##_ps2_bench_reset(unsigned int); \
    int prefix##_ps2_bench_run(unsigned int, unsigned int); \
    uint32_t prefix##_ps2_bench_digest(unsigned int)
DECLARE_EXPERIMENT(r);
DECLARE_EXPERIMENT(h);
DECLARE_EXPERIMENT(s);
DECLARE_EXPERIMENT(g);
DECLARE_EXPERIMENT(k);
DECLARE_EXPERIMENT(c);
DECLARE_EXPERIMENT(d);
DECLARE_EXPERIMENT(p);
DECLARE_EXPERIMENT(q);
DECLARE_EXPERIMENT(e);
DECLARE_EXPERIMENT(n);
DECLARE_EXPERIMENT(w);
#endif

struct suite {
    const char *name;
    test_fn tests[3];
    unsigned int reps;
    unsigned int workload; /* original crypto workload, 0..9 */
    unsigned int optimized_backend; /* private namespace, A is 0 */
};
static const struct suite suites[] = {
#ifdef PS2_SELECTED
    {"ChaCha wrap",{w_ps2_test_chacha20,b_ps2_test_chacha20,NULL}, 12, 0, 14},
    {"SHA224/256",{ps2_test_sha256,b_ps2_test_sha256,NULL}, 6, 1, 0},
    {"Poly reduce",{e_ps2_test_poly1305,b_ps2_test_poly1305,NULL}, 12, 2, 12},
    {"AES",{ps2_test_aes,b_ps2_test_aes,NULL}, 5, 3, 0},
    {"GHASH u8",{g_ps2_test_ghash,b_ps2_test_ghash,NULL}, 4, 4, 6},
    {"BN shift",{d_ps2_test_bn_mont,b_ps2_test_bn_mont,NULL}, 8, 5, 9},
    {"X25519",{ps2_test_x25519,b_ps2_test_x25519,NULL}, 1, 6, 0},
    {"RSA tight",{q_ps2_test_rsa,b_ps2_test_rsa,NULL}, 1, 7, 11},
    {"P256 reg",{r_ps2_test_p256_ecdh,b_ps2_test_p256_ecdh,NULL}, 1, 8, 3},
    {"GCM u8",{c_ps2_test_aes_gcm,b_ps2_test_aes_gcm,NULL}, 2, 9, 8},
#else

    {"ChaCha20", {ps2_test_chacha20,b_ps2_test_chacha20,NULL}, 12, 0, 0},
    {"SHA224/256",{ps2_test_sha256,b_ps2_test_sha256,NULL}, 6, 1, 0},
    {"Poly1305", {ps2_test_poly1305,b_ps2_test_poly1305,
                   f_ps2_test_poly1305}, 12, 2, 0},
    {"AES",      {ps2_test_aes,b_ps2_test_aes,NULL}, 5, 3, 0},
    {"GHASH",    {ps2_test_ghash,b_ps2_test_ghash,NULL}, 4, 4, 0},
    {"BN Mont",  {ps2_test_bn_mont,b_ps2_test_bn_mont,NULL}, 8, 5, 0},
    {"X25519",   {ps2_test_x25519,b_ps2_test_x25519,NULL}, 1, 6, 0},
    {"RSA",      {ps2_test_rsa,b_ps2_test_rsa,NULL}, 1, 7, 0},
    {"P256 ECDH",{ps2_test_p256_ecdh,b_ps2_test_p256_ecdh,NULL}, 1, 8, 0},
    {"AES-GCM",  {ps2_test_aes_gcm,b_ps2_test_aes_gcm,NULL}, 2, 9, 0},
#ifdef PS2_EXPERIMENTS
    {"BN reg",   {r_ps2_test_bn_mont,b_ps2_test_bn_mont,NULL}, 8, 5, 3},
    {"RSA reg",  {r_ps2_test_rsa,b_ps2_test_rsa,NULL}, 1, 7, 3},
    {"P256 reg", {r_ps2_test_p256_ecdh,b_ps2_test_p256_ecdh,NULL}, 1, 8, 3},
    {"Poly hybrid",{h_ps2_test_poly1305,b_ps2_test_poly1305,NULL}, 12, 2, 4},
    {"SHA u4",   {s_ps2_test_sha256,b_ps2_test_sha256,NULL}, 6, 1, 5},
    {"GHASH u8", {g_ps2_test_ghash,b_ps2_test_ghash,NULL}, 4, 4, 6},
    {"AES K2early",{k_ps2_test_aes,b_ps2_test_aes,NULL}, 5, 3, 7},
    {"GCM u8",   {c_ps2_test_aes_gcm,b_ps2_test_aes_gcm,NULL}, 2, 9, 8},
    {"BN shift", {d_ps2_test_bn_mont,b_ps2_test_bn_mont,NULL}, 8, 5, 9},
    {"RSA shift",{d_ps2_test_rsa,b_ps2_test_rsa,NULL}, 1, 7, 9},
    {"Poly preload",{p_ps2_test_poly1305,b_ps2_test_poly1305,NULL}, 12, 2, 10},
    {"RSA tight", {q_ps2_test_rsa,b_ps2_test_rsa,NULL}, 1, 7, 11},
    {"Poly reduce",{e_ps2_test_poly1305,b_ps2_test_poly1305,NULL}, 12, 2, 12},
    {"RSA square",{n_ps2_test_rsa,b_ps2_test_rsa,NULL}, 1, 7, 13},
    {"ChaCha wrap",{w_ps2_test_chacha20,b_ps2_test_chacha20,NULL}, 12, 0, 14},
#endif
#endif /* PS2_SELECTED */
};
static const unsigned int suite_count =
    (unsigned int)(sizeof(suites) / sizeof(suites[0]));

struct backend {
    int (*prepare)(void);
    void (*reset)(unsigned int);
    int (*run)(unsigned int, unsigned int);
    uint32_t (*digest)(unsigned int);
};
static const struct backend backends[] = {
    [0] = {ps2_bench_prepare,ps2_bench_reset,ps2_bench_run,ps2_bench_digest},
    [1] = {b_ps2_bench_prepare,b_ps2_bench_reset,b_ps2_bench_run,b_ps2_bench_digest},
#ifndef PS2_SELECTED
    [2] = {f_ps2_bench_prepare,f_ps2_bench_reset,f_ps2_bench_run,f_ps2_bench_digest},
#endif
#ifdef PS2_EXPERIMENTS
#define EXPERIMENT_BACKEND(prefix) \
    {prefix##_ps2_bench_prepare, prefix##_ps2_bench_reset, \
     prefix##_ps2_bench_run, prefix##_ps2_bench_digest}
    [3] = EXPERIMENT_BACKEND(r),
    [6] = EXPERIMENT_BACKEND(g),
    [8] = EXPERIMENT_BACKEND(c),
    [9] = EXPERIMENT_BACKEND(d),
    [11] = EXPERIMENT_BACKEND(q),
    [12] = EXPERIMENT_BACKEND(e),
    [14] = EXPERIMENT_BACKEND(w),
#ifndef PS2_SELECTED
    [4] = EXPERIMENT_BACKEND(h),
    [5] = EXPERIMENT_BACKEND(s),
    [7] = EXPERIMENT_BACKEND(k),
    [10] = EXPERIMENT_BACKEND(p),
    [13] = EXPERIMENT_BACKEND(n),
#endif
#endif
};
static const unsigned int backend_count =
    (unsigned int)(sizeof(backends) / sizeof(backends[0]));

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

/* Each suite is validated immediately before its isolated speed test.
 * No diagnostics or GS writes run inside measured regions. */
static int scalar_validation[10]; /* 0=unrun, 1=pass, -1=fail per workload */
static int validate_one(unsigned int i)
{
    unsigned int mode, variants = suites[i].tests[2] != NULL ? 3U : 2U;
    int failures = 0;
    scr_setXY(0,FIRST_TEST_ROW+(int)i);
    scr_setfontcolor(0x00ffffff);
    scr_printf("%-12.12s %-6s %-30s", suites[i].name,"RUN","validating...");
    for(mode=0;mode<variants;mode++){
        char *argv[] = {(char *)suites[i].name,NULL};
#ifdef PS2_EXPERIMENTS
        if (suites[i].tests[0] == q_ps2_test_rsa && mode == 0) {
            char *bn_argv[] = {(char *)"RSA tight BN",NULL};
            if (q_ps2_test_bn_mont(1,bn_argv) != 0)
                ++failures;
        }
#ifndef PS2_SELECTED
        if (suites[i].tests[0] == n_ps2_test_rsa && mode == 0) {
            char *bn_argv[] = {(char *)"RSA square BN",NULL};
            if (n_ps2_test_bn_mont(1,bn_argv) != 0)
                ++failures;
        }
#endif /* !PS2_SELECTED */
#ifdef PS2_SELECTED
        if (suites[i].tests[0] == r_ps2_test_p256_ecdh && mode == 0) {
            char *bn_argv[] = {(char *)"P256 reg BN",NULL};
            if (r_ps2_test_bn_mont(1,bn_argv) != 0)
                ++failures;
        }
#endif
#endif /* PS2_EXPERIMENTS */
        int code;
        printf("VALIDATE %s %c start\n",suites[i].name,
               mode == 2 ? 'F' : 'A'+(int)mode);
        fflush(stdout);
        if (mode == 1 && scalar_validation[suites[i].workload] != 0) {
            code = scalar_validation[suites[i].workload] < 0;
            printf("VALIDATE %s B reused scalar regression result\n",suites[i].name);
        } else {
            code=suites[i].tests[mode](1,argv);
            if (mode == 1)
                scalar_validation[suites[i].workload] = code == 0 ? 1 : -1;
        }
        if(code!=0)++failures;
        printf("VALIDATE %s %c %s (code=%d)\n",suites[i].name,
               mode == 2 ? 'F' : 'A'+(int)mode,
               code?"FAIL":"PASS",code);
        fflush(stdout);
    }
    ee_print_status(FIRST_TEST_ROW+(int)i,suites[i].name,
                    failures?"FAIL":"PASS",
                    failures?"benchmark skipped":"timing...");
    return failures == 0;
}

static int benchmark_one(unsigned int suite)
{
    u64 samples[3][SAMPLES] = {{0}};
    uint32_t digests[3];
    double med[3], milliseconds[3];
    unsigned int sample, step, mode, variants = suites[suite].tests[2] != NULL ? 3U : 2U;
    unsigned int reps = suites[suite].reps;
    unsigned int workload = suites[suite].workload;
    unsigned int baseline;
    int row = FIRST_TEST_ROW + (int)suite;

    ee_print_status(row,suites[suite].name,"PASS","sampling...");

    for (sample = 0; sample < SAMPLES; ++sample) {
        uint32_t canonical = 0;
        for (step = 0; step < variants; ++step) {
            const struct backend *selected;
            unsigned int backend_index;
            /* For 2 variants: AB/BA, for 3: ABF/BFA/FAB. */
            if (variants == 2)
                mode = (step + sample) & 1U;
            else
                mode = (step + sample) % 3U;
            backend_index = mode == 0 ? suites[suite].optimized_backend : mode;
            selected = &backends[backend_index];
            selected->reset(workload);
            {
                u64 start = GetTimerSystemTime();
                int worked = selected->run(workload,reps);
                u64 elapsed = GetTimerSystemTime() - start;
                /* The digest and result check happen AFTER the timer. */
                digests[mode] = selected->digest(workload);
                if (!worked || elapsed == 0) {
                    printf("BENCH FAIL: %s mode %u sample %u run/timer\n",
                           suites[suite].name,mode,sample);
                    return 0;
                }
                samples[mode][sample] = elapsed;
            }
        }
        {
            char progress[48];
            snprintf(progress,sizeof(progress),"SAMPLE %u/%d",sample+1,SAMPLES);
            ee_print_status(row,suites[suite].name,"PASS",progress);
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
    {
        unsigned int best=0;
        const char *const names[]={"MMI","SCALAR","FUSED"};
        for(mode=1;mode<variants;mode++)
            if(med[mode]<med[best])best=mode;
        {
            char details[64];
            char rate[20];
            const unsigned int bytes[] = {
                4096U, 4096U, 4096U, 64U, 512U, 0U, 0U, 0U, 0U, 1024U
            };
            const unsigned int ops[] = {0,0,0,0,0,1,4,4,1,0};
            double seconds = milliseconds[0] / 1000.0;
            double value = bytes[workload] ?
                (double)(bytes[workload]*reps)/seconds/1000000.0 :
                (double)(ops[workload]*reps)/seconds;
            snprintf(rate,sizeof(rate),bytes[workload]?"%.2fMB/s":"%.1fop/s",value);
            snprintf(details,sizeof(details),
                     "%-6s %5.2fx A:%7.3f B:%7.3f %s",
                     names[best],med[1]/med[0],
                     milliseconds[0],milliseconds[1],rate);
            ee_print_status(row,suites[suite].name,"PASS",details);
            printf("BENCH_RATE,%s,MMI,%.6f,%s\n",
                   suites[suite].name,value,bytes[workload]?"MB/s":"ops/s");
        }
    }
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
    int failures=0,passed=0;
    result_row = FIRST_TEST_ROW + (int)suite_count;
    init_scr();
    /* PS2SDK cursor is visible as a white cell at the right edge unless
     * explicitly disabled. Never print newline on the last GS row. */
    scr_setCursor(0);
    scr_setXY(0,0);
#ifdef PS2_SELECTED
    scr_printf("PS2 EE | hardware-selected | validation + benchmark");
    scr_setXY(0,1);
    scr_printf("A=selected B=scalar | median6 | B/A>1 faster");
    scr_setXY(0,2);
    scr_printf("ChaCha wrap | Poly reduce | GHASH u8 | BN shift | RSA tight");
    scr_setXY(0,3);
    scr_printf("%-12s %-6s %-6s %-7s %s",
               "FUNCTION","TEST","BEST","B/A","A/B ms + selected rate");
#else
    scr_printf("%-12s %-6s %-6s %-7s %s C%dS%dG%dK%dN%d",
               "FUNCTION","TEST","BEST","B/A","A/B ms + MMI rate",
               PS2_CONFIG_CHACHA,PS2_CONFIG_SHA,PS2_CONFIG_GHASH,
               PS2_CONFIG_AES,PS2_CONFIG_BN);
#endif
    printf("PS2 EE MMI | A=MMI B=scalar F=fused | median6 | B/A>1 faster\n");
    for(i=0;i<suite_count;i++){
        scr_setXY(0,FIRST_TEST_ROW+(int)i);
        scr_printf("%-12.12s %-6s %-30s",suites[i].name,"WAIT","--");
    }
#ifdef PS2_SELECTED
    printf("PS2 PROFILE: selected | ten real-EE winners + scalar | no Poly F\n");
#elif defined(PS2_EXPERIMENTS)
    printf("PS2 EXTRA ROWS: BN/RSA/P256 reg, Poly hybrid, SHA u4, GHASH u8, AES K2early, GCM u8, BN/RSA shift, Poly preload, RSA tight, Poly reduce, RSA square, ChaCha wrap\n");
#endif
    printf("PS2 SCHEDULE C=%d S=%d G=%d K=%d BN=%d (A only)\n",
           PS2_CONFIG_CHACHA,PS2_CONFIG_SHA,
           PS2_CONFIG_GHASH,PS2_CONFIG_AES,PS2_CONFIG_BN);
    for(i=0;i<backend_count;i++){
        if (backends[i].prepare == NULL)
            continue;
        if(!backends[i].prepare()){
            ++failures;
            scr_setXY(0,result_row);scr_setfontcolor(EE_WHITE);
            scr_printf("RESULT: FAIL | backend %u preparation failed",i);
            printf("BENCH FAIL: mode %u preparation failed\n",i);
            fflush(stdout);
            SleepThread();
            return 1;
        }
    }
    for(i=0;i<suite_count;i++){
        if(!validate_one(i)){
            ++failures;
            continue; /* never benchmark a failed correctness check */
        }
        if(!benchmark_one(i)){
            ++failures;
            ee_print_status(FIRST_TEST_ROW+(int)i,suites[i].name,"FAIL","benchmark failed");
        }else ++passed;
    }
    ee_print_result(failures,(unsigned int)passed,suite_count);
    scr_setXY(0,result_row+1);
    scr_setfontcolor(0x00ffffff);
    scr_printf("COMPLETE | all suites visited | details on stdout");
    printf("PS2 BENCH RESULT: %d failures, %d complete suites\n",
           failures,passed);
    fflush(stdout);
    SleepThread();
    return failures!=0;
}
#endif
