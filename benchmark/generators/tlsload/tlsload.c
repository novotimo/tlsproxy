// tlsload: a TLS load generator with an open-model arrival process.
//
// tls-perf and wrk are closed-loop: they hold N connections and start a new
// one only when an old one finishes, so they never offer more load than the
// subject can absorb and a subject that slows down simply receives less work.
// Real clients do not wait their turn. With -r the arrival schedule is fixed
// in advance from a Poisson process, so a subject that slows down accumulates
// a queue and eventually sheds, which is the behaviour worth measuring.
//
// Modes cover the three shapes a TLS terminator sees: connection churn
// (handshake), many mostly-idle connections (hold), and bulk transfer over
// established connections (request).
//
// Needs -D_GNU_SOURCE for accept4/SOCK_NONBLOCK and -lssl -lcrypto -lpthread.

#include <errno.h>
#include <math.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define MAX_EVENTS   1024
#define IO_BUF       65536

enum { M_HANDSHAKE, M_HOLD, M_REQUEST };
enum { S_CONNECT, S_HANDSHAKE, S_ACTIVE, S_HOLD };

typedef struct conn {
    struct conn *next;              // free list
    int          fd;
    SSL         *ssl;
    int          state;
    int          in_use;
    uint64_t     t_start;
    uint64_t     deadline;          // hold mode
    int          reqs_left;
    size_t       wsent;             // bytes written this request
    size_t       rrecv;             // bytes read back this request
} conn_t;

typedef struct {
    int        id;
    pthread_t  th;
    int        ep;
    conn_t    *pool;
    long       npool;
    conn_t    *freelist;
    int        inflight;
    // open model: absolute nanosecond times for the arrivals this thread owns
    uint64_t  *sched;
    long       nsched, next_sched;
    // results
    uint64_t  *lat;                 // handshake latency, ns
    long       nlat, caplat;
    uint64_t   completed, errors, shed;
    uint64_t   bytes_up, bytes_down;
    SSL_SESSION *sess;
    char       io[IO_BUF];
} worker_t;

static struct {
    const char *host, *port, *sni, *group, *cipher;
    int    mode, threads, conc, dur, tlsver, resume, quiet, shutdown;
    double rate;                    // open model, connections/sec, 0 = closed
    long   cap;                     // max in-flight in open model
    int    hold;                    // seconds, 0 = until the run ends
    long   payload;
    int    reqs;
} cfg = { .port = "8443", .mode = M_HANDSHAKE, .threads = 4, .conc = 64,
          .dur = 10, .tlsver = 3, .cap = 200000, .reqs = 1, .payload = 1024 };

static SSL_CTX         *ctx;
static struct addrinfo *addr;
static volatile sig_atomic_t stop_now;
static uint64_t t_end;

static uint64_t now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

static void on_signal(int sig) { (void)sig; stop_now = 1; }

static void die(const char *m) { fprintf(stderr, "tlsload: %s\n", m); exit(1); }

// ---------------------------------------------------------------- connections

static void conn_release(worker_t *w, conn_t *c) {
    if (c->ssl) {
        // -S sends close_notify before closing. Without it the socket is shut
        // with the server's post-handshake records still unread, which makes
        // the kernel send RST rather than FIN.
        if (cfg.shutdown)
            SSL_shutdown(c->ssl);
        SSL_free(c->ssl);
        c->ssl = NULL;
    }
    if (c->fd >= 0) {
        epoll_ctl(w->ep, EPOLL_CTL_DEL, c->fd, NULL);
        close(c->fd);
        c->fd = -1;
    }
    c->in_use = 0;
    c->next = w->freelist;
    w->freelist = c;
    w->inflight--;
}

static int conn_arm(worker_t *w, conn_t *c, uint32_t events) {
    struct epoll_event ev = { .events = events, .data.ptr = c };
    return epoll_ctl(w->ep, EPOLL_CTL_MOD, c->fd, &ev);
}

static int conn_start(worker_t *w) {
    conn_t *c = w->freelist;
    if (!c)
        return -1;

    int fd = socket(addr->ai_family, addr->ai_socktype | SOCK_NONBLOCK, 0);
    if (fd == -1)
        return -1;
    int on = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &on, sizeof(on));

    if (connect(fd, addr->ai_addr, addr->ai_addrlen) == -1
        && errno != EINPROGRESS) {
        close(fd);
        w->errors++;
        return -1;
    }

    w->freelist = c->next;
    c->in_use    = 1;
    c->fd        = fd;
    c->ssl       = NULL;
    c->state     = S_CONNECT;
    c->t_start   = now_ns();
    c->reqs_left = cfg.reqs;
    c->wsent     = 0;
    c->rrecv     = 0;

    struct epoll_event ev = { .events = EPOLLOUT, .data.ptr = c };
    if (epoll_ctl(w->ep, EPOLL_CTL_ADD, fd, &ev) == -1) {
        close(fd);
        c->fd = -1;
        c->in_use = 0;
        c->next = w->freelist;
        w->freelist = c;
        w->errors++;
        return -1;
    }
    w->inflight++;
    return 0;
}

static void record_latency(worker_t *w, uint64_t ns) {
    if (w->nlat < w->caplat)
        w->lat[w->nlat++] = ns;
}

// Returns 0 if the connection was released.
static int conn_drive(worker_t *w, conn_t *c) {
    for (;;) {
        switch (c->state) {
        case S_CONNECT: {
            int err = 0;
            socklen_t len = sizeof(err);
            if (getsockopt(c->fd, SOL_SOCKET, SO_ERROR, &err, &len) == -1
                || err != 0) {
                w->errors++;
                conn_release(w, c);
                return 0;
            }
            c->ssl = SSL_new(ctx);
            if (!c->ssl) {
                w->errors++;
                conn_release(w, c);
                return 0;
            }
            SSL_set_fd(c->ssl, c->fd);
            if (cfg.sni)
                SSL_set_tlsext_host_name(c->ssl, cfg.sni);
            if (cfg.resume && w->sess)
                SSL_set_session(c->ssl, w->sess);
            c->state = S_HANDSHAKE;
            break;
        }
        case S_HANDSHAKE: {
            int r = SSL_connect(c->ssl);
            if (r == 1) {
                record_latency(w, now_ns() - c->t_start);
                if (cfg.resume) {
                    SSL_SESSION *s = SSL_get1_session(c->ssl);
                    if (s) {
                        if (w->sess)
                            SSL_SESSION_free(w->sess);
                        w->sess = s;
                    }
                }
                if (cfg.mode == M_HANDSHAKE) {
                    w->completed++;
                    conn_release(w, c);
                    return 0;
                }
                if (cfg.mode == M_HOLD) {
                    c->state    = S_HOLD;
                    c->deadline = cfg.hold
                                ? now_ns() + (uint64_t)cfg.hold * 1000000000ull
                                : t_end;
                    if (conn_arm(w, c, EPOLLIN | EPOLLRDHUP) == -1) {
                        w->errors++;
                        conn_release(w, c);
                        return 0;
                    }
                    w->completed++;
                    return 1;
                }
                c->state = S_ACTIVE;
                c->wsent = c->rrecv = 0;
                break;
            }
            int e = SSL_get_error(c->ssl, r);
            if (e == SSL_ERROR_WANT_READ)
                return conn_arm(w, c, EPOLLIN) == -1
                       ? (w->errors++, conn_release(w, c), 0) : 1;
            if (e == SSL_ERROR_WANT_WRITE)
                return conn_arm(w, c, EPOLLOUT) == -1
                       ? (w->errors++, conn_release(w, c), 0) : 1;
            w->errors++;
            ERR_clear_error();
            conn_release(w, c);
            return 0;
        }
        case S_ACTIVE: {
            // Both directions must be driven together. Writing the whole
            // payload before reading any of it deadlocks against an echo peer
            // that stops reading while it has output pending, which is what
            // any correctly backpressuring sink does.
            int fatal = 0;
            while (c->wsent < (size_t)cfg.payload) {
                size_t want = (size_t)cfg.payload - c->wsent;
                int r = SSL_write(c->ssl, w->io,
                                  (int)(want > IO_BUF ? IO_BUF : want));
                if (r > 0) { c->wsent += (size_t)r; w->bytes_up += (uint64_t)r;
                             continue; }
                int e = SSL_get_error(c->ssl, r);
                if (e == SSL_ERROR_WANT_WRITE || e == SSL_ERROR_WANT_READ) break;
                fatal = 1; break;
            }
            while (!fatal && c->rrecv < (size_t)cfg.payload) {
                int r = SSL_read(c->ssl, w->io, IO_BUF);
                if (r > 0) { c->rrecv += (size_t)r; w->bytes_down += (uint64_t)r;
                             continue; }
                int e = SSL_get_error(c->ssl, r);
                if (e == SSL_ERROR_WANT_READ || e == SSL_ERROR_WANT_WRITE) break;
                fatal = 1; break;
            }
            if (fatal) {
                if (getenv("TLSLOAD_DEBUG") && w->errors < 3) {
                    unsigned long q = ERR_peek_last_error();
                    fprintf(stderr, "tlsload: active fatal: errno=%s ssl_err=%s"
                            " wsent=%zu rrecv=%zu\n", strerror(errno),
                            q ? ERR_reason_error_string(q) : "(none)",
                            c->wsent, c->rrecv);
                }
                w->errors++;
                ERR_clear_error();
                conn_release(w, c);
                return 0;
            }
            if (c->wsent >= (size_t)cfg.payload
                && c->rrecv >= (size_t)cfg.payload) {
                // -n 0 keeps the connection for the whole run, which is what
                // a data-path test wants: otherwise small payloads finish
                // fast, connections churn, and the generator measures its own
                // ephemeral port table rather than the proxy.
                if (cfg.reqs == 0 || --c->reqs_left > 0) {
                    c->wsent = c->rrecv = 0;
                    w->completed++;
                    continue;
                }
                w->completed++;
                conn_release(w, c);
                return 0;
            }
            uint32_t ev = 0;
            if (c->wsent < (size_t)cfg.payload) ev |= EPOLLOUT;
            if (c->rrecv < (size_t)cfg.payload) ev |= EPOLLIN;
            if (conn_arm(w, c, ev) == -1) {
                w->errors++;
                conn_release(w, c);
                return 0;
            }
            return 1;
        }
        case S_HOLD: {
            // A held connection becomes readable for two very different
            // reasons: the peer closed, or the server sent TLS 1.3
            // NewSessionTicket records after the handshake. Reading is the
            // only way to tell them apart, and treating a ticket as a close
            // turns this mode into a churn test.
            int r = SSL_read(c->ssl, w->io, IO_BUF);
            if (r > 0)
                return 1;
            int e = SSL_get_error(c->ssl, r);
            if (e == SSL_ERROR_WANT_READ || e == SSL_ERROR_WANT_WRITE)
                return 1;
            ERR_clear_error();
            conn_release(w, c);
            return 0;
        }
        default:
            conn_release(w, c);
            return 0;
        }
    }
}

// ---------------------------------------------------------------- worker loop

static void *worker_main(void *arg) {
    worker_t *w = arg;
    struct epoll_event evs[MAX_EVENTS];
    uint64_t last_sweep = 0;

    for (;;) {
        uint64_t now = now_ns();
        if (stop_now || now >= t_end)
            break;

        // Start whatever the model says should have started by now.
        if (cfg.rate > 0.0) {
            while (w->next_sched < w->nsched
                   && w->sched[w->next_sched] <= now) {
                w->next_sched++;
                if (w->inflight >= cfg.cap / cfg.threads || conn_start(w) == -1)
                    w->shed++;
            }
        } else {
            while (w->inflight < cfg.conc && conn_start(w) == 0)
                ;
        }

        int timeout = 1;
        if (cfg.rate > 0.0 && w->next_sched < w->nsched) {
            int64_t d = (int64_t)(w->sched[w->next_sched] - now) / 1000000;
            timeout = d < 0 ? 0 : (d > 100 ? 100 : (int)d);
        }

        // Held connections expire on their own deadline, which no readiness
        // event will ever announce, so they need a sweep. Only hold mode with
        // a finite -H can have any, and 10 Hz is fine for a seconds-scale
        // lifetime.
        if (cfg.mode == M_HOLD && cfg.hold > 0 && now - last_sweep > 100000000ull) {
            last_sweep = now;
            for (long i = 0; i < w->npool; i++) {
                conn_t *c = &w->pool[i];
                if (c->in_use && c->state == S_HOLD && c->deadline <= now)
                    conn_release(w, c);
            }
        }

        int n = epoll_wait(w->ep, evs, MAX_EVENTS, timeout);
        if (n == -1) {
            if (errno == EINTR)
                continue;
            break;
        }
        for (int i = 0; i < n; i++) {
            conn_t *c = evs[i].data.ptr;
            if (!c->in_use)
                continue;
            conn_drive(w, c);
        }
    }
    return NULL;
}

// ---------------------------------------------------------------- reporting

static int cmp_u64(const void *a, const void *b) {
    uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b;
    return x < y ? -1 : (x > y ? 1 : 0);
}

static double pct(const uint64_t *v, long n, double p) {
    if (n == 0) return 0.0;
    long i = (long)(p / 100.0 * (double)(n - 1) + 0.5);
    if (i < 0) i = 0;
    if (i >= n) i = n - 1;
    return (double)v[i] / 1e6;              // ns -> ms
}

// ---------------------------------------------------------------- setup

static void build_schedule(worker_t *w, uint64_t t0) {
    // Poisson arrivals: exponential gaps at this thread's share of the rate.
    double lambda = cfg.rate / cfg.threads;
    long   cap    = (long)(lambda * cfg.dur * 1.5) + 1024;
    w->sched  = malloc((size_t)cap * sizeof(uint64_t));
    if (!w->sched) die("out of memory for the arrival schedule");
    unsigned seed = (unsigned)(0x9e3779b9u * (unsigned)(w->id + 1));
    double t = 0.0;
    w->nsched = 0;
    while (w->nsched < cap) {
        double u = (double)(rand_r(&seed) + 1) / ((double)RAND_MAX + 2.0);
        t += -log(u) / lambda;
        if (t > cfg.dur) break;
        w->sched[w->nsched++] = t0 + (uint64_t)(t * 1e9);
    }
}

static void usage(void) {
    fprintf(stderr,
      "usage: tlsload [options] <host> <port>\n"
      "  -m handshake|hold|request   what each connection does (handshake)\n"
      "  -c N        closed loop: hold N concurrent connections (64)\n"
      "  -r RATE     open loop: start RATE connections/sec on a fixed schedule\n"
      "  -M N        max in-flight in open loop (200000)\n"
      "  -d SECS     duration (10)\n"
      "  -t N        threads (4)\n"
      "  -H SECS     hold seconds per connection, 0 = until the run ends\n"
      "  -b BYTES    payload per request (1024)\n"
      "  -n N        requests per connection, 0 = until the run ends (1)\n"
      "  -V 1.2|1.3  TLS version (1.3)\n"
      "  -G LIST     group list, eg X25519\n"
      "  -k LIST     ciphersuite (1.3) or cipher list (1.2)\n"
      "  -s NAME     SNI\n"
      "  -R          allow session resumption (off by default)\n"
      "  -S          send close_notify before closing\n");
    exit(2);
}

int main(int argc, char **argv) {
    int opt;
    while ((opt = getopt(argc, argv, "m:c:r:M:d:t:H:b:n:V:G:k:s:RqS")) != -1) {
        switch (opt) {
        case 'm':
            if (!strcmp(optarg, "handshake")) cfg.mode = M_HANDSHAKE;
            else if (!strcmp(optarg, "hold")) cfg.mode = M_HOLD;
            else if (!strcmp(optarg, "request")) cfg.mode = M_REQUEST;
            else usage();
            break;
        case 'c': cfg.conc    = atoi(optarg); break;
        case 'r': cfg.rate    = atof(optarg); break;
        case 'M': cfg.cap     = atol(optarg); break;
        case 'd': cfg.dur     = atoi(optarg); break;
        case 't': cfg.threads = atoi(optarg); break;
        case 'H': cfg.hold    = atoi(optarg); break;
        case 'b': cfg.payload = atol(optarg); break;
        case 'n': cfg.reqs    = atoi(optarg); break;
        case 'V': cfg.tlsver  = !strcmp(optarg, "1.2") ? 2 : 3; break;
        case 'G': cfg.group   = optarg; break;
        case 'k': cfg.cipher  = optarg; break;
        case 's': cfg.sni     = optarg; break;
        case 'R': cfg.resume  = 1; break;
        case 'S': cfg.shutdown = 1; break;
        case 'q': cfg.quiet   = 1; break;
        default: usage();
        }
    }
    if (optind + 2 != argc) usage();
    cfg.host = argv[optind];
    cfg.port = argv[optind + 1];
    if (cfg.threads < 1 || cfg.threads > 256) die("threads must be 1-256");
    if (cfg.conc < cfg.threads) cfg.conc = cfg.threads;

    signal(SIGPIPE, SIG_IGN);
    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);

    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    int gai = getaddrinfo(cfg.host, cfg.port, &hints, &addr);
    if (gai) die(gai_strerror(gai));

    ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) die("SSL_CTX_new");
    int v = cfg.tlsver == 2 ? TLS1_2_VERSION : TLS1_3_VERSION;
    SSL_CTX_set_min_proto_version(ctx, v);
    SSL_CTX_set_max_proto_version(ctx, v);
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
    if (!cfg.resume) {
        SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_OFF);
        SSL_CTX_set_options(ctx, SSL_OP_NO_TICKET);
    } else {
        SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_CLIENT
                                       | SSL_SESS_CACHE_NO_INTERNAL_STORE);
    }
    if (cfg.group && !SSL_CTX_set1_groups_list(ctx, cfg.group))
        die("bad group list");
    if (cfg.cipher) {
        int ok = cfg.tlsver == 3 ? SSL_CTX_set_ciphersuites(ctx, cfg.cipher)
                                 : SSL_CTX_set_cipher_list(ctx, cfg.cipher);
        if (!ok) die("bad cipher list");
    }

    long per = (cfg.rate > 0.0 ? cfg.cap : cfg.conc) / cfg.threads + 16;
    worker_t *ws = calloc((size_t)cfg.threads, sizeof(worker_t));
    if (!ws) die("out of memory");

    uint64_t t0 = now_ns() + 50000000ull;       // 50ms so all threads share t0
    t_end = t0 + (uint64_t)cfg.dur * 1000000000ull;

    for (int i = 0; i < cfg.threads; i++) {
        worker_t *w = &ws[i];
        w->id  = i;
        w->ep  = epoll_create1(0);
        if (w->ep == -1) die("epoll_create1");
        w->npool = per;
        w->pool  = calloc((size_t)per, sizeof(conn_t));
        if (!w->pool) die("out of memory for the connection pool");
        for (long j = per - 1; j >= 0; j--) {
            w->pool[j].fd   = -1;
            w->pool[j].next = w->freelist;
            w->freelist     = &w->pool[j];
        }
        w->caplat = 4000000;
        w->lat    = malloc((size_t)w->caplat * sizeof(uint64_t));
        if (!w->lat) die("out of memory for the latency samples");
        memset(w->io, 'x', sizeof(w->io));
        if (cfg.rate > 0.0) build_schedule(w, t0);
    }

    while (now_ns() < t0)
        ;
    for (int i = 0; i < cfg.threads; i++)
        if (pthread_create(&ws[i].th, NULL, worker_main, &ws[i]) != 0)
            die("pthread_create");
    for (int i = 0; i < cfg.threads; i++)
        pthread_join(ws[i].th, NULL);

    uint64_t done = 0, errs = 0, shed = 0, up = 0, down = 0;
    long total = 0;
    for (int i = 0; i < cfg.threads; i++) {
        done += ws[i].completed; errs += ws[i].errors; shed += ws[i].shed;
        up   += ws[i].bytes_up;  down += ws[i].bytes_down;
        total += ws[i].nlat;
    }
    uint64_t *all = malloc((size_t)(total ? total : 1) * sizeof(uint64_t));
    if (!all) die("out of memory merging latencies");
    long k = 0;
    for (int i = 0; i < cfg.threads; i++)
        for (long j = 0; j < ws[i].nlat; j++)
            all[k++] = ws[i].lat[j];
    qsort(all, (size_t)total, sizeof(uint64_t), cmp_u64);

    double secs = (double)cfg.dur;
    printf("mode=%s model=%s target=%s duration=%d threads=%d\n",
           cfg.mode == M_HANDSHAKE ? "handshake"
                                   : (cfg.mode == M_HOLD ? "hold" : "request"),
           cfg.rate > 0.0 ? "open" : "closed",
           cfg.rate > 0.0 ? "rate" : "concurrency", cfg.dur, cfg.threads);
    if (cfg.rate > 0.0)
        printf("offered_rate=%.0f\n", cfg.rate);
    else
        printf("concurrency=%d\n", cfg.conc);
    printf("completed=%llu rate=%.0f errors=%llu shed=%llu\n",
           (unsigned long long)done, (double)done / secs,
           (unsigned long long)errs, (unsigned long long)shed);
    printf("handshakes=%ld hs_ms_p50=%.3f p95=%.3f p99=%.3f p999=%.3f max=%.3f\n",
           total, pct(all, total, 50), pct(all, total, 95),
           pct(all, total, 99), pct(all, total, 99.9), pct(all, total, 100));
    if (cfg.mode == M_REQUEST)
        printf("bytes_up=%llu bytes_down=%llu mbytes_per_sec=%.2f\n",
               (unsigned long long)up, (unsigned long long)down,
               (double)(up + down) / secs / 1048576.0);
    return 0;
}
