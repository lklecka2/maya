#include <inttypes.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#define STRESS_MAX_WORKERS 1024
#define STRESS_DEFAULT_WORKERS 6
#define STRESS_DEFAULT_ITERATIONS 2000

typedef struct {
    pthread_mutex_t lock;
    uint64_t total_calls;
    uint64_t total_value;
    uint64_t worker_totals[STRESS_MAX_WORKERS];
} StressState;

typedef struct {
    StressState *state;
    int worker_id;
    int iterations;
} WorkerArg;

__attribute__((noinline, used)) uint64_t stress_value_c(int worker_id, int iteration) {
    uint64_t base = (uint64_t)(worker_id + 1) * 97u;
    uint64_t offset = (uint64_t)(iteration % 31) * 13u + 7u;
    uint64_t mixed = (base + offset) ^ ((uint64_t)(iteration + 3) * 17u);
    return mixed + (uint64_t)worker_id * 5u + (uint64_t)(iteration & 7);
}

__attribute__((noinline, used)) uint64_t stress_value_b(int worker_id, int iteration) {
    return stress_value_c(worker_id, iteration);
}

__attribute__((noinline, used)) uint64_t stress_value_a(int worker_id, int iteration) {
    return stress_value_b(worker_id, iteration);
}

__attribute__((noinline, used)) void stress_record_value(StressState *state, int worker_id, uint64_t value) {
    pthread_mutex_lock(&state->lock);
    state->total_calls += 1u;
    state->total_value += value;
    state->worker_totals[worker_id] += value;
    pthread_mutex_unlock(&state->lock);
}

__attribute__((noinline, used)) uint64_t stress_expected_worker(int worker_id, int iterations) {
    uint64_t total = 0;
    for (int i = 0; i < iterations; ++i) {
        total += stress_value_c(worker_id, i);
    }
    return total;
}

__attribute__((noinline, used)) uint64_t stress_expected_total(int workers, int iterations) {
    uint64_t total = 0;
    for (int worker = 0; worker < workers; ++worker) {
        total += stress_expected_worker(worker, iterations);
    }
    return total;
}

__attribute__((noinline, used)) void *stress_worker_main(void *arg) {
    WorkerArg *worker = (WorkerArg *)arg;
    for (int i = 0; i < worker->iterations; ++i) {
        uint64_t value = stress_value_a(worker->worker_id, i);
        stress_record_value(worker->state, worker->worker_id, value);
    }
    return 0;
}

__attribute__((noinline, used)) int stress_parse_positive(const char *text, int fallback) {
    char *end = 0;
    long value = strtol(text, &end, 10);
    if (end == text || *end != '\0' || value <= 0 || value > 1000000) {
        return fallback;
    }
    return (int)value;
}

int main(int argc, char **argv) {
    int workers = STRESS_DEFAULT_WORKERS;
    int iterations = STRESS_DEFAULT_ITERATIONS;
    if (argc > 1) {
        workers = stress_parse_positive(argv[1], workers);
    }
    if (argc > 2) {
        iterations = stress_parse_positive(argv[2], iterations);
    }
    if (workers > STRESS_MAX_WORKERS) {
        workers = STRESS_MAX_WORKERS;
    }

    StressState state = {
        .lock = PTHREAD_MUTEX_INITIALIZER,
        .total_calls = 0,
        .total_value = 0,
        .worker_totals = {0},
    };
    pthread_t threads[STRESS_MAX_WORKERS];
    WorkerArg args[STRESS_MAX_WORKERS];

    for (int worker = 0; worker < workers; ++worker) {
        args[worker].state = &state;
        args[worker].worker_id = worker;
        args[worker].iterations = iterations;
        if (pthread_create(&threads[worker], 0, stress_worker_main, &args[worker]) != 0) {
            printf("thread_stress create_failed worker=%d\n", worker);
            return 1;
        }
    }

    for (int worker = 0; worker < workers; ++worker) {
        if (pthread_join(threads[worker], 0) != 0) {
            printf("thread_stress join_failed worker=%d\n", worker);
            return 1;
        }
    }

    uint64_t expected_total = stress_expected_total(workers, iterations);
    uint64_t expected_calls = (uint64_t)workers * (uint64_t)iterations;
    int ok = (state.total_calls == expected_calls) && (state.total_value == expected_total);

    printf("thread_stress workers=%d iterations=%d calls=%" PRIu64
           " total=%" PRIu64 " expected=%" PRIu64 " status=%s\n",
           workers, iterations, state.total_calls,
           state.total_value, expected_total, ok ? "OK" : "FAIL");

    for (int worker = 0; worker < workers; ++worker) {
        uint64_t expected_worker = stress_expected_worker(worker, iterations);
        int worker_ok = state.worker_totals[worker] == expected_worker;
        printf("worker[%d]=%" PRIu64 " expected=%" PRIu64 " status=%s\n",
               worker, state.worker_totals[worker], expected_worker,
               worker_ok ? "OK" : "FAIL");
        ok = ok && worker_ok;
    }

    pthread_mutex_destroy(&state.lock);
    return ok ? 0 : 1;
}
