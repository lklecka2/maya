#include <atomic>
#include <cstdio>
#include <pthread.h>
#include <sched.h>

static std::atomic<int> ready{0};
static std::atomic<int> destroyed{0};

struct Marker {
    ~Marker() { destroyed.fetch_add(1, std::memory_order_relaxed); }
};

__attribute__((noinline, noipa, used)) static void protected_cancel_scope() {
    Marker marker;
    ready.store(1, std::memory_order_release);
    for (;;) {
        pthread_testcancel();
        sched_yield();
    }
}

static void* worker(void*) {
    protected_cancel_scope();
    return nullptr;
}

int main() {
    pthread_t thread{};
    if (pthread_create(&thread, nullptr, worker, nullptr) != 0) return 2;
    while (ready.load(std::memory_order_acquire) == 0) sched_yield();
    if (pthread_cancel(thread) != 0) return 3;
    void* result = nullptr;
    if (pthread_join(thread, &result) != 0) return 4;
    const int count = destroyed.load(std::memory_order_relaxed);
    const bool ok = result == PTHREAD_CANCELED && count == 1;
    std::printf("cancel_unwind destroyed=%d canceled=%s status=%s\n",
                count, result == PTHREAD_CANCELED ? "yes" : "no", ok ? "OK" : "FAIL");
    return ok ? 0 : 1;
}
