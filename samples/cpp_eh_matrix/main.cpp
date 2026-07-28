#include <atomic>
#include <cstdio>
#include <future>
#include <stdexcept>
#include <thread>

struct Counts {
    std::atomic<int> destroyed{0};
    std::atomic<int> typed{0};
    std::atomic<int> catch_all{0};
    std::atomic<int> rethrows{0};
};

struct Marker {
    Counts& counts;
    ~Marker() { counts.destroyed.fetch_add(1, std::memory_order_relaxed); }
};

__attribute__((noinline, noipa, used)) static int same_function(int value, Counts& counts) {
    try {
        Marker first{counts};
        Marker second{counts};
        if (value == 1) throw std::logic_error("same-function");
        return value;
    } catch (const std::logic_error&) {
        counts.typed.fetch_add(1, std::memory_order_relaxed);
        return 11;
    }
}

__attribute__((noinline, noipa, used)) static int cleanup_only(int value, Counts& counts) {
    Marker first{counts};
    Marker second{counts};
    if (value == 2) throw std::runtime_error("cleanup-only");
    return value;
}

__attribute__((noinline, noipa, used)) static int rethrow_typed(int value, Counts& counts) {
    try {
        Marker marker{counts};
        if (value == 3) throw std::range_error("rethrow-typed");
    } catch (const std::range_error&) {
        counts.rethrows.fetch_add(1, std::memory_order_relaxed);
        throw;
    }
    return value;
}

__attribute__((noinline, noipa, used)) static int catch_everything(int value, Counts& counts) {
    try {
        if (value == 4) throw 44;
    } catch (...) {
        counts.catch_all.fetch_add(1, std::memory_order_relaxed);
        return 17;
    }
    return value;
}

__attribute__((noinline, noipa, used)) static int callback_throw(int value, Counts& counts) {
    Marker marker{counts};
    if (value == 5) throw std::overflow_error("callback");
    return value;
}

__attribute__((noinline, noipa, used)) static int callback_boundary(
    int (*callback)(int, Counts&), int value, Counts& counts) {
    try {
        return callback(value, counts);
    } catch (const std::overflow_error&) {
        counts.typed.fetch_add(1, std::memory_order_relaxed);
        return 23;
    }
}

int main() {
    Counts counts;
    int result = same_function(1, counts);
    try {
        result += cleanup_only(2, counts);
    } catch (const std::runtime_error&) {
        result += 13;
    }
    try {
        result += rethrow_typed(3, counts);
    } catch (const std::range_error&) {
        result += 19;
    }
    result += catch_everything(4, counts);
    result += callback_boundary(callback_throw, 5, counts);

    std::promise<int> promise;
    auto future = promise.get_future();
    std::thread worker([&] {
        try {
            promise.set_value(cleanup_only(2, counts));
        } catch (...) {
            promise.set_exception(std::current_exception());
        }
    });
    try {
        (void)future.get();
    } catch (const std::runtime_error&) {
        result += 29;
    }
    worker.join();

    const int destroyed = counts.destroyed.load(std::memory_order_relaxed);
    const int typed = counts.typed.load(std::memory_order_relaxed);
    const int caught_all = counts.catch_all.load(std::memory_order_relaxed);
    const int rethrows = counts.rethrows.load(std::memory_order_relaxed);
    const bool ok = result == 112 && destroyed == 8 && typed == 2 && caught_all == 1 && rethrows == 1;
    std::printf("eh_matrix result=%d destroyed=%d typed=%d catch_all=%d rethrows=%d status=%s\n",
                result, destroyed, typed, caught_all, rethrows, ok ? "OK" : "FAIL");
    return ok ? 0 : 1;
}
