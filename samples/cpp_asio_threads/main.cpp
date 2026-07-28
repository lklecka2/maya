#include <asio.hpp>

#include <atomic>
#include <chrono>
#include <cstdio>
#include <exception>
#include <future>
#include <memory>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

__attribute__((noinline, noipa, used)) static int parse_payload(int value) {
    if (value == 13) {
        throw std::runtime_error("timer payload");
    }
    return value * 3 + 1;
}

static int cleanup_probe(int value, std::atomic<int>& destroyed) {
    struct ScopeMarker {
        std::atomic<int>& count;
        ~ScopeMarker() {
            count.fetch_add(1, std::memory_order_relaxed);
        }
    } marker{destroyed};

    if (value == 21) {
        throw std::runtime_error("raii payload");
    }
    return parse_payload(value);
}

static int catch_inside_protected(int value, std::atomic<int>& caught, std::atomic<int>& destroyed) {
    try {
        return cleanup_probe(value, destroyed);
    } catch (const std::exception&) {
        caught.fetch_add(1, std::memory_order_relaxed);
        return -7;
    }
}

static int throw_to_future(int value) {
    if (value == 34) {
        throw std::runtime_error("future payload");
    }
    return value;
}

static void schedule_timer(asio::io_context& io,
                           int value,
                           std::atomic<int>& total,
                           std::atomic<int>& caught,
                           std::atomic<int>& destroyed) {
    auto timer = std::make_shared<asio::steady_timer>(io, std::chrono::milliseconds(value % 5));
    timer->async_wait([timer, value, &total, &caught, &destroyed](const asio::error_code& ec) {
        if (ec) {
            return;
        }
        total.fetch_add(catch_inside_protected(value, caught, destroyed), std::memory_order_relaxed);
    });
}

int main() {
    asio::io_context io;
    auto guard = asio::make_work_guard(io);

    std::atomic<int> total{0};
    std::atomic<int> caught{0};
    std::atomic<int> destroyed{0};

    std::vector<std::thread> workers;
    for (int i = 0; i < 3; ++i) {
        workers.emplace_back([&io] {
            io.run();
        });
    }

    std::vector<std::thread> producers;
    const int values[] = {2, 5, 8, 13, 21};
    for (int value : values) {
        producers.emplace_back([&io, &total, &caught, &destroyed, value] {
            asio::post(io, [&io, &total, &caught, &destroyed, value] {
                schedule_timer(io, value, total, caught, destroyed);
            });
        });
    }

    std::promise<int> promised;
    std::future<int> future = promised.get_future();
    asio::post(io, [&promised]() mutable {
        try {
            promised.set_value(throw_to_future(34));
        } catch (...) {
            promised.set_exception(std::current_exception());
        }
    });

    for (auto& producer : producers) {
        producer.join();
    }

    guard.reset();

    std::string propagated;
    try {
        (void)future.get();
    } catch (const std::exception& ex) {
        propagated = ex.what();
    }

    for (auto& worker : workers) {
        worker.join();
    }

    const int expected_total = 7 + 16 + 25 - 7 - 7;
    const bool ok = total.load(std::memory_order_relaxed) == expected_total &&
                    caught.load(std::memory_order_relaxed) == 2 &&
                    destroyed.load(std::memory_order_relaxed) == 5 &&
                    propagated == "future payload";

    std::printf("asio_threads total=%d caught=%d destroyed=%d propagated=%s status=%s\n",
                total.load(std::memory_order_relaxed),
                caught.load(std::memory_order_relaxed),
                destroyed.load(std::memory_order_relaxed),
                propagated.c_str(),
                ok ? "OK" : "FAIL");

    return ok ? 0 : 1;
}
