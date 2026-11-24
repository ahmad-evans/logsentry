// A tiny unit-test framework (no external dependencies).
#pragma once

#include <functional>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

namespace testing {

struct TestCase {
    std::string name;
    std::function<void()> fn;
};

inline std::vector<TestCase>& registry() {
    static std::vector<TestCase> tests;
    return tests;
}

struct Registrar {
    Registrar(const std::string& name, std::function<void()> fn) { registry().push_back({name, std::move(fn)}); }
};

struct Failure {
    std::string message;
};

}  // namespace testing

#define TEST_CONCAT2(a, b) a##b
#define TEST_CONCAT(a, b) TEST_CONCAT2(a, b)
#define TEST(name)                                                                     \
    static void name();                                                                \
    static testing::Registrar TEST_CONCAT(registrar_, name)(#name, name);             \
    static void name()

#define CHECK(cond)                                                                    \
    do {                                                                               \
        if (!(cond)) {                                                                 \
            std::ostringstream os_;                                                    \
            os_ << __FILE__ << ":" << __LINE__ << ": CHECK(" #cond ") failed";         \
            throw testing::Failure{os_.str()};                                         \
        }                                                                              \
    } while (0)

#define CHECK_EQ(a, b)                                                                 \
    do {                                                                               \
        auto va_ = (a);                                                                \
        auto vb_ = (b);                                                                \
        if (!(va_ == vb_)) {                                                           \
            std::ostringstream os_;                                                    \
            os_ << __FILE__ << ":" << __LINE__ << ": CHECK_EQ(" #a ", " #b ") failed: " \
                << va_ << " != " << vb_;                                               \
            throw testing::Failure{os_.str()};                                         \
        }                                                                              \
    } while (0)
