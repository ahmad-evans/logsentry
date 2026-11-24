#include "test_framework.hpp"

int main() {
    int passed = 0, failed = 0;
    for (const auto& t : testing::registry()) {
        try {
            t.fn();
            ++passed;
            std::cout << "  PASS  " << t.name << "\n";
        } catch (const testing::Failure& f) {
            ++failed;
            std::cout << "  FAIL  " << t.name << "\n        " << f.message << "\n";
        } catch (const std::exception& e) {
            ++failed;
            std::cout << "  FAIL  " << t.name << "\n        unexpected exception: " << e.what() << "\n";
        }
    }
    std::cout << "\n" << passed << " passed, " << failed << " failed\n";
    return failed == 0 ? 0 : 1;
}
