cmake_minimum_required(VERSION 3.16)
project(qprotect_cpp VERSION 0.2.0 LANGUAGES CXX)

find_package(OpenSSL 3.5 REQUIRED)

add_library(qprotect_cpp STATIC
    src/crypto_context.cpp
    src/algorithms.cpp
    src/envelope.cpp
    src/keys.cpp
    src/json_minimal.cpp
    src/identity.cpp
    src/self_test.cpp
    src/secure_file.cpp
    src/disk.cpp
    src/hardware.cpp
)
target_include_directories(qprotect_cpp PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_compile_features(qprotect_cpp PUBLIC cxx_std_20)
target_link_libraries(qprotect_cpp PUBLIC OpenSSL::Crypto)
target_compile_options(qprotect_cpp PRIVATE
    -Wall
    -Wextra
    -Wpedantic
    -Werror
    -fstack-protector-strong
)

add_executable(qprotect_cpp_selftest apps/selftest_main.cpp)
target_link_libraries(qprotect_cpp_selftest PRIVATE qprotect_cpp)

add_executable(qprotect_cpp_tool apps/qprotect_tool.cpp)
target_link_libraries(qprotect_cpp_tool PRIVATE qprotect_cpp)
target_include_directories(qprotect_cpp_tool PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)

add_executable(qprotect apps/qprotect_tool.cpp)
target_link_libraries(qprotect PRIVATE qprotect_cpp)
target_include_directories(qprotect PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)

add_executable(qprotect_cpp_unittests tests/unit_tests.cpp)
target_link_libraries(qprotect_cpp_unittests PRIVATE qprotect_cpp)
target_include_directories(qprotect_cpp_unittests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)

add_executable(qprotect_native_integration tests/native_integration.cpp)

add_executable(qprotect_startup_tests tests/startup_tests.cpp)
target_link_libraries(qprotect_startup_tests PRIVATE qprotect_cpp)

add_executable(qprotect_diagnostics_tests tests/diagnostics_tests.cpp)
target_link_libraries(qprotect_diagnostics_tests PRIVATE qprotect_cpp)
target_include_directories(qprotect_diagnostics_tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)

enable_testing()
add_test(NAME qprotect_cpp_selftest
         COMMAND qprotect_cpp_selftest)
add_test(NAME qprotect_cpp_unittests
         COMMAND qprotect_cpp_unittests)
add_test(NAME qprotect_startup_tests
         COMMAND qprotect_startup_tests)
add_test(NAME qprotect_diagnostics_tests
         COMMAND qprotect_diagnostics_tests)
add_test(NAME qprotect_native_integration
         COMMAND qprotect_native_integration $<TARGET_FILE:qprotect>)

install(TARGETS qprotect qprotect_cpp
        RUNTIME DESTINATION bin
        ARCHIVE DESTINATION lib)
install(DIRECTORY include/qprotect DESTINATION include)
