cmake_minimum_required(VERSION 3.21)
project(QuirewiseCrypto VERSION 0.1.0 LANGUAGES C)
option(QUIREWISE_BUILD_SHARED "Build Quirewise libraries as shared libraries" OFF)
if(QUIREWISE_BUILD_SHARED)
    set(QW_LIBRARY_TYPE SHARED)
else()
    set(QW_LIBRARY_TYPE STATIC)
endif()

include(GNUInstallDirs)
include(CMakePackageConfigHelpers)
include(CTest)

set(QW_CRYPTO_SOURCES
    src/crypto.c
    src/aes128.c
    src/aes256.c
    src/blowfish.c
    src/blowfish_tables.c
    src/founder_keystream.c
    src/md5.c
    src/pdg_deslike.c
    src/pdg_des_tables.c
    src/sha2.c
    src/tea.c)

add_library(quirewise_crypto ${QW_LIBRARY_TYPE} ${QW_CRYPTO_SOURCES})
add_library(Quirewise::Crypto ALIAS quirewise_crypto)
set_target_properties(quirewise_crypto PROPERTIES
    EXPORT_NAME Crypto
    POSITION_INDEPENDENT_CODE ON)
target_compile_features(quirewise_crypto PUBLIC c_std_11)
target_include_directories(quirewise_crypto PUBLIC
    "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>"
    "$<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>")

if(BUILD_TESTING)
    add_executable(quirewise_crypto_tests tests/test_crypto.c)
    target_compile_features(quirewise_crypto_tests PRIVATE c_std_11)
    target_link_libraries(quirewise_crypto_tests PRIVATE Quirewise::Crypto)
    add_test(NAME quirewise_crypto_known_answers COMMAND quirewise_crypto_tests)
endif()

install(TARGETS quirewise_crypto EXPORT QuirewiseCryptoTargets
    ARCHIVE DESTINATION "${CMAKE_INSTALL_LIBDIR}"
    LIBRARY DESTINATION "${CMAKE_INSTALL_LIBDIR}"
    RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}")
install(DIRECTORY include/ DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}")
install(EXPORT QuirewiseCryptoTargets
    FILE QuirewiseCryptoTargets.cmake
    NAMESPACE Quirewise::
    DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/QuirewiseCrypto")

configure_package_config_file(
    cmake/QuirewiseCryptoConfig.cmake.in
    "${CMAKE_CURRENT_BINARY_DIR}/QuirewiseCryptoConfig.cmake"
    INSTALL_DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/QuirewiseCrypto")
write_basic_package_version_file(
    "${CMAKE_CURRENT_BINARY_DIR}/QuirewiseCryptoConfigVersion.cmake"
    VERSION "${PROJECT_VERSION}"
    COMPATIBILITY SameMajorVersion)
install(FILES
    "${CMAKE_CURRENT_BINARY_DIR}/QuirewiseCryptoConfig.cmake"
    "${CMAKE_CURRENT_BINARY_DIR}/QuirewiseCryptoConfigVersion.cmake"
    DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/QuirewiseCrypto")

if(QUIREWISE_BUILD_SHARED AND WIN32)
    set_target_properties(
        quirewise_crypto
        PROPERTIES WINDOWS_EXPORT_ALL_SYMBOLS ON)
endif()
