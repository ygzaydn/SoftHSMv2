project(milenagetest)

# These tests do not depend on CppUnit (unlike src/lib/crypto/test and
# src/lib/test) -- see doc/MILENAGE-5G-AKA-DESIGN.md section 17 for
# why: this environment has no CppUnit available and no way to install
# it, so a CppUnit-only test suite could not have been built or run
# here. They are registered with CTest directly (enable_testing() is
# already called unconditionally at the top level) and are gated only
# on WITH_MILENAGE, independent of BUILD_TESTS/CppUnit, so `ctest`
# exercises them in any WITH_MILENAGE=ON build.

set(INCLUDE_DIRS ${PROJECT_SOURCE_DIR}/..
                 ${PROJECT_SOURCE_DIR}/../../pkcs11
                 ${CRYPTO_INCLUDES}
                 )
include_directories(${INCLUDE_DIRS})

# --- Algorithm-level KAT tests + wire/service tests: link the full
# static library so they can use CryptoFactory via
# src/lib/milenage/CryptoBackend.cpp (item 2's abstraction seam). ---
add_executable(milenage-kat-test milenage_kat_test.cpp)
target_compile_options(milenage-kat-test PRIVATE ${COMPILE_OPTIONS})
target_link_libraries(milenage-kat-test softhsm2-static ${CRYPTO_LIBS})
add_test(NAME milenage-kat-test COMMAND milenage-kat-test)

add_executable(milenage-service-test milenage_service_test.cpp)
target_compile_options(milenage-service-test PRIVATE ${COMPILE_OPTIONS})
target_link_libraries(milenage-service-test softhsm2-static ${CRYPTO_LIBS})
add_test(NAME milenage-service-test COMMAND milenage-service-test)

# --- Real PKCS#11-level tests: dlopen the built module, no link
# against libsofthsm2 internals. Run through a wrapper script that
# initializes an isolated token in a temp directory per invocation. ---
add_executable(milenage-pkcs11-e2e-test pkcs11_e2e_test.cpp)
target_compile_options(milenage-pkcs11-e2e-test PRIVATE ${COMPILE_OPTIONS})
target_link_libraries(milenage-pkcs11-e2e-test ${CMAKE_DL_LIBS})

add_executable(milenage-pkcs11-restart-test pkcs11_restart_test.cpp)
target_compile_options(milenage-pkcs11-restart-test PRIVATE ${COMPILE_OPTIONS})
target_link_libraries(milenage-pkcs11-restart-test ${CMAKE_DL_LIBS})

add_test(NAME milenage-pkcs11-e2e-test
         COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/run_pkcs11_ctest.sh
                 e2e
                 $<TARGET_FILE:softhsm2>
                 $<TARGET_FILE:softhsm2-util>
                 $<TARGET_FILE:milenage-pkcs11-e2e-test>
         )

add_test(NAME milenage-pkcs11-restart-test
         COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/run_pkcs11_ctest.sh
                 restart
                 $<TARGET_FILE:softhsm2>
                 $<TARGET_FILE:softhsm2-util>
                 $<TARGET_FILE:milenage-pkcs11-restart-test>
         )

if(WITH_MILENAGE_PLAINTEXT_PROVISIONING)
    # The daemon test's provisioning step (done locally via
    # softhsm2-milenage, never over the network -- the daemon refuses
    # plaintext provisioning unconditionally) needs a build that has
    # plaintext provisioning available at all.
    add_executable(milenage-daemon-tcp-client-test daemon_tcp_client_test.cpp)
    target_compile_options(milenage-daemon-tcp-client-test PRIVATE ${COMPILE_OPTIONS})

    add_test(NAME milenage-daemon-tcp-test
             COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/run_daemon_ctest.sh
                     $<TARGET_FILE:softhsm2>
                     $<TARGET_FILE:softhsm2-util>
                     $<TARGET_FILE:softhsm2-milenage>
                     $<TARGET_FILE:softhsm-gsm>
                     $<TARGET_FILE:milenage-daemon-tcp-client-test>
             )
    add_test(NAME milenage-daemon-unix-test
             COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/run_daemon_ctest.sh
                     $<TARGET_FILE:softhsm2>
                     $<TARGET_FILE:softhsm2-util>
                     $<TARGET_FILE:softhsm2-milenage>
                     $<TARGET_FILE:softhsm-gsm>
                     $<TARGET_FILE:milenage-daemon-tcp-client-test>
                     unix
             )
    add_test(NAME milenage-daemon-dual-listener-test
             COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/run_daemon_ctest.sh
                     $<TARGET_FILE:softhsm2>
                     $<TARGET_FILE:softhsm2-util>
                     $<TARGET_FILE:softhsm2-milenage>
                     $<TARGET_FILE:softhsm-gsm>
                     $<TARGET_FILE:milenage-daemon-tcp-client-test>
                     both
             )
endif()

if(WITH_MILENAGE_TRANSPORT_IMPORT)
    add_executable(milenage-pkcs11-transport-import-test pkcs11_transport_import_test.cpp)
    target_compile_options(milenage-pkcs11-transport-import-test PRIVATE ${COMPILE_OPTIONS})
    target_link_libraries(milenage-pkcs11-transport-import-test ${CMAKE_DL_LIBS} ${CRYPTO_LIBS})

    add_test(NAME milenage-pkcs11-transport-import-test
             COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/run_pkcs11_ctest.sh
                     e2e
                     $<TARGET_FILE:softhsm2>
                     $<TARGET_FILE:softhsm2-util>
                     $<TARGET_FILE:milenage-pkcs11-transport-import-test>
             )
endif()
