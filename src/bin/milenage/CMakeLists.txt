project(softhsm2-milenage)

# Client-side tool: loads a PKCS#11 module at runtime via dlopen, so it
# only needs the public cryptoki headers and the vendor mechanism
# header, not libsofthsm2 internals.
set(INCLUDE_DIRS ${PROJECT_SOURCE_DIR}/../../lib/pkcs11
                 ${PROJECT_SOURCE_DIR}/../../lib/milenage
                 )
include_directories(${INCLUDE_DIRS})

add_executable(${PROJECT_NAME} softhsm2-milenage.cpp)
target_compile_options(${PROJECT_NAME} PRIVATE ${COMPILE_OPTIONS})
target_link_libraries(${PROJECT_NAME} ${CMAKE_DL_LIBS})

add_executable(${PROJECT_NAME}d softhsm2-milenaged.cpp)
target_compile_options(${PROJECT_NAME}d PRIVATE ${COMPILE_OPTIONS})
target_link_libraries(${PROJECT_NAME}d ${CMAKE_DL_LIBS})

install(TARGETS ${PROJECT_NAME} ${PROJECT_NAME}d
        DESTINATION ${CMAKE_INSTALL_BINDIR}
        )
