cmake_minimum_required(VERSION 3.0)
project(simple_otp C)

# Generate the static library from the library sources

FILE(GLOB cifra libs/cifra/src/*.c libs/cifra/src/*.h libs/cifra/src/ext/*.h)
add_library(simple_otp STATIC
        ${cifra}
        src/common.h
        src/base32.c
        src/base32.h
        src/hotp.c
        src/totp.c)

target_include_directories(simple_otp
        PUBLIC
        ${PROJECT_SOURCE_DIR}/src
        ${PROJECT_SOURCE_DIR}/libs/cifra/src
        ${PROJECT_SOURCE_DIR}/libs/cifra/src/ext)


# Generate the example executable
add_executable(main
        example/main.c)

target_link_libraries( main
        PRIVATE
        simple_otp
        )