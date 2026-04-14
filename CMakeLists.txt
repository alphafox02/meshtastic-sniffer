cmake_minimum_required(VERSION 3.9)
project(meshtastic-sniffer C)

set(CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake/Modules" ${CMAKE_MODULE_PATH})

# Homebrew include/link paths on MacOS (Intel and Apple Silicon)
if(APPLE)
    if(CMAKE_SYSTEM_PROCESSOR MATCHES "arm|ARM|aarch64|AARCH64")
        link_directories(/opt/homebrew/lib)
        include_directories(/opt/homebrew/include)
    else()
        link_directories(/usr/local/lib)
        include_directories(/usr/local/include)
    endif()
endif()

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fno-common -Wall -Wextra -Wno-unused-parameter -std=c99 -Werror=implicit-function-declaration")
set(CMAKE_C_FLAGS_DEBUG "-ggdb3 -g3 -O0 -fsanitize=address")
set(CMAKE_C_FLAGS_MINSIZEREL "-Os")
set(CMAKE_C_FLAGS_RELWITHDEBINFO "-O3 -march=native -ggdb3 -g3")
set(CMAKE_C_FLAGS_RELEASE "-O3 -march=native")
set(CMAKE_EXE_LINKER_FLAGS_DEBUG "-fsanitize=address")

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE "RelWithDebInfo" CACHE STRING
      "Choose the type of build: Debug Release RelWithDebInfo MinSizeRel." FORCE)
endif()

# Required dependencies
set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads REQUIRED)

# FFTW3 (single-precision) for LoRa dechirp + spectrum FFT
find_library(FFTW3F_LIB fftw3f)
find_library(FFTW3F_THREADS_LIB fftw3f_threads)
find_path(FFTW3_INC fftw3.h)
if(NOT (FFTW3F_LIB AND FFTW3_INC))
    message(FATAL_ERROR "FFTW3 (float) not found. Install libfftw3-dev.")
endif()
include_directories(${FFTW3_INC})

# OpenSSL for AES-CTR (Meshtastic encrypts payloads with AES-128/256-CTR)
find_package(OpenSSL REQUIRED)
include_directories(${OPENSSL_INCLUDE_DIR})

# Optional SDR backends -- enable any/all that are installed.
find_package(SoapySDR)
find_package(SDRplay)
find_package(RTLSDR)
find_library(HACKRF_LIB hackrf)
find_path(HACKRF_INC libhackrf/hackrf.h)
if(HACKRF_LIB AND HACKRF_INC)
    set(HACKRF_FOUND TRUE)
endif()
find_library(BLADERF_LIB bladeRF)
find_path(BLADERF_INC libbladeRF.h)
if(BLADERF_LIB AND BLADERF_INC)
    set(BLADERF_FOUND TRUE)
endif()
find_library(UHD_LIB uhd)
find_path(UHD_INC uhd.h)
if(UHD_LIB AND UHD_INC)
    set(UHD_FOUND TRUE)
endif()
find_library(AIRSPY_LIB airspy)
find_path(AIRSPY_INC libairspy/airspy.h)
if(AIRSPY_LIB AND AIRSPY_INC)
    set(AIRSPY_FOUND TRUE)
endif()

set(HAVE_ANY_SDR FALSE)
foreach(_b SOAPYSDR SDRPLAY RTLSDR HACKRF BLADERF UHD AIRSPY)
    if(${_b}_FOUND)
        set(HAVE_ANY_SDR TRUE)
    endif()
endforeach()
if(NOT HAVE_ANY_SDR)
    message(WARNING "No SDR backend found. Live capture will not be available.\n"
                    "Install at least one: libhackrf-dev libbladerf-dev librtlsdr-dev\n"
                    "                      libsoapysdr-dev libuhd-dev libairspy-dev")
endif()

# Optional MQTT
find_library(MOSQUITTO_LIB mosquitto)
find_path(MOSQUITTO_INC mosquitto.h)
if(MOSQUITTO_LIB AND MOSQUITTO_INC)
    set(MOSQUITTO_FOUND TRUE)
endif()

# Optional ZMQ
find_library(ZMQ_LIB zmq)
find_path(ZMQ_INC zmq.h)
if(ZMQ_LIB AND ZMQ_INC)
    set(ZMQ_FOUND TRUE)
endif()

# Sources -- add files here as they land. The current set builds a
# skeleton binary that initialises SIMD and prints the protocol tables;
# channelizer / demod / decoder / outputs land in subsequent phases.
include_directories(${PROJECT_SOURCE_DIR})

set(SOURCES
    ${PROJECT_SOURCE_DIR}/main.c
    ${PROJECT_SOURCE_DIR}/options.c
    ${PROJECT_SOURCE_DIR}/meshtastic.c
    ${PROJECT_SOURCE_DIR}/file_src.c
    ${PROJECT_SOURCE_DIR}/vita49.c
    ${PROJECT_SOURCE_DIR}/channelizer.c
    ${PROJECT_SOURCE_DIR}/lora.c
    ${PROJECT_SOURCE_DIR}/keyset.c
    ${PROJECT_SOURCE_DIR}/protobuf.c
    ${PROJECT_SOURCE_DIR}/mesh_packet.c
    ${PROJECT_SOURCE_DIR}/mesh_decoders.c
    ${PROJECT_SOURCE_DIR}/feed.c
    ${PROJECT_SOURCE_DIR}/scanner.c
    ${PROJECT_SOURCE_DIR}/web.c
    ${PROJECT_SOURCE_DIR}/cot.c
    ${PROJECT_SOURCE_DIR}/node_db.c
    ${PROJECT_SOURCE_DIR}/sigmf.c
    ${PROJECT_SOURCE_DIR}/simd_generic.c
)

# SIMD kernels -- platform-specific, runtime-detected.
if(CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|AMD64|amd64|x86|i[3-6]86")
    set_source_files_properties(${PROJECT_SOURCE_DIR}/simd_sse42.c
        PROPERTIES COMPILE_FLAGS "-msse4.2")
    set_source_files_properties(${PROJECT_SOURCE_DIR}/simd_avx2.c
        PROPERTIES COMPILE_FLAGS "-mavx2 -mfma")
    list(APPEND SOURCES
        ${PROJECT_SOURCE_DIR}/simd_sse42.c
        ${PROJECT_SOURCE_DIR}/simd_avx2.c)
    message(STATUS "SIMD: SSE4.2 + AVX2+FMA kernels enabled (runtime-detected)")
elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "arm|ARM|aarch64|AARCH64")
    list(APPEND SOURCES
        ${PROJECT_SOURCE_DIR}/simd_neon.c)
    message(STATUS "SIMD: NEON kernels enabled (AArch64)")
else()
    message(STATUS "SIMD: scalar only (unrecognised platform)")
endif()

add_executable(meshtastic-sniffer ${SOURCES})

target_link_libraries(meshtastic-sniffer PRIVATE
    Threads::Threads
    ${FFTW3F_LIB}
    ${OPENSSL_CRYPTO_LIBRARY}
    m)

if(FFTW3F_THREADS_LIB)
    target_link_libraries(meshtastic-sniffer PRIVATE ${FFTW3F_THREADS_LIB})
endif()

# Per-backend conditional compile / link
foreach(_pair  SOAPYSDR:HAVE_SOAPYSDR:soapysdr.c
               SDRPLAY:HAVE_SDRPLAY:sdrplay.c
               RTLSDR:HAVE_RTLSDR:rtlsdr.c
               HACKRF:HAVE_HACKRF:hackrf.c
               BLADERF:HAVE_BLADERF:bladerf.c
               UHD:HAVE_UHD:usrp.c
               AIRSPY:HAVE_AIRSPY:airspy.c)
    string(REPLACE ":" ";" _parts ${_pair})
    list(GET _parts 0 _name)
    list(GET _parts 1 _def)
    list(GET _parts 2 _src)
    if(${_name}_FOUND)
        message(STATUS "${_name}: enabled")
        # Source files for backends are added once they exist on disk.
        if(EXISTS "${PROJECT_SOURCE_DIR}/${_src}")
            target_sources(meshtastic-sniffer PRIVATE ${PROJECT_SOURCE_DIR}/${_src})
            target_compile_definitions(meshtastic-sniffer PRIVATE ${_def})
            if(_name STREQUAL "SOAPYSDR")
                target_link_libraries(meshtastic-sniffer PRIVATE ${SOAPYSDR_LIBRARIES})
                target_include_directories(meshtastic-sniffer PRIVATE ${SOAPYSDR_INCLUDE_DIR})
            elseif(_name STREQUAL "SDRPLAY")
                target_link_libraries(meshtastic-sniffer PRIVATE ${SDRPLAY_LIBRARIES})
                target_include_directories(meshtastic-sniffer PRIVATE ${SDRPLAY_INCLUDE_DIR})
            elseif(_name STREQUAL "RTLSDR")
                target_link_libraries(meshtastic-sniffer PRIVATE ${RTLSDR_LIBRARIES})
                target_include_directories(meshtastic-sniffer PRIVATE ${RTLSDR_INCLUDE_DIR})
            elseif(_name STREQUAL "HACKRF")
                target_link_libraries(meshtastic-sniffer PRIVATE ${HACKRF_LIB})
                target_include_directories(meshtastic-sniffer PRIVATE ${HACKRF_INC})
            elseif(_name STREQUAL "BLADERF")
                target_link_libraries(meshtastic-sniffer PRIVATE ${BLADERF_LIB})
                target_include_directories(meshtastic-sniffer PRIVATE ${BLADERF_INC})
            elseif(_name STREQUAL "UHD")
                target_link_libraries(meshtastic-sniffer PRIVATE ${UHD_LIB})
                target_include_directories(meshtastic-sniffer PRIVATE ${UHD_INC})
            elseif(_name STREQUAL "AIRSPY")
                target_link_libraries(meshtastic-sniffer PRIVATE ${AIRSPY_LIB})
                target_include_directories(meshtastic-sniffer PRIVATE ${AIRSPY_INC})
            endif()
        else()
            message(STATUS "  (${_src} not yet present, will be linked when added)")
        endif()
    else()
        message(STATUS "${_name}: not found")
    endif()
endforeach()

target_sources(meshtastic-sniffer PRIVATE ${PROJECT_SOURCE_DIR}/mqtt.c)
if(MOSQUITTO_FOUND)
    target_link_libraries(meshtastic-sniffer PRIVATE ${MOSQUITTO_LIB})
    target_include_directories(meshtastic-sniffer PRIVATE ${MOSQUITTO_INC})
    target_compile_definitions(meshtastic-sniffer PRIVATE HAVE_MQTT)
    message(STATUS "MQTT: enabled")
else()
    message(STATUS "MQTT: not found (mqtt.c stubs out; --mqtt will be a no-op)")
endif()

target_sources(meshtastic-sniffer PRIVATE ${PROJECT_SOURCE_DIR}/zmq_pub.c)
if(ZMQ_FOUND)
    target_link_libraries(meshtastic-sniffer PRIVATE ${ZMQ_LIB})
    target_include_directories(meshtastic-sniffer PRIVATE ${ZMQ_INC})
    target_compile_definitions(meshtastic-sniffer PRIVATE HAVE_ZMQ)
    message(STATUS "ZMQ: enabled")
else()
    message(STATUS "ZMQ: not found (zmq_pub.c stubs out; --zmq will be a no-op)")
endif()

set_property(TARGET meshtastic-sniffer PROPERTY C_STANDARD 99)
set_property(TARGET meshtastic-sniffer PROPERTY INTERPROCEDURAL_OPTIMIZATION TRUE)

install(TARGETS meshtastic-sniffer DESTINATION bin)

# CPack
set(CPACK_PACKAGE_NAME "meshtastic-sniffer")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "Wideband Meshtastic LoRa receiver")
set(CPACK_PACKAGE_VENDOR "CEMAXECUTER LLC")
set(CPACK_PACKAGE_VERSION_MAJOR "0")
set(CPACK_PACKAGE_VERSION_MINOR "1")
set(CPACK_PACKAGE_VERSION_PATCH "0")
set(CPACK_GENERATOR "DEB;TGZ")
set(CPACK_DEBIAN_PACKAGE_MAINTAINER "CEMAXECUTER LLC")
set(CPACK_DEBIAN_PACKAGE_SECTION "hamradio")
set(CPACK_DEBIAN_PACKAGE_SHLIBDEPS ON)
set(CPACK_RESOURCE_FILE_LICENSE "${CMAKE_SOURCE_DIR}/LICENSE")
include(CPack)
