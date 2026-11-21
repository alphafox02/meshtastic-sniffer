# libmeshsniffer.so: the whole meshtastic-sniffer (repo root) built as a
# library for the Android app, plus the JNI bridge. The app opens the
# HackRF over USB (hackrf_android) and pushes samples in; see ext_src.h.
cmake_minimum_required(VERSION 3.22)
project(meshsniffer C)

get_filename_component(ROOT "${CMAKE_CURRENT_SOURCE_DIR}/../../../../.." ABSOLUTE)
if(NOT DEFINED DEPS_DIR OR DEPS_DIR STREQUAL "")
    set(DEPS_DIR "$ENV{HOME}/Android/deps/${ANDROID_ABI}")   # android/deps/build_deps.sh
endif()
if(NOT EXISTS "${DEPS_DIR}/lib/libfftw3f.a" OR NOT EXISTS "${DEPS_DIR}/lib/libcrypto.a")
    message(FATAL_ERROR "FFTW3f / libcrypto for ${ANDROID_ABI} not found in ${DEPS_DIR}: "
                        "run android/deps/build_deps.sh (or pass -PmeshDepsDir=...)")
endif()

set(SNIFFER_SOURCES
    main.c dedup.c options.c meshtastic.c file_src.c vita49.c channelizer.c iq_ring.c
    iq_snapshot.c fftw_wisdom.c webhook.c focused.c pfb.c lora.c keyset.c protobuf.c
    mesh_packet.c mesh_decoders.c feed.c announce.c gpsd.c archive.c c2.c c2_dealer.c
    geofence.c pcap_out.c psk_dict.c schema.c scanner.c web.c web_assets.c tx.c pki.c mesh_tx.c
    lora_tx.c ext_src.c share_url.c cot.c node_db.c kml_live.c sigmf.c simd_generic.c
    mqtt.c zmq_pub.c)
if(ANDROID_ABI STREQUAL "arm64-v8a")
    list(APPEND SNIFFER_SOURCES simd_neon.c)
endif()
list(TRANSFORM SNIFFER_SOURCES PREPEND "${ROOT}/")

add_library(meshsniffer SHARED ${SNIFFER_SOURCES} jni_bridge.c)
target_include_directories(meshsniffer PRIVATE "${ROOT}" "${DEPS_DIR}/include")
# SNIFFER_LIBRARY: no main(); the app calls sniffer_main(). No libhackrf,
# curl, MQTT or ZMQ here: those backends/outputs compile to stubs.
target_compile_definitions(meshsniffer PRIVATE SNIFFER_LIBRARY)
target_compile_options(meshsniffer PRIVATE -std=gnu11 -O3 -fno-common -Wall -Wno-unused-parameter
                       -Wno-unused-function -Werror=implicit-function-declaration)
target_link_libraries(meshsniffer PRIVATE
    "${DEPS_DIR}/lib/libfftw3f.a" "${DEPS_DIR}/lib/libcrypto.a" z log m)
