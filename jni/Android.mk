# Android.mk - Build script for libfrida-bridge.so
# Place this file inside the jni/ folder of the project.

LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

# Module name - the shared library will be libfrida-bridge.so
LOCAL_MODULE := frida-bridge

# Source files to compile
LOCAL_SRC_FILES := ../src/frida-bridge.c

# Compiler flags
LOCAL_CFLAGS := -Wall -Wextra -Wno-unused-parameter -O2

# Uncomment to enable verbose diagnostic logging (LOGD statements).
# See README.md "Build Flags" section for details.
# LOCAL_CFLAGS += -DFRIDA_BRIDGE_DEBUG

# Linker flags - build-id for debugging
LOCAL_LDFLAGS := -Wl,--build-id=sha1

# Libraries needed at runtime (logcat and dynamic linker)
LOCAL_LDLIBS := -llog -ldl

# Build as a shared library
include $(BUILD_SHARED_LIBRARY)

