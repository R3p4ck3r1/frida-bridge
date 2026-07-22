# Android.mk - Build script for the bridge shared library.
# Place this file inside the jni/ folder of the project.

LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

# Module name - pulled from BRIDGE_MODULE_NAME in ../src/frida-bridge.h so
# that header stays the single place you edit to rename the output .so
# (default below is only a fallback if the header can't be parsed).
BRIDGE_MODULE_NAME := $(strip $(shell awk -F'"' '/#define BRIDGE_MODULE_NAME/ {print $$2}' $(LOCAL_PATH)/../src/frida-bridge.h))
ifeq ($(BRIDGE_MODULE_NAME),)
BRIDGE_MODULE_NAME := frida-bridge
endif

# The shared library will be built as lib$(BRIDGE_MODULE_NAME).so
LOCAL_MODULE := $(BRIDGE_MODULE_NAME)

# Source files to compile
LOCAL_SRC_FILES := \
	../src/app-detection.c \
	../src/container-path.c \
	../src/fork-safety.c \
	../src/frida-bridge.c

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

