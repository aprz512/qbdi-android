#pragma once

#include <android/log.h>

#define QTRACE_TAG "QBDI-TRACER"
#define QTRACE_D(...) __android_log_print(ANDROID_LOG_DEBUG, QTRACE_TAG, __VA_ARGS__)
#define QTRACE_I(...) __android_log_print(ANDROID_LOG_INFO, QTRACE_TAG, __VA_ARGS__)
#define QTRACE_W(...) __android_log_print(ANDROID_LOG_WARN, QTRACE_TAG, __VA_ARGS__)
#define QTRACE_E(...) __android_log_print(ANDROID_LOG_ERROR, QTRACE_TAG, __VA_ARGS__)
