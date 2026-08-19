#pragma once

#define QTRACE_TAG "QBDI-TRACER"
#if defined(QTRACE_HOST_TEST)
#define QTRACE_D(...) ((void) 0)
#define QTRACE_I(...) ((void) 0)
#define QTRACE_W(...) ((void) 0)
#define QTRACE_E(...) ((void) 0)
#else
#include <android/log.h>
#define QTRACE_D(...) __android_log_print(ANDROID_LOG_DEBUG, QTRACE_TAG, __VA_ARGS__)
#define QTRACE_I(...) __android_log_print(ANDROID_LOG_INFO, QTRACE_TAG, __VA_ARGS__)
#define QTRACE_W(...) __android_log_print(ANDROID_LOG_WARN, QTRACE_TAG, __VA_ARGS__)
#define QTRACE_E(...) __android_log_print(ANDROID_LOG_ERROR, QTRACE_TAG, __VA_ARGS__)
#endif
