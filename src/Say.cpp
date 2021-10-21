#include "Say.h"
#include "args.h"

#include <stdio.h>
#include <stdarg.h>

#include <windows.h>

using namespace say;

static int g_level = SayLevelInfo;
static int g_sayType = SayTypeConsole;

void say::say(SayLevel level, const char *fmt, ...)
{
    if (level >= g_level) {
        va_list args;

        va_start(args, fmt);
#ifdef DR_BUILD
        dr_vfprintf(STDOUT, fmt, args);
#else
        vprintf(fmt, args);
#endif
        if (SAY_NEW_LINE && fmt[strlen(fmt) - 1] != '\n')
            PRINTF("\n");
        va_end(args);

        /*
        static char _s[1025 * 4];
        va_list args;

        va_start(args, fmt);
        size_t written = VSNPRINTF(_s, sizeof(_s) - 1, fmt, args);

        va_end(args);
        if (g_sayType == SayTypeDbg) {
            OutputDebugStringA(_s);
            if (SAY_NEW_LINE && fmt[strlen(fmt) - 1] != '\n')
                OutputDebugStringA("\n");
        }
        else if (g_sayType == SayTypeConsole) {
            PRINTF(_s);
            // fputs(_s, stdout);
            if (SAY_NEW_LINE && fmt[strlen(fmt) - 1] != '\n')
                PRINTF("\n");
            // fputs("\n", stdout);
        }
        */
    }
}

void say::sayLevel(SayLevel level)
{
    remove("_log.txt");
    g_level = level;
}

void say::sayType(SayType type) { g_sayType = type; }

void InitLogs(int argc, const char **argv)
{
    const char *logLevel = GetOption("--logLevel", argc, argv);
    if (logLevel) {
        if (!strcmp(logLevel, "debug")) {
            say::sayLevel(say::SayLevelDebug);
        }
        else if (!strcmp(logLevel, "info")) {
            say::sayLevel(say::SayLevelInfo);
        }
        else if (!strcmp(logLevel, "error")) {
            say::sayLevel(say::SayLevelError);
        }
        else if (!strcmp(logLevel, "warning")) {
            say::sayLevel(say::SayLevelWarning);
        }
        else if (!strcmp(logLevel, "silent")) {
            say::sayLevel(say::SayLevelSilent);
        }
        else {
            SAY_FATAL("Unknown log level: %s\n", logLevel);
        }
    }
    const char *logType = GetOption("--logType", argc, argv);

    if (logType) {
        if (!strcmp(logType, "debug")) {
            say::sayType(say::SayTypeDbg);
        }
        else if (!strcmp(logType, "console")) {
            say::sayType(say::SayTypeConsole);
        }
        else {
            SAY_FATAL("Unknown log type: %s\n", logType);
        }
    }
}
