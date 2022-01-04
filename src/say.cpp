#include "say.h"
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

void say::set_level(SayLevel level)
{
    remove("_log.txt");
    g_level = level;
}

void say::say_type(SayType type) { g_sayType = type; }

void init_logs(int argc, const char **argv)
{
    const char *log_level = GetOption("--log_level", argc, argv);
    if (log_level) {
        if (!strcmp(log_level, "debug")) {
            say::set_level(say::SayLevelDebug);
        }
        else if (!strcmp(log_level, "info")) {
            say::set_level(say::SayLevelInfo);
        }
        else if (!strcmp(log_level, "error")) {
            say::set_level(say::SayLevelError);
        }
        else if (!strcmp(log_level, "warning")) {
            say::set_level(say::SayLevelWarning);
        }
        else if (!strcmp(log_level, "silent")) {
            say::set_level(say::SayLevelSilent);
        }
        else {
            SAY_FATAL("Unknown log level: %s\n", log_level);
        }
    }
    const char *logType = GetOption("--log_type", argc, argv);

    if (logType) {
        if (!strcmp(logType, "debug")) {
            say::say_type(say::SayTypeDbg);
        }
        else if (!strcmp(logType, "console")) {
            say::say_type(say::SayTypeConsole);
        }
        else {
            SAY_FATAL("Unknown log type: %s\n", logType);
        }
    }
}
