#ifndef SAY_INCLUDED
#define SAY_INCLUDED

#define SAY_NEW_LINE 0      // add new line after each say
#define SAY_FULL_INFO 0     // print file/line/function each say

#ifdef DR_BUILD

#include "dr_api.h"
#define PRINTF dr_printf
#define VSNPRINTF dr_vsnprintf
#define ABORT dr_abort

#else // DR_BUILD ]

#define PRINTF printf
#define VSNPRINTF vsnprintf
#define ABORT exit

#endif // DR_BUILD

void InitLogs(int argc, const char** argv);

namespace say {

  enum SayType {
    SayTypeConsole = 0,
    SayTypeDbg
  };

  enum SayLevel {
    SayLevelTrace = 0,
    SayLevelDebug,
    SayLevelInfo,
    SayLevelWarning,
    SayLevelError,
    SayLevelSilent
  };

  void say(SayLevel level, const char* fmt, ...);
  void sayLevel(SayLevel l);
  void sayType(SayType type);
}

#define STRINGIFY(x) #x
#define S_(x) STRINGIFY(x)

#define SAY(x, ...)     say::say(say::SayLevelInfo,    x, __VA_ARGS__)

#if SAY_FULL_INFO

  #define SAY_TRACE(x, ...)   say::say(say::SayLevelTrace,   "[.] " __FILE__ " :" S_(__LINE__) " " x, __VA_ARGS__)
  #define SAY_DEBUG(x, ...)   say::say(say::SayLevelDebug,   "[*] " __FILE__ " :" S_(__LINE__) " " x, __VA_ARGS__)
  #define SAY_INFO(x, ...)    say::say(say::SayLevelInfo,    "[+] " __FILE__ " :" S_(__LINE__) " " x, __VA_ARGS__)
  #define SAY_WARN(x, ...)    say::say(say::SayLevelWarning, "[~] " __FILE__ " :" S_(__LINE__) " " x, __VA_ARGS__)
  #define SAY_ERROR(x, ...)   say::say(say::SayLevelError,   "[!] " __FILE__ " :" S_(__LINE__) " " x, __VA_ARGS__)
  #define SAY_FATAL(x, ...)   {say::say(say::SayLevelError,   "[!!!] " __FILE__ " :" S_(__LINE__) " " x, __VA_ARGS__); ABORT(-1);}

  #define SAY_INFO_RAW(x, ...)   say::say(say::SayLevelInfo,   x, __VA_ARGS__)
  #define SAY_DEBUG_RAW(x, ...)   say::say(say::SayLevelDebug,   x, __VA_ARGS__)

#else

  #define SAY_TRACE(x, ...)   say::say(say::SayLevelTrace,   "[.] " x, __VA_ARGS__)
  #define SAY_DEBUG(x, ...)   say::say(say::SayLevelDebug,   "[*] " x, __VA_ARGS__)
  #define SAY_INFO(x, ...)    say::say(say::SayLevelInfo,    "[+] " x, __VA_ARGS__)
  #define SAY_WARN(x, ...)    say::say(say::SayLevelWarning, "[~] " x, __VA_ARGS__)
  #define SAY_ERROR(x, ...)   say::say(say::SayLevelError,   "[!] " x, __VA_ARGS__)
  #define SAY_FATAL(x, ...)   {say::say(say::SayLevelError,   "[!!!] " x, __VA_ARGS__); ABORT(-1);}

  #define SAY_INFO_RAW(x, ...)   say::say(say::SayLevelInfo,   x, __VA_ARGS__)
  #define SAY_DEBUG_RAW(x, ...)   say::say(say::SayLevelDebug,   x, __VA_ARGS__)

#endif

#define LOG_INFO  SAY_INFO
#define LOG_DEBUG SAY_DEBUG
#define LOG_WARN  SAY_WARN
#define LOG_ERROR SAY_ERROR

#endif // SAY_INCLUDED
