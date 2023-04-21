#ifndef __DEBUG_H__
#define __DEBUG_H__

#include <stdio.h>
#include <assert.h>

extern FILE *log_fp;

// formatting macros
#define UNSET_FORMAT "\33[0m"
#define BOLD(format) "\33[1m" format UNSET_FORMAT // notice that I used UNSET_FORMAT in the end

#define DIM(format) "\33[2m" format "\33[22m"

#define ITALIC(format) "\33[3m" format "\33[23m"
#define UNDERSCORE(format) "\33[4m" format "\33[24m"
#define INVERSE(format) "\33[7m" format "\33[27m"

// background,light tone black , greyish
#define DEFAULT_BACKGROUND_COLOR "\33[49m"
#define BG_L_BLACK(format) "\33[100m" format DEFAULT_BACKGROUND_COLOR
#define BG_L_RED(format) "\33[101m" format DEFAULT_BACKGROUND_COLOR
#define BG_L_GREEN(format) "\33[102m" format DEFAULT_BACKGROUND_COLOR
#define BG_L_YELLOW(format) "\33[103m" format DEFAULT_BACKGROUND_COLOR
#define BG_L_BLUE(format) "\33[104m" format DEFAULT_BACKGROUND_COLOR
#define BG_L_PURPLE(format) "\33[105m" format DEFAULT_BACKGROUND_COLOR
#define BG_L_CYAN(format) "\33[106m" format DEFAULT_BACKGROUND_COLOR

// text color
#define DEFAULT_FOREGROUND_COLOR "\33[39m"

#define BLACK(format) "\33[30m" format DEFAULT_FOREGROUND_COLOR
#define BLUE(format) "\33[34m" format DEFAULT_FOREGROUND_COLOR
#define RED(format) "\33[31m" format DEFAULT_FOREGROUND_COLOR
#define YELLOW(format) "\33[33m" format DEFAULT_FOREGROUND_COLOR
#define GREEN(format) "\33[32m" format DEFAULT_FOREGROUND_COLOR
#define PURPLE(format) "\33[35m" format DEFAULT_FOREGROUND_COLOR
#define CYAN(format) "\33[36m" format DEFAULT_FOREGROUND_COLOR
#define WHITE(format) "\33[37m" format DEFAULT_FOREGROUND_COLOR

// light tone text color
#define L_BLACK(format) "\33[90m" format DEFAULT_FOREGROUND_COLOR
#define L_BLUE(format) "\33[94m" format DEFAULT_FOREGROUND_COLOR
#define L_RED(format) "\33[91m" format DEFAULT_FOREGROUND_COLOR
#define L_YELLOW(format) "\33[93m" format DEFAULT_FOREGROUND_COLOR
#define L_GREEN(format) "\33[92m" format DEFAULT_FOREGROUND_COLOR
#define L_PURPLE(format) "\33[95m" format DEFAULT_FOREGROUND_COLOR
#define L_CYAN(format) "\33[96m" format DEFAULT_FOREGROUND_COLOR
#define L_WHITE(format) "\33[97m" format DEFAULT_FOREGROUND_COLOR

// end formatting macros

// formatting utils
#define GREEN_SQUARE_BRACKET(format) \
	L_GREEN("[")                     \
	format L_GREEN("]")

// end formatting utils

// tools
#define PRINT_UTIL_TRACEBACK(stdio_type) fprintf(stdio_type, GREEN_SQUARE_BRACKET(ITALIC("Traceback: " UNDERSCORE("%s:%d") ",%s")), __FILE__, __LINE__, __func__); // print the position where this macro is called
#define PRINT_UTIL_TRACEBACK_STDOUT PRINT_UTIL_TRACEBACK(stdout)																								   // print the position where this macro is called ,stdout
#define PRINT_UTIL_TRACEBACK_STDERR PRINT_UTIL_TRACEBACK(stderr)																								   // print the position where this macro is called ,stderr

// end tools

// macro to print Log
#ifdef LOG_FILE
#define Log_write(format, ...) fprintf(log_fp, format, ##__VA_ARGS__), fflush(log_fp)
#else
#define Log_write(format, ...)
#endif

#define Log(format, ...)                                          \
	do                                                            \
	{                                                             \
		fflush(stdout);                                           \
		fprintf(stdout, BG_L_BLUE(L_WHITE(BOLD("[ LOG ]"))));     \
		PRINT_UTIL_TRACEBACK_STDOUT                               \
		fprintf(stdout, DIM(format) UNSET_FORMAT, ##__VA_ARGS__); \
		fflush(stdout);                                           \
		Log_write(format, ##__VA_ARGS__);                         \
	} while (0)

// macro to print info
#define Info(format, ...)                                      \
	do                                                         \
	{                                                          \
		fflush(stdout);                                        \
		fprintf(stdout, BG_L_CYAN(L_WHITE(BOLD("[ INFO ]")))); \
		fprintf(stdout, format UNSET_FORMAT, ##__VA_ARGS__);   \
		fflush(stdout);                                        \
	} while (0)

// macro to print info with traceback information
#ifdef TraceableInfoON
#define TraceableInfo(format, ...)                             \
	do                                                         \
	{                                                          \
		fflush(stdout);                                        \
		fprintf(stdout, BG_L_CYAN(L_WHITE(BOLD("[ INFO ]")))); \
		PRINT_UTIL_TRACEBACK_STDOUT                            \
		fprintf(stdout, format UNSET_FORMAT, ##__VA_ARGS__);   \
		fflush(stdout);                                        \
	} while (0)
#else
#define TraceableInfo(format, ...)
#endif

// print, but with flush
#define FlushPrint(format, ...)                 \
	do                                          \
	{                                           \
		fprintf(stdout, format, ##__VA_ARGS__); \
		fflush(stdout);                         \
	} while (0)

// Assert with traceback
#define Assert(cond, ...)                                                 \
	do                                                                    \
	{                                                                     \
		if (!(cond))                                                      \
		{                                                                 \
			fflush(stdout);                                               \
			fprintf(stderr, BG_L_RED(L_YELLOW(BOLD("[ ASSERT FAIL ]")))); \
			PRINT_UTIL_TRACEBACK_STDERR                                   \
			fprintf(stderr, "\33[31m\33[1m");                             \
			fprintf(stderr, __VA_ARGS__);                                 \
			fprintf(stderr, "\33[0m");                                    \
			assert(cond);                                                 \
		}                                                                 \
	} while (0)

#define Panic(format, ...)                                      \
	do                                                          \
	{                                                           \
		fflush(stdout);                                         \
		fprintf(stderr, BG_L_RED(L_YELLOW(BOLD("[ PANIC ]")))); \
		PRINT_UTIL_TRACEBACK_STDERR                             \
		fprintf(stderr, RED(BOLD(format)), __VA_ARGS__);        \
		fprintf(stderr, "\33[0m");                              \
		assert(0);                                              \
	} while (0)

#define Error(format, ...)                                   \
	do                                                       \
	{                                                        \
		fflush(stdout);                                      \
		fprintf(stderr, BG_L_RED(L_WHITE(BOLD("[ ERR ]")))); \
		PRINT_UTIL_TRACEBACK_STDERR                          \
		fprintf(stderr, RED(format), ##__VA_ARGS__);         \
		fprintf(stderr, "\33[0m");                           \
	} while (0)

#define Success(format, ...)                                  \
	do                                                        \
	{                                                         \
		fflush(stdout);                                       \
		fprintf(stdout, BG_L_GREEN(L_WHITE(BOLD("[ OK ]")))); \
		fprintf(stdout, GREEN(format), ##__VA_ARGS__);        \
		fprintf(stdout, "\33[0m");                            \
		fflush(stdout);                                       \
	} while (0)

// #ifdef DEBUG_ON
//#define DEBUG(content) \
//	do                 \
//	{                  \
//		content        \
//	} while (0);
//#else
//#define DEBUG(content) ;
//#endif

#endif
