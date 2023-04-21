#ifndef __LOG_H__
#define __LOG_H__
#include <stdlib.h>


extern FILE *log_fp;    //  log file
int addTimeHeader(char *const buffer) // input output buffer, ptr should not be changed, thus *const
{
    char tmp[1000]={0};
    long currenttime;
    struct timeval tv;
    gettimeofday(&tv,NULL);
    currenttime=tv.tv_sec*1000+tv.tv_usec/1000;
    char s[1000]={"\0"};
    sprintf(s, "%ld", currenttime);
    strcat(tmp,"[");
    strcat(tmp,s);
    strcat(tmp,"] ");
    strcat(buffer, tmp);
    return 0;
}

#define Log_printf(iotype, format, ...) fprintf(iotype, format, ##__VA_ARGS__), fflush(iotype)

#define SENDLog(format, ...)                                      \
    do                                                             \
    {                                                              \
        char logBuffer[1024] = {0};                                \
        addTimeHeader(logBuffer);                                 \
        strcat(logBuffer, "[SEND] ");                                \
        fflush(stdout);                                            \
        fprintf(stdout, BG_L_BLUE(L_YELLOW(BOLD("[ SEND LOG ]")))); \
        PRINT_UTIL_TRACEBACK_STDOUT                                \
        fprintf(stdout, DIM("%s"), logBuffer);                     \
        Log_printf(log_fp, "%s", logBuffer);                   \
        fprintf(stdout, DIM(format) UNSET_FORMAT, ##__VA_ARGS__);  \
        fflush(stdout);                                            \
        Log_printf(log_fp, format, ##__VA_ARGS__);             \
    } while (0)

    #define RECVLog(format, ...)                                      \
    do                                                             \
    {                                                              \
        char logBuffer[1024] = {0};                              \
        addTimeHeader(logBuffer);                                \
        strcat(logBuffer, "[RECV] ");                                 \
        fflush(stdout);                                            \
        fprintf(stdout, BG_L_BLUE(L_YELLOW(BOLD("[ RECV LOG ]")))); \
        PRINT_UTIL_TRACEBACK_STDOUT                                \
        fprintf(stdout, DIM("%s"), logBuffer);                     \
        Log_printf(log_fp, "%s", logBuffer);                   \
        fprintf(stdout, DIM(format) UNSET_FORMAT, ##__VA_ARGS__);  \
        fflush(stdout);                                            \
        Log_printf(log_fp, format, ##__VA_ARGS__);             \
    } while (0)

    #define RWNDLog(format, ...)                                      \
    do                                                             \
    {                                                              \
        char logBuffer[1024] = {0};                                \
        strcat(logBuffer, "[RWND] ");                                    \
        addTimeHeader(logBuffer);                                  \
        fflush(stdout);                                            \
        fprintf(stdout, BG_L_BLUE(L_YELLOW(BOLD("[ RWND LOG ]")))); \
        PRINT_UTIL_TRACEBACK_STDOUT                                \
        fprintf(stdout, DIM("%s"), logBuffer);                     \
        Log_printf(log_fp, "%s", logBuffer);                   \
        fprintf(stdout, DIM(format) UNSET_FORMAT, ##__VA_ARGS__);  \
        fflush(stdout);                                            \
        Log_printf(log_fp, format, ##__VA_ARGS__);             \
    } while (0)

    #endif