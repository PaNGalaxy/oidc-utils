#include "log.h"
#include <stdio.h>
#include <stdarg.h>
#include <string.h>

#include "config.h"

void logstr(const char *msg) {
    logit("%s\n", msg);
}

void logit(const char *format, ...) {
    if (!config.enable_log) {
        return;
    }

    FILE *log = stderr;

    if (config.log_file != NULL && strcmp(config.log_file, "system") != 0) {
        log = fopen(config.log_file, "at");
        if (!log) log = fopen(config.log_file, "wt");
        if (!log) {
            return;
        }
    }

    va_list argptr;
    va_start(argptr, format);
    vfprintf(log, format, argptr);
    va_end(argptr);

    fclose(log);
}