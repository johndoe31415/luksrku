#ifndef __LOG_H__
#define __LOG_H__

enum loglvl_t {
	LLVL_FATAL = 0,
	LLVL_ERROR = 1,
	LLVL_WARNING = 2,
	LLVL_INFO = 3,
	LLVL_DEBUG = 4
};

/*************** AUTO GENERATED SECTION FOLLOWS ***************/
void log_setlvl(enum loglvl_t level);
void log_msg(enum loglvl_t level, const char *msg, ...);
void log_libc(enum loglvl_t level, const char *msg, ...);
void log_openssl(enum loglvl_t level, const char *msg, ...);
/***************  AUTO GENERATED SECTION ENDS   ***************/

#endif
