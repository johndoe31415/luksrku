/*
	luksrku - Tool to remotely unlock LUKS disks using TLS.
	Copyright (C) 2016-2016 Johannes Bauer

	This file is part of luksrku.

	luksrku is free software; you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation; this program is ONLY licensed under
	version 3 of the License, later versions are explicitly excluded.

	luksrku is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License
	along with luksrku; if not, write to the Free Software
	Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

	Johannes Bauer <JohannesBauer@gmx.de>
*/

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
bool should_log(enum loglvl_t level);
void log_msg(enum loglvl_t level, const char *msg, ...);
void log_libc(enum loglvl_t level, const char *msg, ...);
void log_openssl(enum loglvl_t level, const char *msg, ...);
/***************  AUTO GENERATED SECTION ENDS   ***************/

#endif
