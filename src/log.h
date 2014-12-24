/*
 *  This file is part of capwap-mitm.
 *
 *  Foobar is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  capwap-mitm is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with capwap-mitm.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef __LOG_H
#define __LOG_H

#include <string.h>
#define __FILE_NAME__ (strrchr(__FILE__, '/') ? strrchr(__FILE__, '/') + 1 : strrchr(__FILE__, '\\') ? strrchr(__FILE__, '\\') + 1 : __FILE__)

#include <syslog.h>

#define log(priority, ...)	syslog(priority, __VA_ARGS__)

#if defined(DEBUG)

#define debug(...)						\
	_debug(__FILE_NAME__, __LINE__, __func__,__VA_ARGS__)
#define debug_head(tv)						\
	_debug_head(__FILE_NAME__, __LINE__, __func__, tv)

void debug_log(const char *fmt, ...) __attribute__ ((__format__ (__printf__, 1, 2)));
void debug_flush(void);

void _debug(const char *filename, int line, const char *func, const char *fmt, ...)
	__attribute__ ((__format__ (__printf__, 4, 5)));
void _debug_head(const char *filename, int line, const char *func, struct timeval *);

#else

#define debug(format, ...) do {} while (0)

#define debug_head() do {} while (0)
#define debug_log(format, ...) do {} while (0)
#define debug_flush() do {} while (0)

#endif

#endif /* __LOG_H */
