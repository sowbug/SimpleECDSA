#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.61)
AC_INIT(SimpleECDSA, 1.0.0, Jopsen@gmail.com)
AC_CONFIG_SRCDIR([src/point.h])
AC_CONFIG_HEADER([config.h])

#Run automake
AM_INIT_AUTOMAKE([-Wall -Werror foreign])

#AC config files
AC_CONFIG_FILES([
	Makefile
	src/Makefile
	])

# Checks for programs.
AC_PROG_CC

# Checks for libraries.
AC_CHECK_LIB(gmp, __gmpz_init, , [AC_MSG_ERROR(
[GMP not found, see http://gmplib.org/])])

# Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS([stdint.h stdlib.h string.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_HEADER_STDBOOL
AC_C_CONST
AC_TYPE_UINT32_T
AC_TYPE_UINT8_T

# Checks for library functions.
AC_FUNC_MALLOC
AC_FUNC_REALLOC
AC_CHECK_FUNCS([sqrt])

AC_OUTPUT
