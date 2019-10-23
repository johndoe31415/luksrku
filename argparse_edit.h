/*
 *   This file was AUTO-GENERATED by pypgmopts.
 *
 *   https://github.com/johndoe31415/pypgmopts
 *
 *   Do not edit it by hand, your changes will be overwritten.
 *
 *   Generated at: 2019-10-23 10:06:43
 */

#ifndef __ARGPARSE_EDIT_H__
#define __ARGPARSE_EDIT_H__

#include <stdbool.h>

#define ARGPARSE_EDIT_DEFAULT_VERBOSE		0

#define ARGPARSE_EDIT_NO_OPTION		0
#define ARGPARSE_EDIT_POSITIONAL_ARG	1

enum argparse_edit_option_t {
	ARG_EDIT_VERBOSE = 2,
	ARG_EDIT_FILENAME = 3,
};

typedef void (*argparse_edit_errmsg_callback_t)(const char *errmsg, ...);
typedef void (*argparse_edit_errmsg_option_callback_t)(enum argparse_edit_option_t error_option, const char *errmsg, ...);
typedef bool (*argparse_edit_callback_t)(enum argparse_edit_option_t option, const char *value, argparse_edit_errmsg_callback_t errmsg_callback);
typedef bool (*argparse_edit_plausibilization_callback_t)(argparse_edit_errmsg_option_callback_t errmsg_callback);

bool argparse_edit_parse(int argc, char **argv, argparse_edit_callback_t argument_callback, argparse_edit_plausibilization_callback_t plausibilization_callback);
void argparse_edit_show_syntax(void);
void argparse_edit_parse_or_quit(int argc, char **argv, argparse_edit_callback_t argument_callback, argparse_edit_plausibilization_callback_t plausibilization_callback);

#endif