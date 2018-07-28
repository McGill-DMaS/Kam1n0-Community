/*
 * exceptions4c lightweight version 1.0
 *
 * Copyright (c) 2014 Guillermo Calvo
 * Licensed under the GNU Lesser General Public License
 */

#include <stdlib.h>
#include <stdio.h>
#include "e4c_lite.h"

E4C_DEFINE_EXCEPTION(RuntimeException, "Runtime exception.", RuntimeException);
E4C_DEFINE_EXCEPTION(NullPointerException, "Null pointer.", RuntimeException);

struct e4c_context e4c = {0};
static const char * err_msg[] = {"\n\nError: %s (%s)\n\n", "\n\nUncaught %s: %s\n\n    thrown at %s:%d\n\n"};

static void e4c_propagate(void){

	e4c.frame[e4c.frames].uncaught = 1;

	if(e4c.frames > 0) longjmp(e4c.jump[e4c.frames - 1], 1);

	if(fprintf(stderr, e4c.err.file == NULL ? err_msg[0] : err_msg[1], e4c.err.type->name, e4c.err.message, e4c.err.file, e4c.err.line) > 0)
		(void)fflush(stderr);

	exit(EXIT_FAILURE);
}

int e4c_try(const char * file, int line){

	if(e4c.frames >= E4C_MAX_FRAMES) e4c_throw(&RuntimeException, file, line, "Too many `try` blocks nested.");

	e4c.frames++;

	e4c.frame[e4c.frames].stage = e4c_beginning;
	e4c.frame[e4c.frames].uncaught = 0;

	return 1;
}

int e4c_hook(int is_catch){

	int uncaught;

	if(is_catch) return !(e4c.frame[e4c.frames].uncaught = 0);

	uncaught = e4c.frame[e4c.frames].uncaught;

	e4c.frame[e4c.frames].stage++;
	if(e4c.frame[e4c.frames].stage == e4c_catching && !uncaught) e4c.frame[e4c.frames].stage++;

	if(e4c.frame[e4c.frames].stage < e4c_done) return 1;

	e4c.frames--;

	if(uncaught) e4c_propagate();

	return 0;
}

int e4c_extends(const struct e4c_exception_type * child, const struct e4c_exception_type * parent){

	for(; child != NULL && child->supertype != child; child = child->supertype)
		if(child->supertype == parent) return 1;

	return 0;
}

void e4c_throw(const struct e4c_exception_type * exception_type, const char * file, int line, const char * message){

	e4c.err.type = (exception_type != NULL ? exception_type : &NullPointerException);
	e4c.err.file = file;
	e4c.err.line = line;

	(void)sprintf(e4c.err.message, "%.*s", (int)E4C_MESSAGE_SIZE - 1, (message != NULL ? message : e4c.err.type->default_message));

	e4c_propagate();
}
