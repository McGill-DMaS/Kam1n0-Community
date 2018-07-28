/*
 * exceptions4c lightweight version 1.0
 *
 * Copyright (c) 2014 Guillermo Calvo
 * Licensed under the GNU Lesser General Public License
 */

#ifndef EXCEPTIONS4C_LITE
#define EXCEPTIONS4C_LITE

#include <stddef.h>
#include <setjmp.h>

/* Maximum number of nested `try` blocks */
#ifndef E4C_MAX_FRAMES
# define E4C_MAX_FRAMES 16
#endif

/* Maximum length (in bytes) of an exception message */
#ifndef E4C_MESSAGE_SIZE
# define E4C_MESSAGE_SIZE 128
#endif

/* Exception handling keywords: try/catch/finally/throw */
#ifndef E4C_NOKEYWORDS
# define try E4C_TRY
# define catch(type) E4C_CATCH(type)
# define finally E4C_FINALLY
# define throw(type, message) E4C_THROW(type, message)
#endif

/* Represents an exception type */
struct e4c_exception_type{
	const char * name;
	const char * default_message;
	const struct e4c_exception_type * supertype;
};

/* Declarations and definitions of exception types */
#define E4C_DECLARE_EXCEPTION(name) extern const struct e4c_exception_type name
#define E4C_DEFINE_EXCEPTION(name, default_message, supertype) const struct e4c_exception_type name = { #name, default_message, &supertype }

/* Predefined exception types */
E4C_DECLARE_EXCEPTION(RuntimeException);
E4C_DECLARE_EXCEPTION(NullPointerException);

/* Represents an instance of an exception type */
struct e4c_exception{
	char message[E4C_MESSAGE_SIZE];
	const char * file;
	int line;
	const struct e4c_exception_type * type;
};

/* Retrieve current thrown exception */
#define E4C_EXCEPTION e4c.err

/* Returns whether current exception is of a given type */
#define E4C_IS_INSTANCE_OF(t) ( e4c.err.type == &t || e4c_extends(e4c.err.type, &t) )

/* Implementation details */
#define E4C_TRY if(e4c_try(E4C_INFO) && setjmp(e4c.jump[e4c.frames - 1]) >= 0) while(e4c_hook(0)) if(e4c.frame[e4c.frames].stage == e4c_trying)
#define E4C_CATCH(type) else if(e4c.frame[e4c.frames].stage == e4c_catching && E4C_IS_INSTANCE_OF(type) && e4c_hook(1))
#define E4C_FINALLY else if(e4c.frame[e4c.frames].stage == e4c_finalizing)
#define E4C_THROW(type, message) e4c_throw(&type, E4C_INFO, message)
#ifndef NDEBUG
# define E4C_INFO __FILE__, __LINE__
#else
# define E4C_INFO NULL, 0
#endif

enum e4c_stage{e4c_beginning, e4c_trying, e4c_catching, e4c_finalizing, e4c_done};
extern struct e4c_context{jmp_buf jump[E4C_MAX_FRAMES]; struct e4c_exception err; struct{unsigned char stage; unsigned char uncaught;} frame[E4C_MAX_FRAMES + 1]; int frames;} e4c;
extern int e4c_try(const char * file, int line);
extern int e4c_hook(int is_catch);
extern int e4c_extends(const struct e4c_exception_type * child, const struct e4c_exception_type * parent);
extern void e4c_throw(const struct e4c_exception_type * exception_type, const char * file, int line, const char * message);

# endif
