#include "sandbox.h"

void errExit(const char* msg) {
	perror(msg);
	exit(EXIT_FAILURE)
}
