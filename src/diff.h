#ifndef ESCROW_DIFF_H
#define ESCROW_DIFF_H

#include <stdio.h>

/* Walk the overlay upper dir against the lower (workspace) and print one
 * "A|M|D <path>" line per change, dirs with a trailing '/'. Never follows
 * symlinks. Exits on failure. */
void diff_print(const char *upper, const char *lower, FILE *out);

#endif
