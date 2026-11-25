#ifndef ESCROW_DIFF_H
#define ESCROW_DIFF_H

// Prints what the overlay upper dir changes relative to the workspace, one
// "A|M|D|? <relpath>" line per entry on stdout, sorted by strcmp per
// directory, with a trailing '/' on dirs. '?' means it couldn't be compared
// (unreadable workspace entry). Run from the host ns after the agent is
// dead. upper and ws must be realpath() output. Returns false if any '?'
// line was printed.
bool diff_print(const char *upper, const char *ws);

#endif
