add_executable(escrow main.c jail.c overlay.c diff.c landlock.c policy.c seccomp.c)
target_link_libraries(escrow PRIVATE escrow::common)
install(TARGETS escrow)
