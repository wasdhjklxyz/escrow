add_executable(escrow
  apply.c changes.c diff.c jail.c landlock.c main.c overlay.c policy.c
  proc.c seccomp.c tree.c)
target_link_libraries(escrow PRIVATE escrow::common)
install(TARGETS escrow)
