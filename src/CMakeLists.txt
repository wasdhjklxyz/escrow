add_executable(escrow
  apply.c changes.c cmd.c diff.c jail.c landlock.c log.c main.c overlay.c
  policy.c proc.c record.c seccomp.c sig.c tree.c)
target_link_libraries(escrow PRIVATE escrow::common)
install(TARGETS escrow)
