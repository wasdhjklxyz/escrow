add_executable(escrow main.c)
target_link_libraries(escrow PRIVATE escrow::common)
install(TARGETS escrow)
