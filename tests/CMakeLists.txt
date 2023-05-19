set(APP test)
set(
    TEST_SRC
    test.c
)

add_executable(${APP} ${TEST_SRC})

target_compile_options(${APP} PUBLIC ${PJ_CFLAGS_OTHER})
target_include_directories(${APP} PRIVATE ../websock)
target_include_directories(${APP} PUBLIC ${PJ_INCLUDE_DIRS})
target_link_directories(${APP} PUBLIC ${PJ_LIBRARY_DIRS})
target_link_libraries(${APP} pjwebsock)
target_link_libraries(${APP} ${PJ_LIBRARIES})
target_link_libraries(${APP} ${PLATFORM_LIBS})

install(TARGETS ${APP} DESTINATION ${CMAKE_INSTALL_BINDIR})
