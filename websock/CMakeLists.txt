set(
    WEBSOCK_SRC
    websock_transport_tcp.c
    websock_transport_tls.c
    websock_transport.c
    websock.c
    http.c
)

add_library(pjwebsock ${WEBSOCK_SRC})
target_compile_options(pjwebsock PUBLIC ${PJ_CFLAGS_OTHER})
target_include_directories(pjwebsock
    PRIVATE
        .
    PUBLIC
        ${PJ_INCLUDE_DIRS})

install(TARGETS pjwebsock DESTINATION ${CMAKE_INSTALL_LIBDIR})
install(FILES websock.h DESTINATION include/pjwebsock)
