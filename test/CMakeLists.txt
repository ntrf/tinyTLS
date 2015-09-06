cmake_minimum_required(VERSION 3.0.0)

add_executable(tinyTLS_test
	MSocket.h
	wsocket.cpp
	test.cpp
)
target_link_libraries(tinyTLS_test tinyTLS)

if(WIN32)
	target_link_libraries(tinyTLS_test ws2_32.lib)
endif()