cmake_minimum_required(VERSION 3.0.0)

project(tinyTLS)

option(TINYTLS_BUILD_EXAMPLE "Build example application with library" OFF)
option(TINYTLS_SKIP_INSTALL "Don't include tinytls into install target" OFF)

include_directories(.)

add_library(tinyTLS STATIC
	tinytls.h
	tinytls.hpp

	aes_hmac_sha.cpp
	aes_hmac_sha.h
	x509.cpp
	certdata.h
	debug.cpp
	internal.h
	intutils.h
	master.cpp
	random.cpp
	tls.cpp

	pkcs1/bigint.cpp
	pkcs1/bigint.h
	pkcs1/pkcs1.cpp
	pkcs1/pkcs1.h
	
	aes/aes_tables.h
	aes/rijndael.cpp
	aes/rijndael.h
	
	hash/hash.h
	hash/hmac.cpp
	hash/md5.cpp
	hash/sha1.cpp
	hash/sha256.cpp	
	hash/sha512.cpp	
	
	mlib/binary.h
	mlib/charstr.h
	
	cdb/cdb.cpp
	cdb/cdb.h
	
	certstore.cpp
)

if (TINYTLS_BUILD_EXAMPLE)
	add_subdirectory(test)
endif()

if (NOT TINYTLS_SKIP_INSTALL)
	install(TARGETS tinyTLS 
		LIBRARY DESTINATION lib
        ARCHIVE DESTINATION lib/static)
	install(FILES tinytls.h 
		DESTINATION include)
endif()