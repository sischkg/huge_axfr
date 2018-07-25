

set( TEST_LIBRARY gtest pthread )
set( UTIL_LIBRARY ipv4  ${OPENSSL_CRYPTO_LIBRARY} ${TEST_LIBRARY} )
set( DNS_LIBRARY  dns   ${UTIL_LIBRARY} )

add_executable( test-base64       test-base64.cpp )
add_executable( test-base32       test-base32.cpp )
add_executable( test-hex          test-hex.cpp )
add_executable( test-wireformat   test-wireformat.cpp )
add_executable( test-domainname   test-domainname.cpp )
add_executable( test-compression  test-compression.cpp )
add_executable( test-nsec         test-nsec.cpp )
target_link_libraries(test-base64      ${UTIL_LIBRARY} )
target_link_libraries(test-base32      ${UTIL_LIBRARY} )
target_link_libraries(test-hex         ${UTIL_LIBRARY} )
target_link_libraries(test-wireformat  ${UTIL_LIBRARY} )
target_link_libraries(test-domainname  ${DNS_LIBRARY} )
target_link_libraries(test-compression ${DNS_LIBRARY} )
target_link_libraries(test-nsec        ${DNS_LIBRARY} )

add_test(
  NAME base64
  COMMAND test-base64
)

add_test(
  NAME base32
  COMMAND test-base32
)

add_test(
  NAME hex
  COMMAND test-hex
)

add_test(
  NAME wireformat
  COMMAND test-wireformat
)

add_test(
  NAME domainname
  COMMAND test-domainname
)

add_test(
  NAME compression
  COMMAND test-compression
)

add_test(
  NAME nsec
  COMMAND test-nsec
)


