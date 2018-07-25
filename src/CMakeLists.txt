add_library(
  ipv4
  utils.cpp
  wireformat.cpp
  udpv4client.cpp udpv4server.cpp
  tcpv4client.cpp tcpv4server.cpp )
add_library( threadpool threadpool.cpp )
add_library( dns dns.cpp domainname.cpp )
add_library( dnsserver dns_server.cpp )

set( CLIENT_LIBRARY boost_program_options boost_thread boost_system dns ipv4 ${OPENSSL_CRYPTO_LIBRARY} )
set( SERVER_LIBRARY dnsserver threadpool ${CLIENT_LIBRARY} )

add_executable( axfr_server    axfr_server.cpp )

target_link_libraries( axfr_server    ${SERVER_LIBRARY} )

