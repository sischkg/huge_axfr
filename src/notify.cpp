#include "dns.hpp"
#include "udpv4client.hpp"
#include <algorithm>
#include <arpa/inet.h>
#include <boost/program_options.hpp>
#include <cstring>
#include <iostream>

const char *DEFAULT_SERVER_ADDRESS = "127.0.0.1";
const char *DEFAULT_ZONE_NAME      = "example.com";

namespace po = boost::program_options;

int main( int argc, char **argv )
{
    std::string target_server;
    uint16_t    target_port;
    std::string zone_name;

    po::options_description desc( "NOTIFY Client" );
    desc.add_options()( "help,h", "print this message" )

        ( "target,t",
          po::value<std::string>( &target_server )->default_value( DEFAULT_SERVER_ADDRESS ),
          "target server address" )
        ( "port,p",
          po::value<uint16_t>( &target_port )->default_value( 53 ),
          "target port" )
	( "zone,z", po::value<std::string>( &zone_name )->default_value( DEFAULT_ZONE_NAME ), "zone name" );

    po::variables_map vm;
    po::store( po::parse_command_line( argc, argv, desc ), vm );
    po::notify( vm );

    if ( vm.count( "help" ) ) {
        std::cerr << desc << "\n";
        return 1;
    }

    dns::PacketInfo                        packet_info;
    std::vector<dns::QuestionSectionEntry> question_section;

    dns::QuestionSectionEntry question;
    question.mDomainname = zone_name;
    question.mType       = dns::TYPE_SOA;
    question.mClass      = dns::CLASS_IN;
    packet_info.pushQuestionSection( question );

    packet_info.mID                  = 1234;
    packet_info.mOpcode              = dns::OPCODE_NOTIFY;
    packet_info.mQueryResponse       = 0;
    packet_info.mAuthoritativeAnswer = 0;
    packet_info.mTruncation          = 0;
    packet_info.mRecursionDesired    = 0;
    packet_info.mRecursionAvailable  = 0;
    packet_info.mZeroField           = 0;
    packet_info.mAuthenticData       = 0;
    packet_info.mCheckingDisabled    = 1;
    packet_info.mResponseCode        = 0;

    WireFormat notify_data;
    packet_info.generateMessage( notify_data );

    udpv4::ClientParameters udp_param;
    udp_param.mAddress = target_server;
    udp_param.mPort    = target_port;
    udpv4::Client udp( udp_param );

    udp.sendPacket( notify_data );
    udpv4::PacketInfo recv_data = udp.receivePacket();
	
    dns::PacketInfo res = dns::parseDNSMessage( recv_data.begin(), recv_data.end() );

    std::cout << res;

    return 0;
}
