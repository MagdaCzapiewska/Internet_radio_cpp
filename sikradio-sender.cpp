#include <cstdio>
#include <iostream>
#include <string>
#include <cstdint>
#include <cstdlib>
#include </usr/include/boost/program_options.hpp>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <endian.h>

#include "structures.h"
#include "err.h"

namespace po = boost::program_options;
std::string dest_addr;
std::string data_port;
int64_t PSIZE;
std::string NAME;

uint64_t session_id = 0;
uint64_t current_package = 0;

uint16_t read_port(char *string, char **port_char) {
    errno = 0;
    unsigned long port = strtoul(string, NULL, 10);
    if (errno != 0) {
        delete[] (*port_char);
    }
    PRINT_ERRNO();
    if (port > UINT16_MAX) {
        delete[] (*port_char);
        fatal("%u is not a valid port number", port);
    }

    return (uint16_t) port;
}

struct sockaddr_in get_send_address(char *host, uint16_t port) {
    struct addrinfo hints;
    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_INET; // IPv4
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_protocol = IPPROTO_UDP;

    struct addrinfo *address_result;
    CHECK_AND_DELETE(getaddrinfo(host, NULL, &hints, &address_result), host);

    struct sockaddr_in send_address;
    send_address.sin_family = AF_INET; // IPv4
    send_address.sin_addr.s_addr =
            ((struct sockaddr_in *) (address_result->ai_addr))->sin_addr.s_addr; // IP address
    send_address.sin_port = htons(port); // port from the command line

    freeaddrinfo(address_result);

    return send_address;
}

ssize_t send_message(int socket_fd, const struct sockaddr_in *send_address,
                     const void *message, size_t length) {
    int send_flags = 0;
    socklen_t address_length = (socklen_t) sizeof(*send_address);
    errno = 0;
    ssize_t sent_length = sendto(socket_fd, message, length, send_flags,
                                 (struct sockaddr *) send_address, address_length);

    return sent_length;
}

void check_data_port_content(char *port) {
    int ind = 0;
    while (port[ind] != '\0') {
        if (! ((int)port[ind] >= (int)('0') && (int)port[ind] <= (int)('9'))) {
            std::cerr << "Port number must consist of digits!\n";
            delete[] port;
            exit(1);
        }
        ind++;
    }
}

void read_program_options(int &argc, char*** argv) {

    po::options_description desc("Allowed options");
    desc.add_options()
            ("help,h", "produce help message")
            ("dest_addr,a", po::value<std::string>(&dest_addr),
             "set destination address (obligatory)")
            ("data_port,P", po::value<std::string>(&data_port)->default_value("27863"),
             "set data port (optional)")
            ("psize,p", po::value<int64_t>(&PSIZE)->default_value(512),
             "set package size (optional)")
            ("name,n", po::value<std::string>(&NAME)->default_value("Nienazwany nadajnik"),
             "set sender name (optional)")
            ;

    po::variables_map vm;
    try {
        po::store(po::parse_command_line(argc, *argv, desc), vm);
        po::notify(vm);
    }
    catch (const std::exception& e) {
        std::cerr << e.what() << "\n";
        std::cerr << desc << "\n";
        exit(1);
    }

    if (argc < 2) {
        std::cerr << "Usage: " << (*argv)[0] << " [options]\n";
        std::cerr << desc;
        exit(1);
    }

    if (vm.count("help")) {
        std::cout << desc;
        exit(1);
    }
    if (!vm.count("dest_addr")){
        std::cerr << "Setting destination address is obligatory!\n";
        exit(1);
    }
    if (PSIZE <= 0) {
        std::cerr << "PSIZE cannot be zero or below!\n";
        exit(1);
    }
    if (PSIZE > 65507 - 16) {
        std::cerr << "PSIZE cannot be greater than 65507 (max UDP datagram) - 16 (first two fields)!\n";
        exit(1);
    }
    if (empty(NAME)) {
        std::cerr << "NAME cannot be empty!\n";
        exit(1);
    }
    else if (NAME[0] == ' ') {
        std::cerr << "NAME cannot begin with space!\n";
        exit(1);
    }
    else if (NAME[NAME.length() - 1] == ' ') {
        std::cerr << "NAME cannot end with space!\n";
        exit(1);
    }
    else {
        size_t i = 0;
        while (i != NAME.length()) {
            if ((int)NAME[i] < 32) {
                std::cerr << "NAME has to consist of signs with ascii codes between 32 and 127!";
                exit(1);
            }
            i++;
        }
    }
}

int main(int argc, char *argv[]) {

    session_id = time(NULL);

    read_program_options(argc, &argv);

    size_t data_port_length = data_port.length();
    char *port_char = new char[data_port_length + 1];
    strcpy(port_char, data_port.c_str());
    check_data_port_content(port_char);
    uint16_t port = read_port(port_char, &port_char);
    delete[] port_char;

    size_t dest_addr_length = dest_addr.length();
    char *dest_char = new char[dest_addr_length + 1];
    strcpy(dest_char, dest_addr.c_str());
    struct sockaddr_in send_address = get_send_address(dest_char, port);
    delete[] dest_char;

    int socket_fd = socket(PF_INET, SOCK_DGRAM, 0);
    if (socket_fd < 0) {
        PRINT_ERRNO();
    }

    struct DataStructure data_to_send;
    data_to_send.session_id = htobe64(session_id);
    ssize_t sent_length;

    size_t SIZE_T_PSIZE = (size_t)PSIZE;
    size_t result = fread(data_to_send.audio_data, sizeof(*(data_to_send.audio_data)), SIZE_T_PSIZE, stdin);

    while (result == SIZE_T_PSIZE) {
        uint64_t fbn = SIZE_T_PSIZE * current_package;

        data_to_send.first_byte_num = htobe64(fbn);
        current_package++;
        sent_length = send_message(socket_fd, &send_address, &data_to_send, SIZE_T_PSIZE + 16);
        if (sent_length < 0) {
            PRINT_ERRNO();
        }
        ENSURE(sent_length == (ssize_t) (SIZE_T_PSIZE + 16));

        result = fread(data_to_send.audio_data, sizeof(*(data_to_send.audio_data)), SIZE_T_PSIZE, stdin);
    }

    CHECK_ERRNO(close(socket_fd));
    exit(0);
}