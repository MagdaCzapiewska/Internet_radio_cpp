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
#include <thread>
#include <algorithm>
#include <mutex>
#include <vector>
#include <semaphore.h>

#include "structures.h"
#include "err.h"

namespace po = boost::program_options;
std::string src_addr;
std::string data_port;
int64_t BSIZE;
uint8_t *buffer = NULL;
int64_t PSIZE;
int64_t BSIZE_div_PSIZE;
uint64_t BYTE0;

size_t index_for_reader;
size_t max_fbn;
sem_t mutex_for_buffer;

bool reader_allowed_to_start = false;
sem_t starting_reader;

bool reader_asked_to_end = false;
sem_t reader_ending;

bool reader_waiting_for_data = false; // Dostęp do tej zmiennej jest koordynowany przez mutex for buffer
sem_t for_reader;

uint64_t session_id = 0;
std::vector<std::pair<uint64_t, uint16_t>> what_is_in_cells;

std::thread reader_thread;

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

int bind_socket(uint16_t port) {
    int socket_fd = socket(AF_INET, SOCK_DGRAM, 0); // creating IPv4 UDP socket
    ENSURE(socket_fd >= 0);
    // after socket() call; we should close(sock) on any execution path;

    struct sockaddr_in server_address;
    server_address.sin_family = AF_INET; // IPv4
    server_address.sin_addr.s_addr = htonl(INADDR_ANY); // listening on all interfaces
    server_address.sin_port = htons(port);

    // bind the socket to a concrete address
    CHECK_ERRNO(bind(socket_fd, (struct sockaddr *) &server_address,
                     (socklen_t) sizeof(server_address)));

    return socket_fd;
}

size_t read_message(int socket_fd, struct sockaddr_in *client_address, void *message, size_t max_length, int flags, char* src_char) {
    socklen_t address_length = (socklen_t) sizeof(*client_address);
    errno = 0;
    ssize_t len = recvfrom(socket_fd, message, max_length, flags,
                           (struct sockaddr *) client_address, &address_length);
    if (len < 0) {
        free(src_char);
        PRINT_ERRNO();
    }
    return (size_t) len;
}

void check_src_address(char *host) {
    struct addrinfo hints;
    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_INET; // IPv4
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_protocol = IPPROTO_UDP;

    struct addrinfo *address_result;
    CHECK_AND_DELETE(getaddrinfo(host, NULL, &hints, &address_result), host);

    freeaddrinfo(address_result);
    return;
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
            ("src_addr,a", po::value<std::string>(&src_addr),
             "set source address (obligatory)")
            ("data_port,P", po::value<std::string>(&data_port)->default_value("27863"),
             "set data port (optional)")
            ("bsize,b", po::value<int64_t>(&BSIZE)->default_value(65536),
             "set buffer size (optional)")
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
    if (!vm.count("src_addr")) {
        std::cerr << "Setting source address is obligatory!\n";
        exit(1);
    }
    if (BSIZE <= 0) {
        std::cerr << "BSIZE cannot be zero or below!\n";
        exit(1);
    }
}

void reader_thread_function() {
    sem_wait(&starting_reader);

    while (true) {
        sem_wait(&reader_ending);
        if (reader_asked_to_end) {
            reader_asked_to_end = false;
            sem_post(&reader_ending);
            return;
        }
        else {
            sem_post(&reader_ending);
        }
        sem_wait(&mutex_for_buffer);
        if(max_fbn >= (size_t)BSIZE_div_PSIZE * PSIZE)  {
            index_for_reader = std::max(index_for_reader, max_fbn - BSIZE_div_PSIZE * PSIZE);
        }
        if (index_for_reader > max_fbn) {

            sem_wait(&reader_ending);
            if (reader_asked_to_end) {
                reader_asked_to_end = false;
                sem_post(&reader_ending);
                sem_post(&mutex_for_buffer);
                return;
            }
            else {
                sem_post(&reader_ending);
            }

            sem_post(&mutex_for_buffer);
            reader_waiting_for_data = true;
            sem_wait(&for_reader);

            continue;
        }

        size_t cell_no = (index_for_reader / PSIZE) % BSIZE_div_PSIZE;
        size_t byte_no = cell_no * PSIZE;
        //std::cerr << "Bede wypisywac. Cell no: " << cell_no << ", byte no: " << byte_no << "\n";
        fwrite(buffer + byte_no, 1, PSIZE, stdout);
        memset(buffer + byte_no, 0, PSIZE);

        index_for_reader += PSIZE;
        sem_post(&mutex_for_buffer);
    }
}

void wait_for_reader_thread() {

    sem_wait(&reader_ending);
    reader_asked_to_end = true;
    sem_post(&reader_ending);

    if (!reader_allowed_to_start) {
        sem_post(&starting_reader);
    }

    sem_post(&mutex_for_buffer);
    if (index_for_reader > max_fbn) {
        sem_post(&for_reader);
    }
    sem_post(&mutex_for_buffer);

    reader_thread.join();
}

size_t next_cell(size_t cell) {
    if (cell > 0) {
        return cell - 1;
    }
    else {
        return BSIZE_div_PSIZE - 1;
    }
}

int main(int argc, char *argv[]) {

    read_program_options(argc, &argv);

    size_t data_port_length = data_port.length();
    char *port_char = new char[data_port_length + 1];
    strcpy(port_char, data_port.c_str());
    check_data_port_content(port_char);
    uint16_t port = read_port(port_char, &port_char);
    delete[] port_char;

    int socket_fd = bind_socket(port);
    struct sockaddr_in client_address;
    size_t read_length;

    size_t src_addr_length = src_addr.length();
    char *src_char = new char[src_addr_length + 1];
    strcpy(src_char, src_addr.c_str());
    check_src_address(src_char);

    struct DataStructure data;
    try {
        buffer = new uint8_t[BSIZE];
    }
    catch (const std::exception& e) {
        std::cerr << e.what() << "\n";
        delete[] src_char;
        exit(1);
    }

    sem_init(&mutex_for_buffer, 0, 1);
    sem_init(&starting_reader, 0, 0);
    sem_init(&reader_ending, 0, 1);
    sem_init(&for_reader, 0, 0);

    for(;;) {
        read_length = read_message(socket_fd, &client_address, &data, sizeof(data), 0, src_char);
        char* client_ip = inet_ntoa(client_address.sin_addr);
        size_t new_session_id = be64toh(data.session_id);
        // Ignoruję paczki otrzymywane z innego adresu IP niż wskazany.
        if (strcmp(client_ip, src_char) == 0) {
            if (new_session_id >= session_id) {
                if (new_session_id > session_id) {
                    if (session_id > 0) {
                        wait_for_reader_thread();
                    }
                    session_id = new_session_id;
                    PSIZE = read_length - 16;
                    if (PSIZE > BSIZE) {
                        std::cerr << "PSIZE cannot be greater than BSIZE!\n";
                        continue;
                    }
                    what_is_in_cells.clear();
                    memset(buffer, 0, BSIZE);
                    reader_allowed_to_start = false;
                    BYTE0 = be64toh(data.first_byte_num);
                    index_for_reader = BYTE0;
                    max_fbn = BYTE0;

                    BSIZE_div_PSIZE = BSIZE / PSIZE;
                    for (int64_t i = 0; i < BSIZE_div_PSIZE; ++i) {
                        what_is_in_cells.push_back(std::make_pair(0, 0));
                    }
                    std::thread t{reader_thread_function};
                    reader_thread = std::move(t);

                    size_t cell_no = (max_fbn / PSIZE) % BSIZE_div_PSIZE;
                    what_is_in_cells[cell_no].first = max_fbn;
                    what_is_in_cells[cell_no].second = 1;

                    size_t byte_no = cell_no * PSIZE;
                    //std::cerr << "Bede wkladac. Cell no: " << cell_no << ", byte no: " << byte_no << "\n";
                    memcpy(buffer + byte_no, data.audio_data, PSIZE);

                    if (max_fbn >= BYTE0 + BSIZE * 3 / 4) {
                        reader_allowed_to_start = true;
                        sem_post(&starting_reader);
                    }
                }
                else {
                    if (PSIZE > BSIZE) {
                        std::cerr << "PSIZE cannot be greater than BSIZE!\n";
                        continue;
                    }

                    sem_wait(&mutex_for_buffer);
                    uint64_t new_fbn = be64toh(data.first_byte_num);
                    if (new_fbn > BYTE0) {
                        // Sprawdzamy, czy paczka nie jest za stara.
                        // Jeśli max_fbn < BSIZE_div_PSIZE * PSIZE, to nie ma sensu tego sprawdzać,
                        // bo paczka w takim wypadku na pewno nie jest za stara.
                        if (max_fbn >= (size_t)BSIZE_div_PSIZE * PSIZE) {
                            if (new_fbn <= max_fbn - BSIZE_div_PSIZE * PSIZE) {
                                sem_post(&mutex_for_buffer);
                                continue;
                            }
                        }
                        // Wiemy, że paczka nie jest za stara.
                        size_t cell_no = (new_fbn / PSIZE) % BSIZE_div_PSIZE;
                        what_is_in_cells[cell_no].first = new_fbn;
                        what_is_in_cells[cell_no].second = 1;

                        size_t byte_no = cell_no * PSIZE;
                        //std::cerr << "Bede wkladac. Cell no: " << cell_no << ", byte no: " << byte_no << "\n";
                        memcpy(buffer + byte_no, data.audio_data, PSIZE);

                        if (new_fbn > max_fbn) {
                            max_fbn = new_fbn;
                        }

                        // Mój indeks do cell_no
                        // Chcę przejrzeć wszystkie paczki odejmując, przerywając w momencie, kiedy indeks paczki będzie
                        // taki, jak indeks największej paczki
                        size_t temp_byte_no = new_fbn; // Tutaj była zmiana!!! (wcześniej: byte_no)
                        size_t max_fbn_cell_no = (max_fbn / PSIZE) % BSIZE_div_PSIZE;
                        size_t next = next_cell(cell_no);
                        while (next != max_fbn_cell_no) {
                            if (temp_byte_no < (size_t)PSIZE) {
                                break;
                            }
                            else {
                                temp_byte_no -= PSIZE;
                                if (what_is_in_cells[next].first != temp_byte_no) {
                                    what_is_in_cells[next].first = temp_byte_no;
                                    what_is_in_cells[next].second = 2;
                                    memset(buffer + temp_byte_no, 0, PSIZE);
                                }
                            }
                            next = next_cell(next);
                        }

                        if (next == max_fbn_cell_no) {
                            next = (next + 1) % BSIZE_div_PSIZE;
                        }
                        while (next != cell_no) {
                            if (what_is_in_cells[next].second == 2) {
                                std::cerr << "MISSING: BEFORE " << byte_no << " EXPECTED " << what_is_in_cells[next].first << "\n";
                            }
                            next = (next + 1) % BSIZE_div_PSIZE;
                        }

                        if (max_fbn >= BYTE0 + BSIZE * 3 / 4) {
                            if (!reader_allowed_to_start) {
                                reader_allowed_to_start = true;
                                sem_post(&starting_reader);
                            }
                        }

                    }
                    if (reader_waiting_for_data) {
                        reader_waiting_for_data = false;
                        sem_post(&for_reader);
                    }
                    sem_post(&mutex_for_buffer);
                }
            }
        }
    }

    sem_destroy(&mutex_for_buffer);
    sem_destroy(&starting_reader);
    sem_destroy(&reader_ending);
    sem_destroy(&for_reader);
    delete[] buffer;
    delete[] src_char;

    CHECK_ERRNO(close(socket_fd));

    exit(0);
}
