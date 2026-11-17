#include <netdb.h>
#include <pthread.h>
#include <signal.h>

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/time.h>

#include <dns/dns.h>
#include <log/log.h>
#include <message/addr-payload.h>
#include <message/message.h>
#include <message/version-payload.h>

bool QUIT = false;
const int MAX_MESSAGES = 25;

const char *SEED_NODE = "seed.peercoin-library.org";
const char *PEERCOIN_PORT = "9901";

typedef struct good_node {
    char ip_address[INET_ADDRSTRLEN];
    time_t last_contact;
    struct good_node *next;
} good_node_s;

pthread_mutex_t GOOD_NODES_MUTEX;
good_node_s *GOOD_NODES = NULL;

typedef struct node_ip_address {
    char ip_address[INET_ADDRSTRLEN];
    struct node_ip_address *next;
} node_ip_address_s;

node_ip_address_s *SEED_NODE_IP_ADDRESSES = NULL;

typedef struct node_connection {
    socketfd s;
    struct sockaddr_in addr;
    version_payload_s version_payload;
} node_connection_s;

void free_node_connection(node_connection_s conn) {
    if (conn.s > 0) {
        close(conn.s);
    }
    free_version_payload(conn.version_payload);
}

void write_version_message(socketfd s, struct sockaddr_in to, struct sockaddr_in from) {
    log_trace("Entering write_version_message()");

    uint32_t now = time(NULL);
    log_debug("now -> %u", now);
    char *addr;
    char *ip;
    addr = inet_ntoa(to.sin_addr);
    log_debug("to addr -> %s", addr);
    ip = address_to_ip(addr);
    net_addr_s addr_recv = new_net_addr(now, 1, ip, false);
    free(ip);

    addr = inet_ntoa(from.sin_addr);
    log_debug("from addr -> %s", addr);
    ip = address_to_ip(addr);
    net_addr_s addr_from = new_net_addr(now, 0, ip, false);
    free(ip);

    log_debug("making version_payload bytes");
    char *str = heap_string("coin-seeder");
    var_str_s user_agent = new_var_str(str);
    version_payload_s version_payload = new_version_payload(addr_recv, addr_from, user_agent);
    bytes_s bytes = serialize_version_payload(version_payload);
    free_version_payload(version_payload);

    log_debug("making new_message");
    message_s message = new_message("version", bytes);
    write_message(s, message);
    free_message(message);

    log_trace("Exiting write_version_message()");
}

parsed_version_payload_s read_version_message(socketfd s) {
    log_trace("Entering read_version_message()");

    parsed_message_s parsed_message = read_message(s);
    if(parsed_message.parsed_bytes <= 0) {
        log_error("Failed to read_message.");
        log_trace("Exiting read_version_message()");
        return (parsed_version_payload_s){.parsed_bytes=-1};
    }

    if(strcmp(parsed_message.message.command, "version") != 0) {
        log_error("Message command was not \"version\".");
        log_trace("Exiting read_version_message()");
        return (parsed_version_payload_s){.parsed_bytes=-1};
    }

    bytes_s payload = {
        .length=parsed_message.message.length,
        .buffer=parsed_message.message.payload,
    };

    log_trace("Exiting read_version_message()");
    return parse_version_payload(payload);
}

void write_verack_message(socketfd s) {
    log_trace("Entering write_verack_message()");

    bytes_s empty = {.length=0, .buffer=NULL};
    message_s message = new_message("verack", empty);
    write_message(s, message);
    free_message(message);

    log_trace("Exiting write_verack_message()");
}

void write_getaddr_message(socketfd s) {
    log_trace("Entering write_getaddr_message()");

    bytes_s empty = {.length=0, .buffer=NULL};
    message_s message = new_message("getaddr", empty);
    write_message(s, message);
    free_message(message);

    log_trace("Exiting write_getaddr_message()");
}

node_connection_s connect_to_node(const char *ip_str) {
    log_trace("Entering connect_to_node()");

    struct sockaddr_in dest;
    memset(&dest, 0, sizeof(dest));
    dest.sin_family = AF_INET;
    dest.sin_port = htons(atoi(PEERCOIN_PORT));
    inet_pton(AF_INET, ip_str, &dest.sin_addr);

    socketfd s = socket(AF_INET, SOCK_STREAM, 0);
    if (s == -1) {
        log_error("Could not create socket for seed node %s", ip_str);
        return (node_connection_s){.s=-1};
    }

    struct timeval timeout = {.tv_sec=5, .tv_usec=0};
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));

    int res = connect(s, (struct sockaddr *)&dest, sizeof(dest));
    if (res < 0) {
        log_error("Could not connect to node %s", ip_str);
        close(s);
        return (node_connection_s){.s=-1};
    }

    log_debug("Connected to seed node: %s", ip_str);

    struct sockaddr_in from;
    memset(&from, 0, sizeof(from));
    write_version_message(s, dest, from);

    parsed_version_payload_s parsed = read_version_message(s);
    if(parsed.parsed_bytes == -1) {
        log_error("Handshake failed with seed node %s", ip_str);
        close(s);
        return (node_connection_s){.s=-1};
    }

    write_verack_message(s);

    node_connection_s conn = {
        .s = s,
        .addr = dest,
        .version_payload = parsed.version_payload,
    };

    log_debug("Seed node %s reports height: %d", ip_str, conn.version_payload.start_height);

    log_trace("Exiting connect_to_node()");
    return conn;
}

void resolve_seed_nodes() {
    log_trace("Entering resolve_seed_nodes()");

    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    struct addrinfo *result;
    int error_number = getaddrinfo(SEED_NODE, NULL, &hints, &result);
    if (error_number != 0) {
        log_error("getaddrinfo() for %s: %s", SEED_NODE, gai_strerror(error_number));
        return;
    }

    for (struct addrinfo *info = result; info != NULL; info = info->ai_next) {
        node_ip_address_s *node_ip_address = malloc(sizeof(node_ip_address_s));
        inet_ntop(AF_INET, &((struct sockaddr_in *)info->ai_addr)->sin_addr, node_ip_address->ip_address, sizeof(node_ip_address->ip_address));
        node_ip_address->next = SEED_NODE_IP_ADDRESSES;
        SEED_NODE_IP_ADDRESSES = node_ip_address;
        log_info("Resolved seed node: %s", node_ip_address->ip_address);
    }

    freeaddrinfo(result);
    log_trace("Exiting resolve_seed_nodes()");
}

void process_seed_node_messages(node_connection_s *connection) {
    log_trace("Entering process_seed_node_messages()");

    socketfd s = connection->s;
    write_getaddr_message(s);

    for(int processed_messages = 0; processed_messages <= MAX_MESSAGES; processed_messages++) {
        parsed_message_s parsed = read_message(s);
        if (parsed.parsed_bytes <= 0) {
            log_warn("Seed node connection lost, moving on.");
            break;
        }

        if (strcmp(parsed.message.command, "ping") == 0)
        {
            log_debug("Got ping from seed node, responding with pong.");
            bytes_s pong_payload = {.length=8, .buffer=malloc(8)};
            memcpy(pong_payload.buffer, parsed.message.payload, 8);
            message_s pong = new_message("pong", pong_payload);
            write_message(s, pong);
            free_message(pong);
            free_message(parsed.message);
            continue;
        }
        else if (strcmp(parsed.message.command, "addr") != 0)
        {
            log_debug("Got a %s message from seed node, dropping.", parsed.message.command);
            free_message(parsed.message);
            continue;
        }
        else
        {
            log_debug("Got addr message from seed node.");
            bytes_s window = {.length=parsed.message.length, .buffer=parsed.message.payload};
            parsed_addr_payload_s parsed_addr = parse_addr_payload(window);
            log_debug("has %d addresses", parsed_addr.addr_payload.count.value);

            int seed_height = connection->version_payload.start_height;
            char seed_ip_str[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &connection->addr.sin_addr, seed_ip_str, sizeof(seed_ip_str));

            for (int i = 0; i < parsed_addr.addr_payload.count.value; i++) {
                net_addr_s net_addr = parsed_addr.addr_payload.addr_list[i];
                if (net_addr.port != 9901) {
                    continue;
                }

                char address[100];
                inet_ntop(AF_INET, &net_addr.ip[12], address, 100);
                if (strcmp(address, "127.0.0.1") == 0) {
                    continue;
                }
                if (strcmp(address, "0.0.0.0") == 0) {
                    continue;
                }
                if (strcmp(address, seed_ip_str) == 0) {
                    continue;
                }

                // Check if this node meets the height threshold
                log_debug("Checking node: %s...", address);
                node_connection_s check_conn = connect_to_node(address);
                if (check_conn.s <= 0) {
                    log_debug("Connection to node %s failed.", address);
                    continue;
                }

                if (check_conn.version_payload.start_height >= seed_height) {
                    log_debug("Node %s has height %d >= seed height %d. Adding to GOOD_NODES.",
                              address, check_conn.version_payload.start_height, seed_height);
                    good_node_s *n = malloc(sizeof(good_node_s));
                    strncpy(n->ip_address, address, INET_ADDRSTRLEN - 1);
                    n->last_contact = time(NULL);
                    n->next = NULL;

                    pthread_mutex_lock(&GOOD_NODES_MUTEX);
                    {
                        n->next = GOOD_NODES;
                        GOOD_NODES = n;
                    }
                    pthread_mutex_unlock(&GOOD_NODES_MUTEX);
                } else {
                    log_debug("Node %s has height %d < seed height %d. Rejecting.",
                              address, check_conn.version_payload.start_height, seed_height);
                }

                free_node_connection(check_conn);
            }

            free_addr_payload(parsed_addr.addr_payload);
            free_message(parsed.message);
            break;
        }
    }

    log_trace("Exiting process_seed_node_messages()");
}

void *seed_thread() {
    log_trace("Entering seed_thread()");

    while (!QUIT) {
        for (
            node_ip_address_s *node_ip_address = SEED_NODE_IP_ADDRESSES;
            node_ip_address != NULL;
            node_ip_address = node_ip_address->next
        ) {
            node_connection_s connection = connect_to_node(node_ip_address->ip_address);
            process_seed_node_messages(&connection);
            free_node_connection(connection);

            if (QUIT) {
                break;
            }
        }

        // Sleep for 10 minutes (600 seconds)
        log_debug("Sleeping seed_thread() for 10 minutes");
        for (int i = 0; i < 600; i++) {
            if (QUIT) {
                break;
            }
            sleep(1);
        }
        log_debug("Waking seed_thread()");
    }

    log_trace("Exiting seed_thread()");
    return NULL;
}

int get_good_ip_list(void *data, addr_t* addr, int max, int ipv4, int ipv6) {
    int i = 0;
    pthread_mutex_lock(&GOOD_NODES_MUTEX);
    {
        for (good_node_s *node = GOOD_NODES; node != NULL; node = node->next) {
            char *obuf = malloc(4);
            int ret_val = inet_pton(AF_INET, node->ip_address, obuf);
            if (ret_val != 1) {
                log_error("Unable to convert address '%s' to ip bytes.", node->ip_address);
                free(obuf);
                continue;
            }

            i++;
            if (i > max) {
                break;
            }

            addr_t a = {.v=AF_INET, .data=*obuf};
            addr[i-1] = a;
        }
    }
    pthread_mutex_unlock(&GOOD_NODES_MUTEX);

    return i-1;
}

void *dns_thread() {
    log_trace("Entering dns_thread()");

    dns_opt_t dns_opt = {
        .port=53,
        .datattl=60,
        .nsttl=40000,
        .host="dot-net-ns.peercoin-library.org",
        .ns="dot-not-seed.peercoin-library.org",
        .mbox="",
        .cb=get_good_ip_list,
        .nRequests=0,
    };

    dnsserver(&dns_opt);

    log_trace("Exiting dns_thread()");
    return NULL;
}

void handle_control_c(int _) {
    log_trace("Entering handle_control_c()");
    log_info("Shutting down");
    QUIT = true;
    log_trace("Exiting handle_control_c()");
}

int main (int argc, char *argv[])
{
    log_set_level(LOG_TRACE);

    struct sigaction act = {.sa_handler=handle_control_c};
    sigaction(SIGINT, &act, NULL);

    // Resolve seed nodes and connect
    resolve_seed_nodes();

    pthread_t seed, dns;

    log_info("Starting dns thread");
    pthread_create(&dns, NULL, &dns_thread, NULL);

    log_info("Starting seed thread");
    pthread_create(&seed, NULL, &seed_thread, NULL);

    void *_;
    pthread_join(seed, &_);
    log_info("Seed thread rejoined the main thread");

    // The dns thread doesn't have a clean way to stop the dns server, so we
    // cancel it after the other threads rejoin.
    pthread_cancel(dns);
    pthread_join(dns, &_);
    log_info("Dns thread rejoined the main thread");
}
