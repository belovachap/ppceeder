#include <netdb.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <strings.h>

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

volatile bool QUIT = false;
const int MAX_MESSAGES = 20;

const char *SEED_NODE = "seed.peercoin-library.org";
const char *PEERCOIN_PORT = "9901";

dns_opt_t DNS_OPT;
typedef struct good_node {
    char ip_address[INET_ADDRSTRLEN];
    time_t last_contact;
    struct good_node *next;
} good_node_s;

pthread_mutex_t GOOD_NODES_MUTEX = PTHREAD_MUTEX_INITIALIZER;
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
    char addr[INET_ADDRSTRLEN];
    char ip[16];
    inet_ntop(AF_INET, &to.sin_addr, addr, sizeof(addr));
    log_debug("to addr -> %s", addr);
    if (address_to_ip(addr, ip) != 0) {
        log_error("Failed to convert to address to ip bytes.");
        log_trace("Exiting write_version_message()");
        return;
    }
    net_addr_s addr_recv = new_net_addr(now, 1, ip, 0);

    inet_ntop(AF_INET, &from.sin_addr, addr, sizeof(addr));
    log_debug("from addr -> %s", addr);
    if (address_to_ip(addr, ip) != 0) {
        log_error("Failed to convert from address to ip bytes.");
        log_trace("Exiting write_version_message()");
        return;
    }
    net_addr_s addr_from = new_net_addr(now, 0, ip, 0);

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
        free_message(parsed_message.message);
        log_trace("Exiting read_version_message()");
        return (parsed_version_payload_s){.parsed_bytes=-1};
    }

    bytes_s payload = {
        .length=parsed_message.message.length,
        .buffer=parsed_message.message.payload,
    };

    parsed_version_payload_s result = parse_version_payload(payload);
    free_message(parsed_message.message);

    log_trace("Exiting read_version_message()");
    return result;
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
    dest.sin_port = htons((uint16_t)atoi(PEERCOIN_PORT));
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
        log_debug("Could not connect to node %s", ip_str);
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

void add_or_update_good_node(const char *ip_address) {
    pthread_mutex_lock(&GOOD_NODES_MUTEX);
    {
        for (good_node_s *node = GOOD_NODES; node != NULL; node = node->next) {
            if (strcmp(node->ip_address, ip_address) == 0) {
                node->last_contact = time(NULL);
                pthread_mutex_unlock(&GOOD_NODES_MUTEX);
                return;
            }
        }
        good_node_s *n = malloc(sizeof(good_node_s));
        strncpy(n->ip_address, ip_address, INET_ADDRSTRLEN - 1);
        n->last_contact = time(NULL);
        n->next = GOOD_NODES;
        GOOD_NODES = n;
    }
    pthread_mutex_unlock(&GOOD_NODES_MUTEX);
}

node_ip_address_s *process_seed_node_messages(node_connection_s *connection) {
    log_trace("Entering process_seed_node_messages()");

    node_ip_address_s *result = NULL;
    socketfd s = connection->s;
    write_getaddr_message(s);

    for (int processed_messages = 0; processed_messages < MAX_MESSAGES; processed_messages++) {
        parsed_message_s parsed = read_message(s);
        if (parsed.parsed_bytes <= 0) {
            log_warn("Seed node connection lost, moving on.");
            break;
        }

        if (strcmp(parsed.message.command, "addr") != 0) {
            log_debug("Got a %s message from seed node, dropping.", parsed.message.command);
            free_message(parsed.message);
            continue;
        } else {
            close(s);
            connection->s = -1;

            log_debug("Got addr message from seed node.");
            bytes_s window = {.length=parsed.message.length, .buffer=parsed.message.payload};
            parsed_addr_payload_s parsed_addr = parse_addr_payload(window);
            log_debug("has %d addresses", parsed_addr.addr_payload.count.value);

            char seed_ip_str[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &connection->addr.sin_addr, seed_ip_str, sizeof(seed_ip_str));

            for (int i = 0; i < parsed_addr.addr_payload.count.value; i++) {
                if (QUIT) {
                    break;
                }
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

                node_ip_address_s *node_ip_address = malloc(sizeof(node_ip_address_s));
                strncpy(node_ip_address->ip_address, address, INET_ADDRSTRLEN - 1);
                node_ip_address->next = result;
                result = node_ip_address;
            }

            free_addr_payload(parsed_addr.addr_payload);
            free_message(parsed.message);
            break;
        }
    }

    log_trace("Exiting process_seed_node_messages()");
    return result;
}

void *seed_thread() {
    log_trace("Entering seed_thread()");

    while (!QUIT) {
        log_debug("seed_thread() starting while loop...");

        for (
            node_ip_address_s *node_ip_address = SEED_NODE_IP_ADDRESSES;
            node_ip_address != NULL;
            node_ip_address = node_ip_address->next
        ) {
            if (QUIT) {
                break;
            }
            node_connection_s connection = connect_to_node(node_ip_address->ip_address);
            if (connection.s <= 0) {
                log_error("Could not connect to seed node %s", node_ip_address->ip_address);
                continue;
            }

            int seed_height = connection.version_payload.start_height;
            node_ip_address_s *discovered = process_seed_node_messages(&connection);
            free_node_connection(connection);

            check_nodes(discovered, seed_height);
            free_node_ip_address_list(discovered);
        }

        log_debug("seed_thread() taking a 10 minute break...");
        for (int i = 0; i < 600; i++) {
            if (QUIT) {
                break;
            }
            sleep(1);
        }
    }

    log_trace("Exiting seed_thread()");
    return NULL;
}
    log_trace("Entering process_seed_node_messages()");

    socketfd s = connection->s;
    write_getaddr_message(s);

    for(int processed_messages = 0; processed_messages < MAX_MESSAGES; processed_messages++) {
        parsed_message_s parsed = read_message(s);
        if (parsed.parsed_bytes <= 0) {
            log_warn("Seed node connection lost, moving on.");
            break;
        }

        if (strcmp(parsed.message.command, "addr") != 0)
        {
            log_debug("Got a %s message from seed node, dropping.", parsed.message.command);
            free_message(parsed.message);
            continue;
        }
        else
        {
            // Close the connection to the seed node since we might take a while to process the addresses it sent.
            close(s);
            connection->s = -1;

            // Proceed with processing addresses.
            log_debug("Got addr message from seed node.");
            bytes_s window = {.length=parsed.message.length, .buffer=parsed.message.payload};
            parsed_addr_payload_s parsed_addr = parse_addr_payload(window);
            log_debug("has %d addresses", parsed_addr.addr_payload.count.value);

            int seed_height = connection->version_payload.start_height;
            char seed_ip_str[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &connection->addr.sin_addr, seed_ip_str, sizeof(seed_ip_str));

            for (int i = 0; i < parsed_addr.addr_payload.count.value; i++) {
                if (QUIT) {
                    break;
                }
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
                    add_or_update_good_node(address);
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
        log_debug("seed_thread() starting while loop...");

        for (
            node_ip_address_s *node_ip_address = SEED_NODE_IP_ADDRESSES;
            node_ip_address != NULL;
            node_ip_address = node_ip_address->next
        ) {
            if (QUIT) {
                break;
            }
            node_connection_s connection = connect_to_node(node_ip_address->ip_address);
            if (connection.s <= 0) {
                log_error("Could not connect to seed node %s", node_ip_address->ip_address);
                continue;
            }
            process_seed_node_messages(&connection);
            free_node_connection(connection);
        }

        log_debug("seed_thread() taking a 10 minute break...");
        for(int i = 0; i < 600; i++) {
            if (QUIT) {
                break;
            }
            sleep(1);
        }
    }

    log_trace("Exiting seed_thread()");
    return NULL;
}

int get_good_ip_list(void *data, addr_t* addr, int max, int ipv4, int ipv6) {
    int i = 0;
    pthread_mutex_lock(&GOOD_NODES_MUTEX);
    {
        for (good_node_s *node = GOOD_NODES; node != NULL; node = node->next) {
            if (i >= max) break;
            int ret_val = inet_pton(AF_INET, node->ip_address, addr[i].data.v4);
            if (ret_val != 1) {
                log_error("Unable to convert address '%s' to ip bytes.", node->ip_address);
                continue;
            }
            addr[i].v = AF_INET;
            i++;
        }
    }
    pthread_mutex_unlock(&GOOD_NODES_MUTEX);

    return i;
}

void *dns_thread() {
    log_trace("Entering dns_thread()");

    DNS_OPT = (dns_opt_t){
        .port=53,
        .datattl=60,
        .nsttl=40000,
        .host="dot-net-ns.peercoin-library.org",
        .ns="dot-not-seed.peercoin-library.org",
        .mbox="",
        .cb=get_good_ip_list,
        .nRequests=0,
    };

    dnsserver(&DNS_OPT);

    log_trace("Exiting dns_thread()");
    return NULL;
}

void *stats_thread() {
    log_trace("Entering stats_thread()");

    while (!QUIT) {
        int count = 0;
        pthread_mutex_lock(&GOOD_NODES_MUTEX);
        for (good_node_s *node = GOOD_NODES; node != NULL; node = node->next) {
            count++;
        }
        pthread_mutex_unlock(&GOOD_NODES_MUTEX);
        log_info("Stats: %d good nodes, %lu dns queries handled",
                 count, (unsigned long)DNS_OPT.nRequests);
        for (int i = 0; i < 60; i++) {
            if (QUIT) break;
            sleep(1);
        }
    }

    log_trace("Exiting stats_thread()");
    return NULL;
}

void *evict_thread() {
    log_trace("Entering evict_thread()");

    while (!QUIT) {
        for (int i = 0; i < 600; i++) {
            if (QUIT) break;
            sleep(1);
        }
        if (QUIT) break;

        time_t cutoff = time(NULL) - (24 * 60 * 60);
        int evicted = 0;

        pthread_mutex_lock(&GOOD_NODES_MUTEX);
        {
            good_node_s **pp = &GOOD_NODES;
            while (*pp != NULL) {
                if ((*pp)->last_contact <= cutoff) {
                    good_node_s *to_free = *pp;
                    *pp = to_free->next;
                    log_debug("Evicting good node %s (last_contact=%ld)", to_free->ip_address, (long)to_free->last_contact);
                    free(to_free);
                    evicted++;
                } else {
                    pp = &(*pp)->next;
                }
            }
        }
        pthread_mutex_unlock(&GOOD_NODES_MUTEX);

        if (evicted > 0) {
            log_info("Evicted %d stale node(s) from GOOD_NODES.", evicted);
        }
    }

    log_trace("Exiting evict_thread()");
    return NULL;
}

void handle_control_c(int _) {
    log_trace("Entering handle_control_c()");
    log_info("Shutting down");
    QUIT = true;
    log_trace("Exiting handle_control_c()");
}

static int parse_log_level(const char *level_str) {
    if (strcasecmp(level_str, "trace") == 0) return LOG_TRACE;
    if (strcasecmp(level_str, "debug") == 0) return LOG_DEBUG;
    if (strcasecmp(level_str, "info") == 0)  return LOG_INFO;
    if (strcasecmp(level_str, "warn") == 0)  return LOG_WARN;
    if (strcasecmp(level_str, "error") == 0) return LOG_ERROR;
    if (strcasecmp(level_str, "fatal") == 0) return LOG_FATAL;
    return -1;
}

static void print_usage(const char *prog) {
    fprintf(stderr, "Usage: %s [-l <level>]\n", prog);
    fprintf(stderr, "  -l <level>  Set log level: trace, debug, info, warn, error, fatal (default: trace)\n");
    fprintf(stderr, "  -h          Show this help message\n");
}

int main (int argc, char *argv[])
{
    int log_level = LOG_TRACE;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            print_usage(argv[0]);
            return 0;
        }
        else if (strcmp(argv[i], "-l") == 0 && i + 1 < argc) {
            i++;
            int level = parse_log_level(argv[i]);
            if (level < 0) {
                fprintf(stderr, "Invalid log level: %s\n", argv[i]);
                print_usage(argv[0]);
                return 1;
            }
            log_level = level;
        }
        else {
            fprintf(stderr, "Unknown argument: %s\n", argv[i]);
            print_usage(argv[0]);
            return 1;
        }
    }

    log_set_level(log_level);

    struct sigaction act = {.sa_handler=handle_control_c};
    sigaction(SIGINT, &act, NULL);

    // Resolve seed nodes and connect
    resolve_seed_nodes();

    pthread_t seed, dns, stats, evict;

    log_info("Starting dns thread");
    pthread_create(&dns, NULL, &dns_thread, NULL);

    log_info("Starting seed thread");
    pthread_create(&seed, NULL, &seed_thread, NULL);

    log_info("Starting stats thread");
    pthread_create(&stats, NULL, &stats_thread, NULL);

    log_info("Starting evict thread");
    pthread_create(&evict, NULL, &evict_thread, NULL);

    void *_;
    pthread_join(seed, &_);
    log_info("Seed thread rejoined the main thread");

    pthread_join(stats, &_);
    log_info("Stats thread rejoined the main thread");

    pthread_join(evict, &_);
    log_info("Evict thread rejoined the main thread");

    // The dns thread doesn't have a clean way to stop the dns server, so we
    // cancel it after the other threads rejoin.
    pthread_cancel(dns);
    pthread_join(dns, &_);
    log_info("Dns thread rejoined the main thread");
}

void free_node_ip_address_list(node_ip_address_s *list) {
    while (list != NULL) {
        node_ip_address_s *next = list->next;
        free(list);
        list = next;
    }
}

void check_nodes(node_ip_address_s *node_list, int seed_height) {
    log_trace("Entering check_nodes()");

    for (node_ip_address_s *node_ip_address = node_list; node_ip_address != NULL; node_ip_address = node_ip_address->next) {
        if (QUIT) {
            break;
        }
        const char *address = node_ip_address->ip_address;

        log_debug("Checking node: %s...", address);
        node_connection_s check_conn = connect_to_node(address);
        if (check_conn.s <= 0) {
            log_debug("Connection to node %s failed.", address);
            continue;
        }

        if (check_conn.version_payload.start_height >= seed_height) {
            log_debug("Node %s has height %d >= seed height %d. Adding to GOOD_NODES.",
                      address, check_conn.version_payload.start_height, seed_height);
            add_or_update_good_node(address);
        } else {
            log_debug("Node %s has height %d < seed height %d. Rejecting.",
                      address, check_conn.version_payload.start_height, seed_height);
        }

        free_node_connection(check_conn);
    }

    log_trace("Exiting check_nodes()");
}

