/**
 * RustScan Clone - Fast Port Scanner in C (Final Version)
 * Compiled with: gcc -O3 -pthread -o rustscan rustscan_final.c
 * Usage: ./rustscan -a 192.168.1.1 -p 1-1000 -o results.txt
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <fcntl.h>
#include <errno.h>
#include <netdb.h>
#include <signal.h>
#include <time.h>

#define MAX_PORTS 65535
#define MAX_THREADS 2000
#define BUFFER_SIZE 1024
#define DEFAULT_TIMEOUT_MS 1000
#define DEFAULT_BATCH_SIZE 1000
#define MAX_TARGETS 1024

/* ANSI Color Codes */
#define COLOR_RESET   "\033[0m"
#define COLOR_RED     "\033[31m"
#define COLOR_GREEN   "\033[32m"
#define COLOR_YELLOW  "\033[33m"
#define COLOR_BLUE    "\033[34m"
#define COLOR_MAGENTA "\033[35m"
#define COLOR_CYAN    "\033[36m"
#define COLOR_WHITE   "\033[37m"
#define COLOR_BOLD    "\033[1m"

/* Structures */
typedef struct {
    char ip[16];
    int port;
    int timeout_ms;
    int is_open;
} ScanTask;

typedef struct {
    int *ports;
    int count;
    int capacity;
} PortList;

typedef struct {
    char *targets;
    int *ports;
    int port_count;
    int timeout_ms;
    int threads;
    int nmap_mode;
    char *script;
    char *output_file;
    int batch_size;
    int verbose;
} Config;

/* Global variables */
pthread_mutex_t print_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t port_mutex = PTHREAD_MUTEX_INITIALIZER;
PortList open_ports;
int total_scanned = 0;
int active_threads = 0;
int scan_cancelled = 0;

/* Function prototypes */
void print_banner();
void parse_arguments(int argc, char *argv[], Config *config);
void parse_port_range(const char *port_str, int **ports, int *port_count);
void expand_single_range(int start, int end, int **ports, int *count);
int is_valid_ip(const char *ip);
char** resolve_domain(const char *domain, int *count);
void expand_cidr(const char *cidr, char ***targets, int *count);
int tcp_connect_scan(const char *ip, int port, int timeout_ms);
void* scan_worker(void *arg);
void run_batch_scan(Config *config, const char *ip);
void run_nmap(const char *ip, PortList *ports);
void run_script(const char *script, const char *ip, PortList *ports);
void add_port(PortList *list, int port);
void init_port_list(PortList *list);
void free_port_list(PortList *list);
void save_results_to_file(const char *filename, const char *ip, PortList *ports);
const char* get_service_name(int port);
void print_colored(const char *color, const char *text);
void print_colored_int(const char *color, int value);
void signal_handler(int sig);

/* Signal handler */
void signal_handler(int sig) {
    printf("\n\n\033[33m[!] Scan cancelled by user\033[0m\n");
    scan_cancelled = 1;
}

/* Print colored text */
void print_colored(const char *color, const char *text) {
    printf("%s%s\033[0m", color, text);
}

/* Print colored integer */
void print_colored_int(const char *color, int value) {
    printf("%s%d\033[0m", color, value);
}

/* Print banner */
void print_banner() {
    printf("\n\033[36m");
    printf("╔══════════════════════════════════════════════════════════════════╗\n");
    printf("║                    \033[32mRustScan Clone in C\033[36m                    ║\n");
    printf("║                    \033[33mFast Port Scanner\033[36m                            ║\n");
    printf("╚══════════════════════════════════════════════════════════════════╝\n");
    printf("\033[0m\n");
}

/* Get service name */
const char* get_service_name(int port) {
    switch(port) {
        case 21: return "FTP";
        case 22: return "SSH";
        case 23: return "Telnet";
        case 25: return "SMTP";
        case 53: return "DNS";
        case 80: return "HTTP";
        case 110: return "POP3";
        case 111: return "RPC";
        case 135: return "RPC";
        case 139: return "NetBIOS";
        case 143: return "IMAP";
        case 443: return "HTTPS";
        case 445: return "SMB";
        case 993: return "IMAPS";
        case 995: return "POP3S";
        case 1433: return "MSSQL";
        case 3306: return "MySQL";
        case 3389: return "RDP";
        case 5432: return "PostgreSQL";
        case 5900: return "VNC";
        case 6379: return "Redis";
        case 8080: return "HTTP-Proxy";
        case 8443: return "HTTPS-Alt";
        case 27017: return "MongoDB";
        default: return "unknown";
    }
}

/* TCP Connect Scan */
int tcp_connect_scan(const char *ip, int port, int timeout_ms) {
    int sock;
    struct sockaddr_in target;
    fd_set fdset;
    struct timeval tv;
    int flags;
    int so_error;
    socklen_t len;
    
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return 0;
    
    flags = fcntl(sock, F_GETFL, 0);
    if (flags == -1) { close(sock); return 0; }
    
    if (fcntl(sock, F_SETFL, flags | O_NONBLOCK) == -1) { close(sock); return 0; }
    
    memset(&target, 0, sizeof(target));
    target.sin_family = AF_INET;
    target.sin_port = htons(port);
    
    if (inet_pton(AF_INET, ip, &target.sin_addr) <= 0) { close(sock); return 0; }
    
    connect(sock, (struct sockaddr*)&target, sizeof(target));
    
    FD_ZERO(&fdset);
    FD_SET(sock, &fdset);
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    
    if (select(sock + 1, NULL, &fdset, NULL, &tv) > 0) {
        len = sizeof(so_error);
        getsockopt(sock, SOL_SOCKET, SO_ERROR, &so_error, &len);
        if (so_error == 0) {
            close(sock);
            return 1;
        }
    }
    
    close(sock);
    return 0;
}

/* Add port to list */
void add_port(PortList *list, int port) {
    pthread_mutex_lock(&port_mutex);
    
    if (list->count >= list->capacity) {
        list->capacity *= 2;
        list->ports = realloc(list->ports, list->capacity * sizeof(int));
        if (!list->ports) exit(1);
    }
    
    list->ports[list->count++] = port;
    pthread_mutex_unlock(&port_mutex);
}

/* Initialize port list */
void init_port_list(PortList *list) {
    list->capacity = 100;
    list->count = 0;
    list->ports = malloc(list->capacity * sizeof(int));
    if (!list->ports) exit(1);
}

/* Free port list */
void free_port_list(PortList *list) {
    if (list->ports) {
        free(list->ports);
        list->ports = NULL;
    }
    list->count = 0;
    list->capacity = 0;
}

/* Save results to file */
void save_results_to_file(const char *filename, const char *ip, PortList *ports) {
    if (!filename) return;
    
    FILE *fp = fopen(filename, "a");
    if (!fp) {
        fprintf(stderr, "Error: Cannot open file %s\n", filename);
        return;
    }
    
    time_t now = time(NULL);
    char *time_str = ctime(&now);
    time_str[strlen(time_str) - 1] = '\0';
    
    fprintf(fp, "[%s] %s: ", time_str, ip);
    for (int i = 0; i < ports->count; i++) {
        fprintf(fp, "%d", ports->ports[i]);
        if (i < ports->count - 1) fprintf(fp, ",");
    }
    fprintf(fp, "\n");
    fclose(fp);
    
    printf("\033[32m[+] Results saved to %s\033[0m\n", filename);
}

/* Worker thread */
void* scan_worker(void *arg) {
    ScanTask *task = (ScanTask*)arg;
    
    if (!scan_cancelled && tcp_connect_scan(task->ip, task->port, task->timeout_ms)) {
        task->is_open = 1;
        pthread_mutex_lock(&print_mutex);
        printf("\r\033[32m[+] Found open port: \033[33m%d\033[0m (IP: %s) [\033[36m%s\033[0m]\n", 
               task->port, task->ip, get_service_name(task->port));
        fflush(stdout);
        pthread_mutex_unlock(&print_mutex);
        add_port(&open_ports, task->port);
    }
    
    pthread_mutex_lock(&print_mutex);
    total_scanned++;
    if (total_scanned % 100 == 0) {
        printf("\r\033[36m[*] Scanned: %d ports\033[0m", total_scanned);
        fflush(stdout);
    }
    pthread_mutex_unlock(&print_mutex);
    
    free(task);
    active_threads--;
    return NULL;
}

/* Run batch scan */
void run_batch_scan(Config *config, const char *ip) {
    pthread_t threads[MAX_THREADS];
    int thread_count = 0;
    int port_idx;
    ScanTask *task;
    
    total_scanned = 0;
    scan_cancelled = 0;
    init_port_list(&open_ports);
    
    printf("\n\033[36m[*] Scanning %s (%d ports)...\033[0m\n", ip, config->port_count);
    
    for (port_idx = 0; port_idx < config->port_count && !scan_cancelled; port_idx++) {
        int port = config->ports[port_idx];
        
        while (active_threads >= config->threads && !scan_cancelled) {
            usleep(1000);
        }
        
        if (scan_cancelled) break;
        
        task = malloc(sizeof(ScanTask));
        if (!task) continue;
        
        strncpy(task->ip, ip, 15);
        task->ip[15] = '\0';
        task->port = port;
        task->timeout_ms = config->timeout_ms;
        task->is_open = 0;
        
        if (pthread_create(&threads[thread_count], NULL, scan_worker, task) != 0) {
            free(task);
            continue;
        }
        
        thread_count++;
        active_threads++;
        
        if (thread_count >= config->batch_size) {
            for (int i = 0; i < thread_count; i++) {
                pthread_join(threads[i], NULL);
            }
            thread_count = 0;
        }
    }
    
    for (int i = 0; i < thread_count; i++) {
        pthread_join(threads[i], NULL);
    }
    
    printf("\n\n");
    
    if (open_ports.count > 0) {
        printf("\033[36m");
        printf("╔══════════════════════════════════════════════════════════════════╗\n");
        printf("║                     \033[32mSCAN RESULTS\033[36m                     ║\n");
        printf("╠══════════════════════════════════════════════════════════════════╣\n");
        printf("║ IP Address: \033[33m%-55s\033[36m ║\n", ip);
        printf("║ Open ports: \033[32m%-55d\033[36m ║\n", open_ports.count);
        printf("╠══════════════════════════════════════════════════════════════════╣\n");
        printf("║ Ports: \033[0m");
        
        for (int i = 0; i < open_ports.count; i++) {
            if (i > 0 && i % 8 == 0) {
                printf("\n║         ");
            }
            if (open_ports.ports[i] == 80 || open_ports.ports[i] == 443 || 
                open_ports.ports[i] == 8080 || open_ports.ports[i] == 8443) {
                printf("\033[32m%d\033[0m", open_ports.ports[i]);
            } else if (open_ports.ports[i] == 22) {
                printf("\033[33m%d\033[0m", open_ports.ports[i]);
            } else if (open_ports.ports[i] == 21 || open_ports.ports[i] == 23) {
                printf("\033[31m%d\033[0m", open_ports.ports[i]);
            } else {
                printf("%d", open_ports.ports[i]);
            }
            if (i < open_ports.count - 1) printf(", ");
        }
        
        printf("\n\033[36m║ Services: \033[0m");
        for (int i = 0; i < open_ports.count; i++) {
            if (i > 0 && i % 3 == 0) {
                printf("\n║           ");
            }
            printf("%d(\033[36m%s\033[0m)", open_ports.ports[i], get_service_name(open_ports.ports[i]));
            if (i < open_ports.count - 1) printf(", ");
        }
        
        printf("\n\033[36m╚══════════════════════════════════════════════════════════════════╝\033[0m\n\n");
        
        /* Save to file if output file specified */
        if (config->output_file) {
            save_results_to_file(config->output_file, ip, &open_ports);
        }
        
        if (config->nmap_mode) {
            run_nmap(ip, &open_ports);
        }
        
        if (config->script) {
            run_script(config->script, ip, &open_ports);
        }
    } else {
        printf("\033[33m[-] No open ports found on %s\033[0m\n\n", ip);
    }
    
    free_port_list(&open_ports);
}

/* Run Nmap */
void run_nmap(const char *ip, PortList *ports) {
    char cmd[BUFFER_SIZE];
    char port_str[BUFFER_SIZE] = "";
    char temp[32];
    
    for (int i = 0; i < ports->count; i++) {
        sprintf(temp, "%d", ports->ports[i]);
        if (i > 0) strcat(port_str, ",");
        strcat(port_str, temp);
    }
    
    snprintf(cmd, sizeof(cmd), "nmap -sV -p %s %s", port_str, ip);
    printf("\033[36m[+] Running Nmap: %s\033[0m\n", cmd);
    system(cmd);
    printf("\n");
}

/* Run script */
void run_script(const char *script, const char *ip, PortList *ports) {
    char cmd[BUFFER_SIZE];
    char port_str[BUFFER_SIZE] = "";
    char temp[32];
    
    for (int i = 0; i < ports->count; i++) {
        sprintf(temp, "%d", ports->ports[i]);
        if (i > 0) strcat(port_str, ",");
        strcat(port_str, temp);
    }
    
    snprintf(cmd, sizeof(cmd), "%s %s %s", script, ip, port_str);
    printf("\033[36m[+] Running script: %s\033[0m\n", cmd);
    system(cmd);
    printf("\n");
}

/* Expand single range */
void expand_single_range(int start, int end, int **ports, int *count) {
    if (start < 1) start = 1;
    if (end > MAX_PORTS) end = MAX_PORTS;
    if (start > end) {
        int temp = start;
        start = end;
        end = temp;
    }
    
    *ports = malloc((end - start + 1) * sizeof(int));
    if (*ports) {
        for (int i = start; i <= end; i++) {
            (*ports)[i - start] = i;
        }
        *count = end - start + 1;
    } else {
        *count = 0;
    }
}

/* Parse port range */
void parse_port_range(const char *port_str, int **ports, int *port_count) {
    int *temp_ports = NULL;
    int temp_count = 0;
    int capacity = 1000;
    char *str = strdup(port_str);
    char *token;
    
    temp_ports = malloc(capacity * sizeof(int));
    if (!temp_ports) {
        *ports = NULL;
        *port_count = 0;
        free(str);
        return;
    }
    
    if (strchr(port_str, ',')) {
        token = strtok(str, ",");
        while (token != NULL && temp_count < MAX_PORTS) {
            if (strchr(token, '-')) {
                int start, end;
                if (sscanf(token, "%d-%d", &start, &end) == 2) {
                    if (start < 1) start = 1;
                    if (end > MAX_PORTS) end = MAX_PORTS;
                    for (int i = start; i <= end && temp_count < MAX_PORTS; i++) {
                        if (temp_count >= capacity) {
                            capacity *= 2;
                            temp_ports = realloc(temp_ports, capacity * sizeof(int));
                            if (!temp_ports) goto cleanup;
                        }
                        temp_ports[temp_count++] = i;
                    }
                }
            } else {
                int port = atoi(token);
                if (port >= 1 && port <= MAX_PORTS) {
                    if (temp_count >= capacity) {
                        capacity *= 2;
                        temp_ports = realloc(temp_ports, capacity * sizeof(int));
                        if (!temp_ports) goto cleanup;
                    }
                    temp_ports[temp_count++] = port;
                }
            }
            token = strtok(NULL, ",");
        }
    } else if (strchr(port_str, '-')) {
        int start, end;
        if (sscanf(port_str, "%d-%d", &start, &end) == 2) {
            expand_single_range(start, end, &temp_ports, &temp_count);
        } else {
            temp_ports[0] = atoi(port_str);
            temp_count = 1;
        }
    } else {
        temp_ports[0] = atoi(port_str);
        temp_count = 1;
    }
    
cleanup:
    free(str);
    
    if (temp_count > 0) {
        *ports = temp_ports;
        *port_count = temp_count;
    } else {
        free(temp_ports);
        *ports = NULL;
        *port_count = 0;
    }
}

/* Check valid IP */
int is_valid_ip(const char *ip) {
    struct sockaddr_in sa;
    return inet_pton(AF_INET, ip, &(sa.sin_addr)) != 0;
}

/* Resolve domain */
char** resolve_domain(const char *domain, int *count) {
    struct hostent *host;
    char **ips = NULL;
    int ip_count = 0;
    
    host = gethostbyname(domain);
    if (!host) {
        *count = 0;
        return NULL;
    }
    
    if (host->h_addrtype == AF_INET) {
        for (ip_count = 0; host->h_addr_list[ip_count] != NULL; ip_count++);
        
        ips = malloc(ip_count * sizeof(char*));
        if (!ips) {
            *count = 0;
            return NULL;
        }
        
        for (int i = 0; i < ip_count; i++) {
            ips[i] = malloc(16);
            struct in_addr addr;
            memcpy(&addr, host->h_addr_list[i], sizeof(addr));
            strcpy(ips[i], inet_ntoa(addr));
        }
        
        *count = ip_count;
        return ips;
    }
    
    *count = 0;
    return NULL;
}

/* Expand CIDR */
void expand_cidr(const char *cidr, char ***targets, int *count) {
    char ip_str[16];
    int prefix;
    unsigned int ip_start, ip_end, ip;
    struct in_addr addr;
    char **result = NULL;
    int result_count = 0;
    
    if (sscanf(cidr, "%15[^/]/%d", ip_str, &prefix) != 2) {
        *count = 0;
        return;
    }
    
    if (prefix < 0 || prefix > 32) {
        *count = 0;
        return;
    }
    
    if (inet_pton(AF_INET, ip_str, &addr) <= 0) {
        *count = 0;
        return;
    }
    
    ip_start = ntohl(addr.s_addr);
    ip_end = ip_start | (0xFFFFFFFF >> prefix);
    ip_start = ip_start & (0xFFFFFFFF << (32 - prefix));
    
    result_count = ip_end - ip_start - 1;
    if (result_count <= 0 || result_count > MAX_TARGETS) {
        *count = 0;
        return;
    }
    
    result = malloc(result_count * sizeof(char*));
    if (!result) {
        *count = 0;
        return;
    }
    
    int idx = 0;
    for (ip = ip_start + 1; ip < ip_end && idx < MAX_TARGETS; ip++) {
        addr.s_addr = htonl(ip);
        result[idx] = malloc(16);
        if (result[idx]) {
            strcpy(result[idx], inet_ntoa(addr));
            idx++;
        }
    }
    
    *targets = result;
    *count = idx;
}

/* Parse arguments */
void parse_arguments(int argc, char *argv[], Config *config) {
    int opt;
    
    config->ports = NULL;
    config->port_count = 0;
    config->timeout_ms = DEFAULT_TIMEOUT_MS;
    config->threads = 500;
    config->nmap_mode = 0;
    config->script = NULL;
    config->output_file = NULL;
    config->batch_size = DEFAULT_BATCH_SIZE;
    config->targets = NULL;
    config->verbose = 0;
    
    while ((opt = getopt(argc, argv, "a:p:t:T:ns:o:b:vh")) != -1) {
        switch (opt) {
            case 'a':
                config->targets = optarg;
                break;
            case 'p':
                parse_port_range(optarg, &config->ports, &config->port_count);
                break;
            case 't':
                config->timeout_ms = atoi(optarg);
                if (config->timeout_ms < 1) config->timeout_ms = 1;
                break;
            case 'T':
                config->threads = atoi(optarg);
                if (config->threads > MAX_THREADS) config->threads = MAX_THREADS;
                if (config->threads < 1) config->threads = 1;
                break;
            case 'n':
                config->nmap_mode = 1;
                break;
            case 's':
                config->script = optarg;
                break;
            case 'o':
                config->output_file = optarg;
                break;
            case 'b':
                config->batch_size = atoi(optarg);
                if (config->batch_size < 1) config->batch_size = 1;
                break;
            case 'v':
                config->verbose = 1;
                break;
            case 'h':
                printf("Usage: %s [options]\n", argv[0]);
                printf("\nOptions:\n");
                printf("  -a <target>    Target IP, CIDR, or domain (required)\n");
                printf("  -p <ports>     Port range/comma list (e.g., 1-1000, 80,443,8080)\n");
                printf("  -t <ms>        Timeout in milliseconds (default: 1000)\n");
                printf("  -T <threads>   Number of threads (default: 500, max: %d)\n", MAX_THREADS);
                printf("  -b <size>      Batch size (default: 1000)\n");
                printf("  -o <file>      Save results to file\n");
                printf("  -n             Pipe results to Nmap\n");
                printf("  -s <script>    Run script after scan\n");
                printf("  -v             Verbose output\n");
                printf("  -h             Show this help\n");
                printf("\nExamples:\n");
                printf("  %s -a 192.168.1.1 -p 1-1000\n", argv[0]);
                printf("  %s -a 192.168.1.0/24 -p 80,443,22 -o results.txt\n", argv[0]);
                printf("  %s -a google.com -p 1-10000 -t 500 -T 1000\n", argv[0]);
                printf("  %s -a 192.168.1.1 -p 1-1000 -n\n", argv[0]);
                exit(0);
        }
    }
    
    if (!config->targets) {
        fprintf(stderr, "Error: Target required (-a)\n");
        exit(1);
    }
    
    if (!config->ports) {
        expand_single_range(1, 1000, &config->ports, &config->port_count);
    }
}

/* Main function */
int main(int argc, char *argv[]) {
    Config config;
    char **targets = NULL;
    int target_count = 0;
    struct timeval start_time, end_time;
    double elapsed;
    
    signal(SIGINT, signal_handler);
    print_banner();
    parse_arguments(argc, argv, &config);
    
    printf("\033[36m[+] Configuration:\033[0m\n");
    printf("    Targets: \033[33m%s\033[0m\n", config.targets);
    printf("    Ports: \033[32m%d\033[0m ports to scan\n", config.port_count);
    printf("    Timeout: \033[33m%d\033[0m ms\n", config.timeout_ms);
    printf("    Threads: \033[33m%d\033[0m\n", config.threads);
    printf("    Batch size: \033[33m%d\033[0m\n", config.batch_size);
    if (config.output_file) printf("    Output file: \033[32m%s\033[0m\n", config.output_file);
    if (config.nmap_mode) printf("    Nmap mode: \033[32menabled\033[0m\n");
    if (config.script) printf("    Script: \033[36m%s\033[0m\n", config.script);
    printf("\n");
    
    gettimeofday(&start_time, NULL);
    
    if (strchr(config.targets, '/')) {
        expand_cidr(config.targets, &targets, &target_count);
        if (target_count > 0) {
            for (int i = 0; i < target_count && !scan_cancelled; i++) {
                run_batch_scan(&config, targets[i]);
                free(targets[i]);
            }
            free(targets);
        } else {
            fprintf(stderr, "Error: Invalid CIDR range\n");
            exit(1);
        }
    } else if (is_valid_ip(config.targets)) {
        run_batch_scan(&config, config.targets);
    } else {
        targets = resolve_domain(config.targets, &target_count);
        if (target_count > 0) {
            for (int i = 0; i < target_count && !scan_cancelled; i++) {
                printf("\033[32m[+] Resolved %s -> \033[36m%s\033[0m\n", config.targets, targets[i]);
                run_batch_scan(&config, targets[i]);
                free(targets[i]);
            }
            free(targets);
        } else {
            fprintf(stderr, "Error: Could not resolve %s\n", config.targets);
            exit(1);
        }
    }
    
    gettimeofday(&end_time, NULL);
    elapsed = (end_time.tv_sec - start_time.tv_sec) + 
              (end_time.tv_usec - start_time.tv_usec) / 1000000.0;
    
    printf("\n\033[32m[+] Scan completed in %.2f seconds\033[0m\n", elapsed);
    
    if (config.ports) free(config.ports);
    
    return 0;
}
