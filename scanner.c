
/*
 * @author Ammar Faizi <ammarfaizi2@gmail.com> https://www.facebook.com/ammarfaizi2
 * @license MIT
 * @version 0.0.2
 *
 * TCP port scanner.
 */

#include <errno.h>
#include <stdio.h>
#include <stdint.h>
#include <getopt.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <stdbool.h>
#include <stdbool.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>

#define SOCKET_ERROR_TRY      0
#define THREAD_WAIT_SLEEP     1
#define DEFAULT_THREAD_NUM    8
#define DEFAULT_SEND_TIMEOUT  5
#define DEFAULT_RECV_TIMEOUT  5
#define msg_log(LVL, ...) \
  if (verbose_level >= LVL) printf(__VA_ARGS__)

typedef struct {
  char *target_host;
  uint16_t num_thread;
} scanner_config;

typedef struct {
  pthread_t thread;
  char *target_host;
  uint16_t target_port;
  bool is_busy;
} thread_job;

const static struct option long_options[] = {
  {"help",         no_argument,       0,  0x1},
  {"verbose",      no_argument,       0,  'v'},
  {"host",         required_argument, 0,  'h'},
  {"thread",       required_argument, 0,  't'},
  {"recv-timeout", required_argument, 0,  'r'},
  {"send-timeout", required_argument, 0,  's'},
  {0, 0, 0, 0}
};

FILE *report_handle;
uint8_t verbose_level = 0;
int16_t recv_timeout  = DEFAULT_RECV_TIMEOUT;
int16_t send_timeout  = DEFAULT_SEND_TIMEOUT;
pthread_mutex_t lock_write_report = PTHREAD_MUTEX_INITIALIZER;

void usage(char *app);
void do_scan(scanner_config *config);
void *thread_handler(thread_job *job);
bool parse_argv(int argc, char *argv[], scanner_config *config);
uint16_t get_non_busy_thread(
  register thread_job *__restrict__ jobs,
  register uint16_t num_thread
);
static int socket_init();
static bool socket_connect(int net_fd,
  char *target_host, uint16_t target_port,
  int *out_errno);
static void write_report(char *report_data);
static size_t set_http_payload(char *buffer);


/**
 * @param int   argc
 * @param char* argv[]
 * @return int
 */
int main(int argc, char *argv[])
{
  scanner_config config;

  if (!parse_argv(argc, argv, &config)) {
    usage(argv[0]);
    return 1;
  }

  do_scan(&config);

  return 0;
}


/**
 * @param char *app
 * @return void
 */
void usage(char *app)
{
  printf("Usage: %s [options]\n", app);
  printf("  Options:\n");
  printf("    -t|--threads <num>\tNumber of threads (default: %d)\n",
    DEFAULT_THREAD_NUM);
  printf("    -h|--host <host>\tTarget host (IPv4)\n");
  printf("    -v|--verbose\tVerbose output (use more -v to increase verbose level)\n");
  printf("    -r|--recv-timeout\trecv(2) timeout (default: %d)\n", DEFAULT_RECV_TIMEOUT);
  printf("    -s|--send-timeout\tsend(2) timeout, this affects connect(2) too (default: %d)\n", DEFAULT_SEND_TIMEOUT);
}


/**
 * @param int            argc
 * @param char           *argv[]
 * @param scanner_config *config
 * @return bool
 */
bool parse_argv(int argc, char *argv[], scanner_config *config)
{
  if (argc == 1) {
    return 0;
  }

  int c;
  int opt_index = 0;

  memset(config, '\0', sizeof(scanner_config));

  while (1) {
    c = getopt_long(argc, argv, "t:h:r:s:v", long_options, &opt_index);

    if (c == -1) {
      break;
    }

    switch (c) {
      case 0x1:
        return false;
        break;

      case 'v':
        verbose_level++;
        break;

      case 'h':
        config->target_host = optarg;
        break;

      case 't':
        config->num_thread = (uint16_t)atoi(optarg);
        break;

      case 'r':
        recv_timeout = atoi(optarg);
        break;

      case 's':
        send_timeout = atoi(optarg);
        break;

      default:
        printf("\n");
        return false;
        break;
    }
  }

  if (config->target_host == NULL) {
    printf("Error: Target host cannot be empty!\n");
    return false;
  }

  if (config->num_thread == 0) {
    config->num_thread = DEFAULT_THREAD_NUM;
  }

  return true;
}


/**
 * @param scanner_config *config
 * @return void
 */
void do_scan(scanner_config *config)
{
  thread_job *jobs;
  struct stat dirst;
  char report_file[128];
  uint16_t free_thread, i;

  msg_log(2, "Allocating thread jobs for %d threads...\n", config->num_thread);

  jobs = (thread_job *)malloc(sizeof(thread_job) * (config->num_thread + 1));

  memset(jobs, '\0', sizeof(thread_job) * (config->num_thread + 1));

  if (stat("reports", &dirst) < 0) {
    if (
      (mkdir("reports", 0700) < 0) ||
      (stat("reports", &dirst) < 0)
    ) {
      perror("mkdir");
      printf("Cannot create directory ./reports\n");
      exit(1);
    }
  }

  if ((dirst.st_mode & S_IFMT) != S_IFDIR) {
    printf("Cannot create directory ./reports\n");
    exit(1);
  }

  sprintf(report_file, "reports/%s", config->target_host);
  if (stat(report_file, &dirst) < 0) {
    if (
      (mkdir(report_file, 0700) < 0) ||
      (stat(report_file, &dirst) < 0)
    ) {
      perror("mkdir");
      printf("Cannot create directory ./%s\n", report_file);
      exit(1);
    }
  }

  sprintf(report_file, "reports/%s/000_report.txt", config->target_host);
  report_handle = fopen(report_file, "w");

  for (i = 1; i < 65535; i++) {

    free_thread = (uint16_t)get_non_busy_thread(jobs, config->num_thread);

    jobs[free_thread].target_host = config->target_host;
    jobs[free_thread].target_port = i;
    jobs[free_thread].is_busy = true;

    pthread_create(&(jobs[free_thread].thread), NULL,
      (void * (*)(void *))thread_handler, &(jobs[free_thread]));

    pthread_detach(jobs[free_thread].thread);
  }

  bool has_busy_thread = false;
  do {
    for (i = 0; i < config->num_thread; i++) {
      if (jobs[i].is_busy) {
        has_busy_thread = true;
        break;
      }
    }
    msg_log(1, "Waiting for the last jobs...\n");
    sleep(THREAD_WAIT_SLEEP);
  } while (has_busy_thread);


  free(jobs);
  fclose(report_handle);
}


/**
 * @param register thread_job *__restrict__ jobs
 * @param register uint16_t   num_thread
 * @return uint16_t
 */
uint16_t get_non_busy_thread(
  register thread_job *__restrict__ jobs,
  register uint16_t num_thread
)
{
  register uint16_t i;
  register uint32_t counter;

  counter = 0;

  check_threads:
  for (i = 0; i < num_thread; i++) {
    if (!jobs[i].is_busy) {
      return i;
    }
  }
  counter++;

  if (counter % 5 == 0) {
    msg_log(3, "(%d) All threads all busy...\n", counter);
  }
  sleep(THREAD_WAIT_SLEEP);
  goto check_threads;
}


/**
 * @param char *report_data
 * @return void
 */
static void write_report(char *report_data)
{
  pthread_mutex_lock(&lock_write_report);
  fprintf(report_handle, "%s\n", report_data);
  fflush(report_handle);
  pthread_mutex_unlock(&lock_write_report);
}


/**
 * @param char *buffer
 * @return size_t
 */
static size_t set_http_payload(char *buffer)
{
  #define HTTP_PAYLOAD \
    "GET / HTTP/1.1\r\n" \
    "Host: example.com\r\n" \
    "Accept: */*\r\n\r\n"

  memcpy(buffer, HTTP_PAYLOAD, sizeof(HTTP_PAYLOAD) - 1);

  return sizeof(HTTP_PAYLOAD) - 1;

  #undef HTTP_PAYLOAD
}


/**
 * @param thread_job *job
 * @return void *
 */
void *thread_handler(thread_job *job)
{
  int net_fd;
  int ret_val;
  int out_errno;
  bool is_error;
  bool is_port_open;
  uint8_t try_count;
  size_t sock_buflen;
  char sock_buffer[1024];
  char _report_data[1024];
  char *report_data = &(_report_data[0]);

  try_count = 0;

thread_try:

  report_data += 
    sprintf(report_data, "%05d|%s:%d", job->target_port,
      job->target_host, job->target_port);

  try_count++;
  is_error = false;
  is_port_open = false;


  msg_log(2, "Initializing TCP socket...\n");
  net_fd = socket_init();
  if (net_fd < 0) {
    report_data += sprintf(report_data, "|socket_init:failed");
    goto ret;
  }

  if (socket_connect(net_fd, job->target_host, job->target_port, &out_errno)) {

    report_data += sprintf(report_data, "|connect_ok");
    msg_log(3, "Connect OK\n");

    sock_buflen = set_http_payload(sock_buffer);
    ret_val = send(net_fd, sock_buffer, sock_buflen, 0);
    report_data += sprintf(report_data, "|send:%d", ret_val);
    if (ret_val < 0) {
      goto close_ret;
    }

    ret_val = recv(net_fd, sock_buffer, 1024, 0);
    report_data += sprintf(report_data, "|recv:%d", ret_val);
    printf("recv_buffer: \"%s\"\n", sock_buffer);
  } else {

    report_data += sprintf(report_data, "|errno:%d", out_errno);

    switch (out_errno) {
      /*
       * The port may not be DROPPED by the firewall.
       */
      case ECONNREFUSED: /* Connection refused. */
        msg_log(3, "ECONNREFUSED\n");
        report_data += sprintf(report_data, "|may_not_be_firewalled|ECONNREFUSED");
        is_port_open = true;
        break;

      /*
       * The port may be DROPPED by the firewall.
       */
      case EINPROGRESS:
        report_data += sprintf(report_data, "|firewall_det|EINPROGRESS");
        msg_log(3, "ETIMEDOUT\n");
        break;
      case ETIMEDOUT: /* Connection timedout. */
        report_data += sprintf(report_data, "|firewall_det|ETIMEDOUT");
        msg_log(3, "ETIMEDOUT\n");
        break;

      /*
       * Error client.
       */
      case ENETUNREACH: /* Network unreachable. */
        report_data += sprintf(report_data, "|ENETUNREACH");
        msg_log(3, "ENETUNREACH\n");
        is_error = true;
        break;
      case EINTR: /* Interrupted. */
        report_data += sprintf(report_data, "|EINTR");
        msg_log(3, "EINTR\n");
        is_error = true;
        break;
      case EFAULT: /* Fault. */
        report_data += sprintf(report_data, "|EFAULT");
        msg_log(3, "EFAULT\n");
        is_error = true;
        break;
      case EBADF: /* Invalid sockfd. */
        report_data += sprintf(report_data, "|EBADF");
        msg_log(3, "EBADF\n");
        is_error = true;
        break;
      case ENOTSOCK: /* sockfd is not a socket file descriptor. */
        report_data += sprintf(report_data, "|ENOTSOCK");
        msg_log(3, "ENOTSOCK\n");
        is_error = true;
        break;
      case EPROTOTYPE: /* Socket does not support the protocol. */
        report_data += sprintf(report_data, "|EPROTOTYPE");
        msg_log(3, "EPROTOTYPE\n");
        is_error = true;
        break;
      default:
        report_data += sprintf(report_data, "|unknown_error");
        msg_log(3, "default ERR\n");
        is_error = true;
        break;
    }
  }

close_ret:
  
  if (net_fd > -1) {
    close(net_fd);
  }

ret:

  if (is_error && (try_count <= SOCKET_ERROR_TRY)) {
    msg_log(1, "Retrying... (%d)\n", try_count);
    goto thread_try;
  }

  write_report(_report_data);

  /* Clean up all job. */
  memset(job, '\0', sizeof(thread_job));

  return NULL;
}


/**
 * @return int
 */
static int socket_init()
{
  int net_fd;
  struct timeval timeout;

  net_fd = socket(AF_INET, SOCK_STREAM, 0);
  if (net_fd < 0) {
    perror("socket");
    goto ret;
  }

  timeout.tv_sec = recv_timeout;
  timeout.tv_usec = 0;
  if (setsockopt(net_fd, SOL_SOCKET, SO_RCVTIMEO,
        (char *)&timeout, sizeof(timeout)) < 0
  ) {
    perror("setsockopt");
    goto close_ret;
  }

  timeout.tv_sec = send_timeout;
  timeout.tv_usec = 0;
  if (setsockopt(net_fd, SOL_SOCKET, SO_SNDTIMEO,
        (char *)&timeout, sizeof(timeout)) < 0
  ) {
    perror("setsockopt");
    goto close_ret;
  }


  goto ret;

close_ret:
  if (net_fd > -1) {
    close(net_fd);
    net_fd = -1;
  }
ret:
  return net_fd;
}


/**
 * @param int      net_fd
 * @param char     *target_host
 * @param uint16_t target_port
 * @param int      *out_errno
 * @return bool
 */
static bool socket_connect(int net_fd,
  char *target_host, uint16_t target_port,
  int *out_errno)
{
  struct sockaddr_in server_addr;

  bzero(&server_addr, sizeof(server_addr));
  server_addr.sin_family = AF_INET;
  server_addr.sin_port = htons(target_port);
  server_addr.sin_addr.s_addr = inet_addr(target_host);

  msg_log(1, "Connecting to %s:%d...\n", target_host, target_port);
  if (connect(net_fd, (struct sockaddr *)&(server_addr),
    sizeof(struct sockaddr_in)) < 0) {
    *out_errno = errno;
    perror("connect");
    return false;
  }
  msg_log(1, "Connection established %s:%d\n", target_host, target_port);

  return true;
}
