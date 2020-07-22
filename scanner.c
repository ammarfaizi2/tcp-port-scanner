
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
#include <sys/socket.h>

#define SOCKET_ERROR_TRY      3
#define THREAD_WAIT_SLEEP     1
#define DEFAULT_THREAD_NUM    1
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

uint8_t verbose_level = 0;
int16_t recv_timeout  = -1;
int16_t send_timeout  = -1;

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
  printf("    -s|--send-timeout\tsend(2) timeout (default: %d)\n", DEFAULT_SEND_TIMEOUT);
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
  uint16_t free_thread;

  msg_log(2, "Allocating thread jobs for %d threads...\n", config->num_thread);

  jobs = (thread_job *)malloc(sizeof(thread_job) * (config->num_thread + 1));

  memset(jobs, '\0', sizeof(thread_job) * (config->num_thread + 1));

  for (uint16_t i = 1; i < 65535; i++) {

    free_thread = (uint16_t)get_non_busy_thread(jobs, config->num_thread);

    jobs[free_thread].target_host = config->target_host;
    jobs[free_thread].target_port = i;
    jobs[free_thread].is_busy = true;

    pthread_create(&(jobs[free_thread].thread), NULL,
      (void * (*)(void *))thread_handler, &(jobs[free_thread]));

    pthread_detach(jobs[free_thread].thread);
  }


  free(jobs);
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
    printf("%d\n", jobs[i].is_busy);
    if (!jobs[i].is_busy) {
      return (int32_t)i;
    }
  }
  counter++;

  if (counter % 5 == 0) {
    msg_log(3, "(%d) All threads all busy...\n", counter);
    sleep(THREAD_WAIT_SLEEP); 
  }
  goto check_threads;
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


  try_count = 0;

thread_try:

  try_count++;
  is_error = false;
  is_port_open = false;


  msg_log(2, "Initializing TCP socket...\n");
  net_fd = socket_init();
  if (net_fd < 0) goto ret;

  if (socket_connect(net_fd, job->target_host, job->target_port, &out_errno)) {

  } else {

    switch (ret_val) {
      /*
       * The port may not be DROPPED by the firewall.
       */
      case ECONNREFUSED: /* Connection refused. */
        is_port_open = true;
        break;

      /*
       * The port may be DROPPED by the firewall.
       */
      case ETIMEDOUT: /* Connection timedout. */

      /*
       * Error client.
       */
      case ENETUNREACH: /* Network unreachable. */
      case EINTR: /* Interrupted. */
      case EFAULT: /* Fault. */
      case EBADF: /* Invalid sockfd. */
      case ENOTSOCK: /* sockfd is not a socket file descriptor. */
      case EPROTOTYPE: /* Socket does not support the protocol. */
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
  if (setsockopt(net_fd, SOL_SOCKET, SO_RCVTIMEO,
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
    return false;
  }

  return true;
}
