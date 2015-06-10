#include <openssl/rand.h>
#include <openssl/sha.h>

#include <assert.h>

#ifndef __MACH__
#  include <endian.h> /* Linux-ism fuck yeah. */
#else
#  include <libkern/OSByteOrder.h>
#  define htobe64(x) OSSwapHostToBigInt64(x)
#  define htole64(x) OSSwapHostToLittleInt64(x)
#endif

#include <getopt.h>
#include <limits.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "ref10/ge.h"

#include "base32.h"

/*
 * Workers will re-check the termination condition every n / 8 iterations.
 * MUST be a power of 2 or bad things will happen.
 */
#define CHECK_INCR 131072

/* Maximum supported prefix length (bytes). */
#define MAX_PREFIX_BYTES 12

/* Maximum supported prefix length (bits). */
#define MAX_PREFIX_BITS 60

typedef struct {
  uint64_t prefix;
  uint64_t mask;
  size_t nbits;
} bitprefix;

static bitprefix *bitprefix_from_base32(const char *b32);
static inline int bitprefix_matches(const bitprefix *v, const uint8_t *buf,
                                    size_t len);

static void usage(const char *execname);
static void random_32bytes(uint8_t *buf);
static void scalar_add(uint8_t r[32], const uint8_t x[32], const uint8_t y[32]);
static void *search_worker(void *arg);

static pthread_mutex_t rng_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_rwlock_t result_lock = PTHREAD_RWLOCK_INITIALIZER;
static int result_found = 0;

/* The basepoint multiplied by 8. */
static const ge_cached ge_eightpoint = {
  /* YplusX */
  {
    48496028, -16430416, 15164263, 11885335, 60784617, -4866353, 46481863,
    -2771805, 9708580, 2387263
  },
  /* YmunusX */
  {
    -10173472, -5540046, 21277639, 4080693, 1932823, -14916249, -9515873,
    -21787995, -36575460, 29827857
  },
  /* Z */
  {
    25143927, -10256223, -3515585, 5715072, 19432778, -14905909, 22462083,
    -8862871, 13226552, 743677
  },
  /* T2d */
  {
    -784818, -8208065, -28479270, 5551579, 15746872, 4911053, 19117091,
    11267669, -24569594, 14624995
  }
};


static bitprefix *
bitprefix_from_base32(const char *b32)
{
  uint8_t decoded[MAX_PREFIX_BYTES] = { 0 };
  const uint64_t *p = (uint64_t*)decoded;
  bitprefix *v;
  size_t nbytes;
  size_t i;

  if (b32 == NULL)
    return NULL;

  if (base32_decode(b32, decoded, sizeof(decoded)) == -1)
    return NULL;
  nbytes = strlen(b32);

  v = (bitprefix*)calloc(1, sizeof(*v));
  v->nbits = nbytes * 5;

  /*
   * Instead of using memcmp() or anything else, we can simplify things and use
   * a mask + 64 bit integer compare if we limit the lenght of the prefix to 12
   * characters (60 bits).  Since it's unlikely that anyone is crazy enough to
   * search for prefixes that are that long, use the optimization.
   */
  for (i = 0; i < nbytes; i++) {
    v->mask |= ((uint64_t)0x1f << (64 - 5 * (i + 1)));
  }
  v->mask = htobe64(v->mask);
  v->prefix = *p & v->mask;

  return v;
}

static inline
int bitprefix_matches(const bitprefix *v, const uint8_t *buf, size_t len)
{
  const uint64_t *p = (uint64_t*)buf;

  assert(v != NULL);
  assert(buf != NULL);
  assert(len * 8 >= v->nbits);
#ifdef NDEBUG
  (void)len;
#endif

  return (*p & v->mask) == v->prefix;
}

static void
usage(const char *execname)
{
  fprintf(stderr, "%s [-n cores] prefix\n", execname);
  exit(-1);
}

static void
random_32bytes(uint8_t *buf)
{
  uint8_t az[64];

  /* Yes, this is the "wrong" way to make this threadsafe. */
  pthread_mutex_lock(&rng_lock);
  RAND_bytes(buf, 32);
  pthread_mutex_unlock(&rng_lock);
  SHA512(buf, 32, az);
  memcpy(buf, az, 32);
}

static void
scalar_add(uint8_t r[32], const uint8_t x[32], const uint8_t y[32])
{
  uint32_t v[32];
  int carry;
  int i;

  for (i = 0; i < 32; i++) {
    v[i] = x[i] + y[i];
  }
  for (i = 0; i < 31; i++) {
    carry = v[i] >> 8;
    v[i+1] += carry;
    v[i] &= 0xff;
  }
  for (i = 0; i < 32; i++) {
    r[i] = v[i];
  }
}

static void *
search_worker(void *arg)
{
  const bitprefix *prefix = arg;
  uint8_t pk[32];
  uint8_t pk_cmp[32];
  uint8_t sk[32];
  uint8_t sk_base[32];
  uint8_t sk_fixup[32];
  ge_p3 ge_pk;
  uint64_t incr = 0;

  memset(sk_fixup, 0, sizeof(sk_fixup));

 regenerate:
  /* Generate the keypair. */
  random_32bytes(sk_base);
  sk_base[0] &= 248;
  sk_base[31] &= 63;
  sk_base[31] |= 64;
  ge_scalarmult_base(&ge_pk, sk_base);
  ge_p3_tobytes(pk, &ge_pk);

  /*
   * This is the core of the search algorithm.  We increment the public key by
   * the basepoint till a public key with the desired prefix is found.
   *
   * Note: We actually increment the public key by the basepoint 8 times per
   * iteration, so that when we go to fixup the private key, we do not end up
   * adding a value that will result in a private key that gets screwed up when
   * we do the usual masking business.
   */
  for (incr = 0; incr < UINT64_MAX - 8; incr += 8) {
    ge_p1p1 sum;

    /* Only check if the worker should exit once in a while. */
    if (__builtin_expect((incr & (CHECK_INCR - 1)) == 0, 0)) {
      int found;
      pthread_rwlock_rdlock(&result_lock);
      found = result_found;
      pthread_rwlock_unlock(&result_lock);
      if (found)
        return NULL;
    }

    /* GCC-ism fuck yeah. */
    if (__builtin_expect(bitprefix_matches(prefix, pk, sizeof(pk)), 0)) {
      uint64_t incr_le = htole64(incr);

      /*
       * Fixup the private key by adding the number of times the basepoint was
       * incremented, and ensure that it is sane.
       *
       * Note: The 0th byte should *ALWAYS* be valid due to the increment being
       * a multiple of 8.  The only way for the last byte to be screwed up is
       * if the carry bit propagates all the way across the key.  While it is
       * possible to filter out keys that can do that in the generation
       * phase, the probability of that happening to begin with are
       * astronomically low.
       */
      memcpy(sk_fixup, &incr_le, sizeof(incr_le));
      scalar_add(sk, sk_base, sk_fixup);
      if (((sk[0] & 248) == sk[0]) && (((sk[31] & 63) | 64) == sk[31])) {
        /* These operations should be a no-op. */
        sk[0] &= 248;
        sk[31] &= 63;
        sk[31] |= 64;
        goto found;
      } else {
        /*
         * Well shit.  Presumably incr is >= 2^56, and the private key that was
         * randomly generated is such that the carry bit propagated and screwed
         * up the last byte.
         */
        goto regenerate;
      }
    }

    ge_add(&sum, &ge_pk, &ge_eightpoint);
    ge_p1p1_to_p3(&ge_pk, &sum);
    ge_p3_tobytes(pk, &ge_pk);
  }
  goto regenerate; /* This should *never* happen in a reasonable time. */

 found:
  /*
   * This will cause all of the other threads to stop work once they go to
   * check the termination condition.  This is fine because a worker in this
   * part of the code means that a key has been found.
   */
  pthread_rwlock_wrlock(&result_lock);

  /* First result found, print it. */
  if (!result_found) {
    /* At this point, sk *should* produce pk, which has the prefix. */
    ge_scalarmult_base(&ge_pk, sk);
    ge_p3_tobytes(pk_cmp, &ge_pk);
    if (memcmp(pk_cmp, pk, sizeof(pk_cmp)) == 0) {
      char *public_key = base32_encode(pk, sizeof(pk));
      char *private_key = base32_encode(sk, sizeof(sk));

      fprintf(stdout, "Private Key: %s\n", private_key);
      fprintf(stdout, "Public  Key: %s\n", public_key);

      result_found = 1;

      free(public_key);
      free(private_key);

    } else {
      fprintf(stderr, "BUG: Couldn't produce public key from private key.\n");
    }
  }

  pthread_rwlock_unlock(&result_lock);

  return NULL;
}

int
main(int argc, char *argv[])
{
  const struct option options[] = {
    { "ncores", required_argument, NULL, 'n' },
    { NULL, 0, NULL, 0}
  };
  const char *execname = argv[0];
  pthread_t *workers = NULL;
  bitprefix *prefix;
  unsigned long n;
  unsigned int ncores = 1;
  unsigned int i;
  int ch;

  /* Parse the command line arguments. */
  while ((ch = getopt_long(argc, argv, "n:", options, NULL)) != -1) {
    switch (ch) {
    case 'n':
      n = strtoul(optarg, NULL, 10);
      if (n == 0 || n == ULONG_MAX || n > UINT_MAX) {
        fprintf(stderr, "Failed to parse ncores: [%s]\n", optarg);
        return -1;
      }
      ncores = (int)n;
      break;

    default:
      usage(execname);
    }
  }

  /* The prefix is mandatory and can't contain white space because Base32. */
  if (optind != argc - 1) {
    usage(execname);
  }
  argc -= optind;
  argv += optind;
  if (strlen(argv[0]) > MAX_PREFIX_BYTES) {
    fprintf(stderr, "Invalid prefix length. (Max: %d)\n", MAX_PREFIX_BYTES);
    return -1;
  }
  prefix = bitprefix_from_base32(argv[0]);
  if (prefix == NULL) {
    fprintf(stderr, "Failed to decode prefix: [%s]\n", argv[0]);
    return -1;
  }

  fprintf(stdout, "Searching for prefix: [%s] (%zd bits)\n", argv[0],
          prefix->nbits);
  fprintf(stdout, "Threads: %u\n", ncores);
  fprintf(stdout, "\n");

  /* Kick off the worker threads and start searching. */
  ncores -= 1;
  if (ncores > 0) {
    workers = calloc(ncores, sizeof(*workers));
    for (i = 0; i < ncores; i++) {
      pthread_create(&workers[i], NULL, &search_worker, prefix);
    }
  }
  search_worker(prefix);

  /* Ensure all of the threads have terminated. */
  for (i = 0; i < ncores; i++) {
    pthread_join(workers[i], NULL);
  }

  if (!result_found) {
    fprintf(stderr, "BUG: All threads exited without a result.");
  }

  if (workers)
    free(workers);
  free(prefix);

  return 0;
}
