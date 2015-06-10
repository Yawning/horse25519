CFLAGS := -O2 -g -Wall -Werror -Wno-error=deprecated-declarations -Wextra -I./src -DNDEBUG
LDFLAGS := -lcrypto -lpthread

SRCS = src/ref10/fe_0.c \
	src/ref10/fe_1.c \
	src/ref10/fe_add.c \
	src/ref10/fe_cmov.c \
	src/ref10/fe_copy.c \
	src/ref10/fe_frombytes.c \
	src/ref10/fe_invert.c \
	src/ref10/fe_isnegative.c \
	src/ref10/fe_isnonzero.c \
	src/ref10/fe_mul.c \
	src/ref10/fe_neg.c \
	src/ref10/fe_pow22523.c \
	src/ref10/fe_sq2.c \
	src/ref10/fe_sq.c \
	src/ref10/fe_sub.c \
	src/ref10/fe_tobytes.c \
	src/ref10/ge_add.c \
	src/ref10/ge_double_scalarmult.c \
	src/ref10/ge_frombytes.c \
	src/ref10/ge_madd.c \
	src/ref10/ge_msub.c \
	src/ref10/ge_p1p1_to_p2.c \
	src/ref10/ge_p1p1_to_p3.c \
	src/ref10/ge_p2_0.c \
	src/ref10/ge_p2_dbl.c \
	src/ref10/ge_p3_0.c \
	src/ref10/ge_p3_dbl.c \
	src/ref10/ge_p3_tobytes.c \
	src/ref10/ge_p3_to_cached.c \
	src/ref10/ge_p3_to_p2.c \
	src/ref10/ge_precomp_0.c \
	src/ref10/ge_scalarmult_base.c \
	src/ref10/ge_sub.c \
	src/ref10/ge_tobytes.c \
	src/ref10/sc_muladd.c \
	src/ref10/sc_reduce.c \
	src/crypto_verify_32.c \
	src/base32.c \
	src/horse25519.c

OBJS = $(SRCS:.c=.o)

.c.o:
	$(CC) $(CFLAGS) -c $< -o $@

.PHONEY: all clean

all: $(OBJS) horse25519

horse25519: $(OBJS)
	$(CC) $(OBJS) $(LDFLAGS) -o horse25519

clean:
	rm -f $(OBJS) horse25519
