#include <string.h>
#include "crypto_sign.h"
#include "crypto_hash_sha512.h"
#include "ge.h"
#include "sc.h"

int crypto_sign(
  unsigned char *sm,unsigned long long *smlen,
  const unsigned char *m,unsigned long long mlen,
  const unsigned char *sk
)
{
  unsigned char pk[32];
  unsigned char az[64];
  unsigned char nonce[64];
  unsigned char hram[64];
  ge_p3 R, A;

  /* Re-derive the public key from the secret key's scalar component,
   * because someone that foolishly copy-pastes this exotic Ed25519
   * sign variant may pass in the incorrect public key and destroy
   * their confidentiality, when using this code in something else.
   *
   * See: https://github.com/MystenLabs/ed25519-unsafe-libs
   */
  ge_scalarmult_base(&A, sk);
  ge_p3_tobytes(pk, &A);

#if 0
  crypto_hash_sha512(az,sk,32);
  az[0] &= 248;
  az[31] &= 63;
  az[31] |= 64;
#else
  /*
   * Horse25519 changes:
   *
   * The ref10 keypair generation code returns the "seed | public key", for sk.
   *
   * Signing (and public key derivation) both work off SHA512(seed) (+ clamping,
   * on bytes 0..31).  Since it's not possible to reverse our fixed up `az`
   * back to a seed, just patch the code to skip `az` derivation, since the
   * private key is in expanded form already.
   */
  memcpy(az,sk,64);
#endif

  *smlen = mlen + 64;
  memmove(sm + 64,m,mlen);
  memmove(sm + 32,az + 32,32);
  crypto_hash_sha512(nonce,sm + 32,mlen + 32);
  memmove(sm + 32,pk,32);

  sc_reduce(nonce);
  ge_scalarmult_base(&R,nonce);
  ge_p3_tobytes(sm,&R);

  crypto_hash_sha512(hram,sm,mlen + 64);
  sc_reduce(hram);
  sc_muladd(sm + 32,hram,az,nonce);

  return 0;
}
