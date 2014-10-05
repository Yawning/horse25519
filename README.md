## horse25519 - An Ed25519 vanity public key generator
### Yawning Angel (yawning at torproject dot org)

### What?

This is a Ed25519 vanity public key search tool in the spirit of shallot.  It
attempts to generate a Ed25519 keypair that has a public key with a user
provided prefix when encoded in Base32.

It is slower than searching for keys via Scallion as it only runs on the CPU.
Porting the relevant math to run on a GPU is left as an exercise for the
student.

### Notes

The Ed25519 implementation is ed25519/ref10 from SUPERCOP (20140924).  The
src/ref10 directory contains an unmodified copy, with the portability headers
and routines thrown into src.  In theory minor speedups may be obtained by
switching to Floodyberry's ed25519-donna, but as the search phase does not do
the scalar multiplication, this probably will not be that big of a gain.

The trick for skipping the scalar multiplication, and the basis for the
implementation was shown to be my Nick Mathewson.

OpenSSL is used for the CSPRNG and a SHA512 implementation.  This is subject to
change at a later date since pulling in OpenSSL for either of those things is
approaching overkill.

The code doesn't take any particular care to scrub values off the heap or stack.
You are using this on a dedicated offline box without swap right?

The number of fucks I give about Windows or Darwin is equal to the number of
computers I have that run either operating system.  Patches for the latter
probably accepted.
