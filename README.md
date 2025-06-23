# mldsa-testing
ML-DSA key testing (expected support of ML-DSA keys in Linux 6.x)

This project currently hosts some simple tests scripts for Linux ML-DSA key support testing.

- test-mldsa-kernel-keys.sh: Endless test for loading ML-DSA keys into the kernel; sometimes an error is injected into the certificate resulting in an expected rejection of the key
- generates.sh + load-keys-kernel.sh: generate CAs and certified keys and then load them into the kernel using restricted keyrings
