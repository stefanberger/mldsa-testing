#!/usr/bin/env bash

# shellcheck disable=SC2059,SC2043

# Test loading of self-signed x509 certificates holding ML-DSA keys.

# Flip a random bit at given byte offset in the given file
bit_flip_in_file()
{
  local filename="$1"
  local fileoffset="$2"

  local byte newbyte byte_to_write

  # current byte at this offset
  byte="0x$(dd if="${filename}" bs=1 count=1 skip=$((fileoffset)) status=none |
            od -An -tx1 |
            cut -d" " -f2- |
            tr -d ' ')"
  #echo "fileoffset=$((fileoffset)) byte=$((byte))"
  # flip a single random bit in this byte
  newbyte=$((byte ^ (1 << (RANDOM & 7))))
  byte_to_write="\x$(printf "%02x" ${newbyte})"
  #echo "byte=$((byte)) newbyte=$((newbyte)) ${byte_to_write}"
  #printf "${byte_to_write}" | od -An -tx1

  # write this byte back into the file
  echo -en "${byte_to_write}" | \
    dd of="${filename}" bs=1 count=1 seek=$((fileoffset)) conv=notrunc status=none
  #dd if=${certfile} bs=1 count=1 skip=$((fileoffset)) status=none | od -An -tx1
}

# Inject a fault into the certificate's key
inject_fault_cert_key() {
  local certfilein="$1"
  local certfileout="$2"

  local line offset keysize keyoffset

  cp -f "${certfilein}" "${certfileout}"

  line=$(openssl asn1parse -inform der -in "${certfilein}" |
        grep "BIT STRING" |
        head -n1)
  offset=$(echo "${line}" | cut -d":" -f1)

  #dd if="${certfilein}" bs=1 count=2 skip=$((offset+2)) status=none | od -An -tx1
  # the size of the key can be found in 2 bytes at offset+2
  keysize="0x$(dd if="${certfilein}" bs=1 count=2 skip=$((offset+2)) status=none |
               od -An -tx1 |
               cut -d" " -f2- |
               tr -d ' ')"

  # offset within key
  keyoffset=$((RANDOM % keysize))

  bit_flip_in_file "${certfileout}" "$((offset+2+keyoffset))"
  #sha1sum "${certfilein}" "${certfileout}"
}

# Inject a fault into the certificate's signature
inject_fault_cert_signature() {
  local certfilein="$1"
  local certfileout="$2"

  local line offset sigsize sigoffset

  cp -f "${certfilein}" "${certfileout}"

  line=$(openssl asn1parse -inform der -in "${certfilein}" |
        grep "BIT STRING" |
        tail -n1)
  offset=$(echo "${line}" | cut -d":" -f1)

  #set -x
  # the size of the signature can be found in 2 bytes at offset+2
  sigsize="0x$(dd if="${certfilein}" bs=1 count=2 skip=$((offset+2)) status=none |
               od -An -tx1 |
               cut -d" " -f2- |
               tr -d ' ')"
  # offset within signature
  sigoffset=$((RANDOM % sigsize))

  bit_flip_in_file "${certfileout}" "$((offset+2+sigoffset))"
}

main() {
  local certfile id rc reason

  keyctl newring test @u 1>/dev/null

  if ! grep -q -E ": ecdsa-nist-p(192|256|384|521)" /proc/crypto; then
    echo "Kernel does not support any NIST curves. Try 'sudo modprobe ecdsa_generic'." >&2
    exit 1
  fi

  keys="mldsa44 mldsa65 mldsa87"
  echo "Testing with keys: ${keys}"

  while :; do
    for key in ${keys}; do
      for hash in shake256; do # only shake256 seems supported; no need to pass it
        certfile="cert.der"
        openssl req \
                -x509 \
                -newkey "${key}" \
                "-${hash}" \
                -keyout key.pem \
                -days 365 \
                -subj '/CN=test' \
                -nodes \
                -outform der \
                -out "${certfile}" 2>/dev/null

        exp=0
        # Every once in a while we inject a fault into the
        # certificate's key or signature
        reason=""
        case $((RANDOM & 3)) in
        0)
          inject_fault_cert_key "${certfile}" "${certfile}.bad"
          certfile="${certfile}.bad"
          exp=1
          reason="bad key"
        ;;
        1)
          inject_fault_cert_signature "${certfile}" "${certfile}.bad"
          certfile="${certfile}.bad"
          exp=1
          reason="bad signature"
        ;;
        esac

        id=$(keyctl padd asymmetric testkey %keyring:test < "${certfile}")
        rc=$?
        if [ $rc -ne $exp ]; then
          case "$exp" in
          0) echo "Error: Could not load valid certificate!";;
          1) echo "Error: Succeeded to load invalid certificate! ($reason)";;
          esac
          echo "key: $key"
          exit 1
        else
          case "$rc" in
          0) printf "Good: key: %7s  keyid: %-10s" "$key" "$id";;
          *) printf "Good: key: %7s  keyid: %-10s -- bad certificate was rejected ($reason)\n" "$key" "$id";;
          esac
        fi
        if [ -n "${id}" ]; then
          local sigsz off byte1 byte2

          echo "test" >> raw-in
          # pre-hash
          openssl dgst -shake256 -xoflen=32 -binary raw-in > raw-in.hash
          # Sign the pre-hash; OpenSSL must be using domain separator 0x00, 0x00 (!)
          openssl pkeyutl -sign -inkey key.pem -in raw-in.hash -out sig.bin
          # This also works because the kernel uses domain separator 0x00, 0x00
          if ! keyctl pkey_verify "${id}" 0 /dev/null sig.bin "msg=$(base64 -w0 raw-in.hash)"; then
            printf "\n\nSignature verification failed\n"
            exit 1
          fi
          sigsz=$(stat -c%s sig.bin)
          hashsz=$(stat -c%s raw-in.hash)

          # Try verification with bad signatures
          for _ in $(seq 0 19); do
            cp sig.bin sig.bin.bad

            off=$((RANDOM % (sigsz-1)))
            # Generate a bad signature by injecting 2 random bytes into the file at some offset
            byte1=$(printf "%02x" $((RANDOM % 255)))
            byte2=$(printf "%02x" $((RANDOM % 255)))
            printf "\x${byte1}\x${byte2}" |
              dd of=sig.bin.bad bs=1 count=2 seek=$((off)) conv=notrunc status=none
            if keyctl pkey_verify "${id}" 0 /dev/null sig.bin.bad "msg=$(base64 -w0 raw-in.hash)" &>/dev/null; then
              # Accidentally verified - Must also pass with openssl
              if ! openssl pkeyutl \
                     -verify \
                     -in raw-in.hash \
                     -sigfile sig.bin.bad \
                     -inkey key.pem &>/dev/null; then
                printf "\n\nBAD: Kernel driver reported successful verification of bad signature"
                exit 1
              fi
            fi


            # test with good signature and bad hash
            cp raw-in.hash raw-in.hash.bad
            off=$((RANDOM % (hashsz-1)))

            # Generate a bad hash by injecting 2 random bytes into the file at some offset
            printf "\x${byte1}\x${byte2}" |
              dd of=raw-in.hash.bad bs=1 count=2 seek=$((off)) conv=notrunc status=none
            if keyctl pkey_verify "${id}" 0 /dev/null sig.bin "msg=$(base64 -w0 raw-in.hash.bad)" &>/dev/null; then
              # Accidentally verified - Must also pass with openssl
              if ! openssl pkeyutl \
                     -verify \
                     -in raw-in.hash.bad \
                     -sigfile sig.bin \
                     -inkey key.pem &>/dev/null; then
                printf "\n\nBAD: Kernel driver reported successful verification of bad signature with bad hash"
                exit 1
              fi
            fi
          done
          printf " Signature test passed\n"

          # check for fixes introduced by
          # https://lore.kernel.org/linux-crypto/cover.1735236227.git.lukas@wunner.de/T/#mf161d128e8f7a8498c64e66d69dd666a1385c382
          if ! keyctl pkey_query "${id}" 0 > pkey_query.out; then
            printf "\nWarning: pkey_query failed on key\n"
          else
            local expkeylen=0
            case "${key}" in
            mldsa44)	expkeylen=$((1312*8));;
            mldsa65)	expkeylen=$((1952*8));;
            mldsa87)	expkeylen=$((2592*8));;
            esac
            keylen=$(sed -n 's/key_size=//p' pkey_query.out)
            # keylen is part of the curve name
            if [ "${keylen}" -ne ${expkeylen} ]; then
              printf "\nWarning: Wrong key length indicated by pkey_query on ${key} for key ${id}: ${keylen} (${expkeylen})\n"
            fi
          fi

        fi
      done
    done
  done
}

main
