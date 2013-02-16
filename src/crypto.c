/* vim: filetype=c fenc=utf-8 shiftwidth=2 tabstop=2 expandtab
 *
 * mega.co.nz plugin for plowshare
 * Copyright (c) 2013 Plowshare team
 *
 * This file is part of Plowshare.
 *
 * Plowshare is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Plowshare is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Plowshare.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <sys/stat.h>

#include <openssl/aes.h>
#include <openssl/bn.h>
#include <openssl/err.h>

#define AES_KEYSIZE_128       16
#define MAX_BUFFER_LENGTH    (64*AES_KEYSIZE_128)

/* Same errors used by Plowshare (core.sh) */
#define ERR_FATAL              1
#define ERR_NETWORK            3
#define ERR_BAD_COMMAND_LINE  15

/* Global *big* buffer */
static unsigned char work_buffer[MAX_BUFFER_LENGTH];

/* Hexdump */
static void print (unsigned char *in, const unsigned long len)
{
  int i;
  for (i = 0; i < len; i++)
    fprintf(stdout, "%02X", in[i]);
  fputc('\n', stdout);
}

/* File size can be non multiple of block size. iv will be updated. */
static int aes_128_cbc_mac (FILE *fd, const unsigned char key[AES_KEYSIZE_128],
    unsigned char iv[AES_BLOCK_SIZE])
{
  AES_KEY akey;
  unsigned long len;
  struct stat info;
  unsigned char *buffer = &work_buffer[0]; /* global temp buffer */

  AES_set_encrypt_key(&key[0], 128, &akey);

  fstat(fileno(fd), &info);
  len = info.st_size;

  while (len >= MAX_BUFFER_LENGTH) {
    if (fread(buffer, MAX_BUFFER_LENGTH, 1, fd) <= 0) {
      fprintf(stderr, "error: fread (len=%ld)\n", len);
      return ERR_FATAL;
    }

    AES_cbc_encrypt(buffer, buffer, MAX_BUFFER_LENGTH, &akey, iv, AES_ENCRYPT);
    len -= MAX_BUFFER_LENGTH;
  }

  if (len > 0 && fread(buffer, 1, len, fd) > 0) {
    AES_cbc_encrypt(buffer, buffer, len, &akey, iv, AES_ENCRYPT);
  }

  return 0;
}

static int aes_128_cbc_mac0 (const unsigned long length, const unsigned char key[AES_KEYSIZE_128],
    const unsigned char iv[AES_BLOCK_SIZE], unsigned char out[AES_BLOCK_SIZE])
{
  AES_KEY akey;
  unsigned long len = length;

  AES_set_encrypt_key(&key[0], 128, &akey);
  memcpy(&out[0], &iv[0], AES_BLOCK_SIZE);

  while (len >= AES_BLOCK_SIZE) {
    AES_encrypt(out, out, &akey);
    len -= AES_BLOCK_SIZE;
  }

  if (len != 0)
    AES_encrypt(out, out, &akey);

  return 0;
}

/* in & out can be the same address. length can be non multiple of block size. */
static int aes_128_cbc (const unsigned char key[AES_KEYSIZE_128],
    const unsigned char *in, const unsigned long length, unsigned char *out,
    int enc)
{
  AES_KEY akey;
  unsigned char iv[AES_BLOCK_SIZE];

  memset(&iv[0], 0, AES_BLOCK_SIZE);

  /* Calls AES_encrypt (length/AES_BLOCK_SIZE times) */
  if (enc) {
    AES_set_encrypt_key(&key[0], 128, &akey);
    AES_cbc_encrypt(in, out, length, &akey, iv, AES_ENCRYPT);
  } else {
    AES_set_decrypt_key(&key[0], 128, &akey);
    AES_cbc_encrypt(in, out, length, &akey, iv, AES_DECRYPT);
  }

  return 0;
}

/* in & out can be the same address */
static int aes_128_ecb (const unsigned char key[AES_KEYSIZE_128],
    const unsigned char *in, const unsigned long length, unsigned char *out,
    int enc)
{
  AES_KEY akey;
  unsigned long len = length;

  if (enc) {
    AES_set_encrypt_key(&key[0], 128, &akey);

    while (len >= AES_BLOCK_SIZE) {
      AES_encrypt(in, out, &akey);
      len -= AES_BLOCK_SIZE;
      out += AES_BLOCK_SIZE;
      in += AES_BLOCK_SIZE;
    }
  } else {
    AES_set_decrypt_key(&key[0], 128, &akey);

    while (len >= AES_BLOCK_SIZE) {
      AES_decrypt(in, out, &akey);
      len -= AES_BLOCK_SIZE;
      out += AES_BLOCK_SIZE;
      in += AES_BLOCK_SIZE;
    }
  }

  if (len != 0)
    fprintf(stderr, "error: len=%ld, should be 0\n", len);

  return 0;
}

/* in & out can be the same address. length can be non multiple of block size.
   iv (containing the 64-bit counter) will be updated. */
static int aes_128_ctr (const unsigned char key[AES_KEYSIZE_128],
    unsigned char iv[AES_BLOCK_SIZE], const unsigned char *in,
    const unsigned long length, unsigned char *out, int enc)
{
  AES_KEY akey;
	unsigned int num = 0;
	unsigned char tmp[AES_BLOCK_SIZE]; /* should be zeroed if num is non zero */

  if (!enc) {
    fprintf(stderr, "error: aes_128-ctr decrypt not implemented\n");
    return ERR_FATAL;
  }

  AES_set_encrypt_key(&key[0], 128, &akey);
  AES_ctr128_encrypt(in, out, length, &akey, iv, tmp, &num);

  return 0;
}

/* iv (containing the 64-bit counter) will be updated. */
static int aes_128_ctr_encrypt (FILE *fin, FILE *fout,
    const unsigned char key[AES_KEYSIZE_128], unsigned char iv[AES_BLOCK_SIZE])
{
  unsigned long len;
  struct stat info;
  unsigned char *buffer = &work_buffer[0]; /* global temp buffer */

  fstat(fileno(fin), &info);
  len = info.st_size;

  while (len >= MAX_BUFFER_LENGTH) {
    if (fread(buffer, MAX_BUFFER_LENGTH, 1, fin) <= 0) {
      fprintf(stderr, "error: fread (len=%ld)\n", len);
      return ERR_FATAL;
    }

    aes_128_ctr(key, iv, buffer, MAX_BUFFER_LENGTH, buffer, 1);
    len -= MAX_BUFFER_LENGTH;

    if (fwrite(buffer, MAX_BUFFER_LENGTH, 1, fout) <= 0) {
      fprintf(stderr, "error: fwrite (len=%ld)\n", len);
      return ERR_FATAL;
    }
  }

  if (len > 0 && fread(buffer, 1, len, fin) > 0) {
    aes_128_ctr(key, iv, buffer, len, buffer, 1);
    fwrite(buffer, len, 1, fout);
  }

  return 0;
}

/* Convert hexstring buffer to binary (hex2bin).
   Output length will be multiple of AES_BLOCK_SIZE. */
static int normalize_buffer (const char *in, unsigned char *out,
    unsigned long *length)
{
  size_t sz;
  int i, m;
  unsigned char lo, hi, *p = (unsigned char *)in;
  unsigned char *q = out;

  if (!in) {
    fprintf(stderr, "error: missing hexstring, abort\n");
    return ERR_BAD_COMMAND_LINE;
  }

  sz = strlen(in);

  /* Sanity check */
  if (sz > (*length * 2)) {
    fprintf(stderr, "warning: input hexstring is too long, truncating\n");
    sz = *length * 2;
  }

  *length = 0;

  for (i = 0; i < sz / 2; i++, p+=2, q++) {
    hi = *p;
    lo = *(p+1);

    if (!isxdigit(hi)) {
      fprintf(stderr, "error: not a hexadecimal digit `0x%02x', abort\n", hi);
      return ERR_BAD_COMMAND_LINE;
    }

    if (!isxdigit(lo)) {
      fprintf(stderr, "error: not a hexadecimal digit `0x%02x', abort\n", lo);
      return ERR_BAD_COMMAND_LINE;
    }

    if (hi < 0x40)
      hi -= 0x30;
    else
      hi = toupper(hi) - 0x37;

    if (lo < 0x40)
      lo -= 0x30;
    else
      lo = toupper(lo) - 0x37;

    *q = hi << 4 | lo;
  }

  /* Odd input? */
  if (sz & 1) {
    hi = *p;

    if (!isxdigit(hi)) {
      fprintf(stderr, "error: not a hexadecimal digit `0x%02x', abort\n", hi);
      return ERR_BAD_COMMAND_LINE;
    }

    if (hi < 0x40)
      hi -= 0x30;
    else
      hi = toupper(hi) - 0x37;

    *q = hi << 4;
    q++;
  }

  *length = sz / (2 * AES_BLOCK_SIZE) * AES_BLOCK_SIZE;
  m = sz % (2 * AES_BLOCK_SIZE);

  /* Deal with padding */
  if (m > 0) {
    fprintf(stderr, "warning: add padding (%d)\n", (2 * AES_BLOCK_SIZE) - m);

    if (sz & 1)
      m++;

    for (i = 0; i < AES_BLOCK_SIZE - (m / 2); i++, q++)
      *q = 0;
    *length += AES_BLOCK_SIZE;
  }

  //print(out, *length);
  return 0;
}

static void usage (const char *name)
{
  fprintf(stdout, "usage: %s <command> [<args>]\n\n"
      "Commands are:\n"
      "  cbc_enc <key> <buffer>     AES-128-CBC encrypt (IV=0)\n"
      "  cbc_dec <key> <buffer>     AES-128-CBC decrypt (IV=0)\n"
      "  ecb_enc <key> <buffer>     AES-128-ECB encrypt (IV=0)\n"
      "  ecb_dec <key> <buffer>     AES-128-ECB decrypt (IV=0)\n"
      "  mac <file> <key> <iv>      AES-128-CBC-MAC for file\n"
      "  mac0 <size> <key> <iv>     AES-128-CBC-MAC for zeroed file\n"
      "  rsa <p> <q> <d> <buffer>   RSA decryption: buffer^d (mod p*q)\n"
      "  ctr_enc <filein> <fileout> <key> <iv>  AES-128-CTR encrypt\n"
      "\nNotes:\n"
      "- <key> & <iv> are 32-digit hexstring. For example: 93C467E37DB0C7A4D1BE3F810152CB56\n"
      "- <buffer> are also hexstring (length multiple of 32)\n", name);
}

int main (int argc, char *argv[])
{
    char *p = argv[1];
    unsigned char key[AES_KEYSIZE_128];
    unsigned char iv[AES_BLOCK_SIZE];
    unsigned long len;
    int i, ret = 0;

    if (p == NULL || (strcmp(p, "--help") == 0)) {
        usage(argv[0]);
    } else if (strcmp(p, "--version") == 0) {
        fprintf(stdout, "%s: version 1.0\n", argv[0]);

    } else if (strcmp(p, "cbc_enc") == 0) {

      if (argc != 4) {
        fprintf(stderr, "error: missing argument, abort\n");
        ret = ERR_BAD_COMMAND_LINE;
      } else {

        len = AES_KEYSIZE_128;
        ret = normalize_buffer(argv[2], &key[0], &len);
        if (ret == 0) {
          len = MAX_BUFFER_LENGTH;
          ret = normalize_buffer(argv[3], &work_buffer[0], &len);
          if (ret == 0) {
            aes_128_cbc(key, &work_buffer[0], len, &work_buffer[0], 1);
            print(&work_buffer[0], len);
          }
        }
      }

    } else if (strcmp(p, "cbc_dec") == 0) {

      if (argc != 4) {
        fprintf(stderr, "error: missing argument, abort\n");
        ret = ERR_BAD_COMMAND_LINE;
      } else {
        len = AES_KEYSIZE_128;
        ret = normalize_buffer(argv[2], &key[0], &len);
        if (ret == 0) {
          len = MAX_BUFFER_LENGTH;
          ret = normalize_buffer(argv[3], &work_buffer[0], &len);
          if (ret == 0) {
            aes_128_cbc(key, &work_buffer[0], len, &work_buffer[0], 0);
            print(&work_buffer[0], len);
          }
        }
      }

    } else if (strcmp(p, "ecb_enc") == 0) {

      if (argc != 4) {
        fprintf(stderr, "error: missing argument, abort\n");
        ret = ERR_BAD_COMMAND_LINE;
      } else {

        len = AES_KEYSIZE_128;
        ret = normalize_buffer(argv[2], &key[0], &len);
        if (ret == 0) {
          len = MAX_BUFFER_LENGTH;
          ret = normalize_buffer(argv[3], &work_buffer[0], &len);
          if (ret == 0) {
            aes_128_ecb(key, &work_buffer[0], len, &work_buffer[0], 1);
            print(&work_buffer[0], len);
          }
        }
      }

    } else if (strcmp(p, "ecb_dec") == 0) {

      if (argc < 4) {
        fprintf(stderr, "error: missing argument, abort\n");
        ret = ERR_BAD_COMMAND_LINE;
      } else {

        len = AES_KEYSIZE_128;
        ret = normalize_buffer(argv[2], &key[0], &len);
        if (ret == 0) {
          len = MAX_BUFFER_LENGTH;
          ret = normalize_buffer(argv[3], &work_buffer[0], &len);
          if (ret == 0) {
            aes_128_ecb(key, &work_buffer[0], len, &work_buffer[0], 0);
            print(&work_buffer[0], len);
          }
        }
      }

    } else if (strcmp(p, "mac0") == 0) {

      if (argc < 5) {
        fprintf(stderr, "error: missing argument, abort\n");
        ret = ERR_BAD_COMMAND_LINE;
      } else {
        long size = strtoul(argv[2], NULL, 10);
        if (size <= 0) {
          fprintf(stderr, "error: bad argument size, abort\n");
          ret = ERR_BAD_COMMAND_LINE;
        } else {

          len = AES_KEYSIZE_128;
          ret = normalize_buffer(argv[3], &key[0], &len);
          if (ret == 0) {
            len = AES_BLOCK_SIZE;
            ret = normalize_buffer(argv[4], &iv[0], &len);
            if (ret == 0) {
              aes_128_cbc_mac0(size, key, iv, work_buffer);
              print(&work_buffer[0], AES_KEYSIZE_128);
            }
          }
        }
      }

    } else if (strcmp(p, "mac") == 0) {

      if (argc < 5) {
        fprintf(stderr, "error: missing argument, abort\n");
        ret = ERR_BAD_COMMAND_LINE;
      } else {
        FILE *fd = fopen(argv[2], "r");
        if (fd == NULL) {
          fprintf(stderr, "error: can't open file, abort\n");
          ret = ERR_BAD_COMMAND_LINE;
        } else {

          len = AES_KEYSIZE_128;
          ret = normalize_buffer(argv[3], &key[0], &len);
          if (ret == 0) {
            len = AES_BLOCK_SIZE;
            ret = normalize_buffer(argv[4], &iv[0], &len);
            if (ret == 0) {
              aes_128_cbc_mac(fd, key, iv);
              print(&iv[0], AES_BLOCK_SIZE);
            }
          }
          fclose(fd);
        }
      }

    } else if (strcmp(p, "rsa") == 0) {

      if (argc < 6) {
        fprintf(stderr, "error: missing argument, abort\n");
        ret = ERR_BAD_COMMAND_LINE;
      } else {
        BIGNUM *bn[4] = {0,0,0,0}; /* p, q, d, buffer */

        ERR_load_crypto_strings();

        for (i = 0; i < 4; i++) {
          if (BN_hex2bn(&bn[i], argv[i+2]) == 0) {
            unsigned long err = ERR_get_error();
            fprintf(stderr, "error: BN_hex2bn(): %ld\n", err);
            ret = ERR_BAD_COMMAND_LINE;
            break;
          }
        }

        if (ret == 0) {
          BN_CTX *bn_ctx;
          ret = ERR_BAD_COMMAND_LINE;
          if ((bn_ctx = BN_CTX_new()) != NULL) {
            if (BN_mul(bn[0], bn[0], bn[1], bn_ctx)) {
              if (BN_mod_exp(bn[3], bn[3], bn[2], bn[0], bn_ctx)) {
                BN_print_fp(stdout, bn[3]);
                fputc('\n', stdout);
                ret = 0;
              }
            }
            BN_CTX_free(bn_ctx);
          }
        }

        for (i = 0; i < 4; i++)
          if (bn[i]) OPENSSL_free(bn[i]);
      }


    } else if (strcmp(p, "ctr_enc") == 0) {

      if (argc < 6) {
        fprintf(stderr, "error: missing argument, abort\n");
        ret = ERR_BAD_COMMAND_LINE;
      } else {
        FILE *fd_in, *fd_out;

        fd_in = fopen(argv[2], "r");
        if (fd_in == NULL) {
          fprintf(stderr, "error: can't open file, abort\n");
          ret = ERR_BAD_COMMAND_LINE;
        } else {
          fd_out = fopen(argv[3], "w+");
          if (fd_out == NULL) {
            fprintf(stderr, "error: can't open file, abort\n");
            ret = ERR_BAD_COMMAND_LINE;
          } else {
            len = AES_KEYSIZE_128;
            ret = normalize_buffer(argv[4], &key[0], &len);
            if (ret == 0) {
              len = AES_BLOCK_SIZE;
              ret = normalize_buffer(argv[5], &iv[0], &len);
              if (ret == 0) {
                aes_128_ctr_encrypt(fd_in, fd_out, key, iv);

                // Updated counter returned
                print(&iv[0], AES_BLOCK_SIZE);
              }
            }

            fclose(fd_out);
          }
          fclose(fd_in);
        }
      }

    } else {
      fprintf(stderr, "%s: invalid <command> argument `%s'\n", argv[0], p);
    }

    return ret;
}
