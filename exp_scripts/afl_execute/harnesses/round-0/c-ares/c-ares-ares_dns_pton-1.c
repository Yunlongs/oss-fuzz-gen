/* MIT License
 *
 * Copyright (c) The c-ares project and its contributors
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice (including the next
 * paragraph) shall be included in all copies or substantial portions of the
 * Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 * SPDX-License-Identifier: MIT
 */
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include "ares.h"
#include "include/ares_buf.h"
#include "include/ares_mem.h"

int LLVMFuzzerTestOneInput(const unsigned char *data, unsigned long size);

#ifdef USE_LEGACY_FUZZERS

/* This implementation calls the legacy c-ares parsers, which historically
 * all used different logic and parsing.  As of c-ares 1.21.0 these are
 * simply wrappers around a single parser, and simply convert the parsed
 * DNS response into the data structures the legacy parsers used which is a
 * small amount of code and not likely going to vary based on the input data.
 *
 * Instead, these days, it makes more sense to test the new parser directly
 * instead of calling it 10 or 11 times with the same input data to speed up
 * the number of iterations per second the fuzzer can perform.
 *
 * We are keeping this legacy fuzzer test for historic reasons or if someone
 * finds them of use.
 */

int LLVMFuzzerTestOneInput(const unsigned char *data, unsigned long size)
{
  /* Feed the data into each of the ares_parse_*_reply functions. */
  struct hostent          *host = NULL;
  struct ares_addrttl      info[5];
  struct ares_addr6ttl     info6[5];
  unsigned char            addrv4[4] = { 0x10, 0x20, 0x30, 0x40 };
  struct ares_srv_reply   *srv       = NULL;
  struct ares_mx_reply    *mx        = NULL;
  struct ares_txt_reply   *txt       = NULL;
  struct ares_soa_reply   *soa       = NULL;
  struct ares_naptr_reply *naptr     = NULL;
  struct ares_caa_reply   *caa       = NULL;
  struct ares_uri_reply   *uri       = NULL;
  int                      count     = 5;
  ares_parse_a_reply(data, (int)size, &host, info, &count);
  if (host) {
    ares_free_hostent(host);
  }

  host  = NULL;
  count = 5;
  ares_parse_aaaa_reply(data, (int)size, &host, info6, &count);
  if (host) {
    ares_free_hostent(host);
  }

  host = NULL;
  ares_parse_ptr_reply(data, (int)size, addrv4, sizeof(addrv4), AF_INET, &host);
  if (host) {
    ares_free_hostent(host);
  }

  host = NULL;
  ares_parse_ns_reply(data, (int)size, &host);
  if (host) {
    ares_free_hostent(host);
  }

  ares_parse_srv_reply(data, (int)size, &srv);
  if (srv) {
    ares_free_data(srv);
  }

  ares_parse_mx_reply(data, (int)size, &mx);
  if (mx) {
    ares_free_data(mx);
  }

  ares_parse_txt_reply(data, (int)size, &txt);
  if (txt) {
    ares_free_data(txt);
  }

  ares_parse_soa_reply(data, (int)size, &soa);
  if (soa) {
    ares_free_data(soa);
  }

  ares_parse_naptr_reply(data, (int)size, &naptr);
  if (naptr) {
    ares_free_data(naptr);
  }

  ares_parse_caa_reply(data, (int)size, &caa);
  if (caa) {
    ares_free_data(caa);
  }

  ares_parse_uri_reply(data, (int)size, &uri);
  if (uri) {
    ares_free_data(uri);
  }

  return 0;
}

#else

int LLVMFuzzerTestOneInput(const unsigned char *data, unsigned long size)
{
  /* Call ares_dns_pton with the fuzzing input - refined for better coverage */
  {
    /* Use first 4 bytes as control parameters */
    unsigned char param_byte = (size > 0) ? data[0] : 0;
    unsigned char family_byte = (size > 1) ? data[1] : 0;
    unsigned char addr_null_byte = (size > 2) ? data[2] : 0;
    unsigned char outlen_null_byte = (size > 3) ? data[3] : 0;
    
    const unsigned char *string_data = (size > 4) ? data + 4 : NULL;
    size_t string_len = (size > 4) ? size - 4 : 0;
    
    char *ipaddr_str = NULL;
    struct ares_addr *addr_ptr = NULL;
    size_t *out_len_ptr = NULL;
    struct ares_addr addr_storage;
    size_t out_len_storage;
    
    /* Determine if we should pass NULL for ipaddr */
    if ((param_byte & 0x01) == 0) {
        /* Allocate and prepare string */
        if (string_len > 0) {
            /* Sometimes try to create valid IP addresses */
            if ((param_byte & 0x02) && string_len >= 4) {
                /* Format as IPv4: X.X.X.X */
                ipaddr_str = ares_malloc(16);
                if (ipaddr_str) {
                    snprintf(ipaddr_str, 16, "%u.%u.%u.%u",
                             (unsigned int)string_data[0] % 256,
                             (unsigned int)string_data[1] % 256,
                             (unsigned int)string_data[2] % 256,
                             (unsigned int)string_data[3] % 256);
                }
            } else if ((param_byte & 0x04) && string_len >= 16) {
                /* Format as IPv6 (simplified representation) */
                ipaddr_str = ares_malloc(40);
                if (ipaddr_str) {
                    snprintf(ipaddr_str, 40,
                             "%02x%02x:%02x%02x:%02x%02x:%02x%02x:"
                             "%02x%02x:%02x%02x:%02x%02x:%02x%02x",
                             (unsigned int)string_data[0],
                             (unsigned int)string_data[1],
                             (unsigned int)string_data[2],
                             (unsigned int)string_data[3],
                             (unsigned int)string_data[4],
                             (unsigned int)string_data[5],
                             (unsigned int)string_data[6],
                             (unsigned int)string_data[7],
                             (unsigned int)string_data[8],
                             (unsigned int)string_data[9],
                             (unsigned int)string_data[10],
                             (unsigned int)string_data[11],
                             (unsigned int)string_data[12],
                             (unsigned int)string_data[13],
                             (unsigned int)string_data[14],
                             (unsigned int)string_data[15]);
                }
            } else {
                /* Raw string (may contain nulls) */
                ipaddr_str = ares_malloc(string_len + 1);
                if (ipaddr_str) {
                    memcpy(ipaddr_str, string_data, string_len);
                    ipaddr_str[string_len] = '\0';
                    
                    /* Sometimes replace null bytes with '0' */
                    if ((param_byte & 0x08) && string_len > 0) {
                        size_t i;
                        for (i = 0; i < string_len; i++) {
                            if (ipaddr_str[i] == '\0') {
                                ipaddr_str[i] = '0';
                            }
                        }
                    }
                }
            }
        } else {
            /* Empty string case */
            ipaddr_str = ares_malloc(1);
            if (ipaddr_str) {
                ipaddr_str[0] = '\0';
            }
        }
    }
    /* else: ipaddr_str remains NULL (testing NULL parameter) */
    
    /* Determine if we should pass NULL for addr */
    if ((addr_null_byte & 0x01) == 0) {
        addr_ptr = &addr_storage;
        /* Set family with various values, not just 0,1,2 */
        addr_ptr->family = family_byte; /* Can be 0-255 */
        /* Initialize union to avoid uninitialized memory reads */
        memset(&addr_ptr->addr, 0, sizeof(addr_ptr->addr));
    }
    
    /* Determine if we should pass NULL for out_len */
    if ((outlen_null_byte & 0x01) == 0) {
        out_len_ptr = &out_len_storage;
    }
    
    /* Call the function under test */
    const void *result = ares_dns_pton(ipaddr_str, addr_ptr, out_len_ptr);
    (void)result; /* Suppress unused warning */
    
    if (ipaddr_str) {
        ares_free(ipaddr_str);
    }
  }

  ares_dns_record_t *dnsrec    = NULL;
  char              *printdata = NULL;
  ares_buf_t        *printmsg  = NULL;
  size_t             i;
  unsigned char     *datadup     = NULL;
  size_t             datadup_len = 0;

  /* There is never a reason to have a size > 65535, it is immediately
   * rejected by the parser */
  if (size > 65535) {
    return -1;
  }

  if (ares_dns_parse(data, size, 0, &dnsrec) != ARES_SUCCESS) {
    goto done;
  }

  /* Lets test the message fetchers */
  printmsg = ares_buf_create();
  if (printmsg == NULL) {
    goto done;
  }

  ares_buf_append_str(printmsg, ";; ->>HEADER<<- opcode: ");
  ares_buf_append_str(
    printmsg, ares_dns_opcode_tostr(ares_dns_record_get_opcode(dnsrec)));
  ares_buf_append_str(printmsg, ", status: ");
  ares_buf_append_str(printmsg,
                      ares_dns_rcode_tostr(ares_dns_record_get_rcode(dnsrec)));
  ares_buf_append_str(printmsg, ", id: ");
  ares_buf_append_num_dec(printmsg, (size_t)ares_dns_record_get_id(dnsrec), 0);
  ares_buf_append_str(printmsg, "\n;; flags: ");
  ares_buf_append_num_hex(printmsg, (size_t)ares_dns_record_get_flags(dnsrec),
                          0);
  ares_buf_append_str(printmsg, "; QUERY: ");
  ares_buf_append_num_dec(printmsg, ares_dns_record_query_cnt(dnsrec), 0);
  ares_buf_append_str(printmsg, ", ANSWER: ");
  ares_buf_append_num_dec(
    printmsg, ares_dns_record_rr_cnt(dnsrec, ARES_SECTION_ANSWER), 0);
  ares_buf_append_str(printmsg, ", AUTHORITY: ");
  ares_buf_append_num_dec(
    printmsg, ares_dns_record_rr_cnt(dnsrec, ARES_SECTION_AUTHORITY), 0);
  ares_buf_append_str(printmsg, ", ADDITIONAL: ");
  ares_buf_append_num_dec(
    printmsg, ares_dns_record_rr_cnt(dnsrec, ARES_SECTION_ADDITIONAL), 0);
  ares_buf_append_str(printmsg, "\n\n");
  ares_buf_append_str(printmsg, ";; QUESTION SECTION:\n");
  for (i = 0; i < ares_dns_record_query_cnt(dnsrec); i++) {
    const char         *name;
    ares_dns_rec_type_t qtype;
    ares_dns_class_t    qclass;

    if (ares_dns_record_query_get(dnsrec, i, &name, &qtype, &qclass) !=
        ARES_SUCCESS) {
      goto done;
    }

    ares_buf_append_str(printmsg, ";");
    ares_buf_append_str(printmsg, name);
    ares_buf_append_str(printmsg, ".\t\t\t");
    ares_buf_append_str(printmsg, ares_dns_class_tostr(qclass));
    ares_buf_append_str(printmsg, "\t");
    ares_buf_append_str(printmsg, ares_dns_rec_type_tostr(qtype));
    ares_buf_append_str(printmsg, "\n");
  }
  ares_buf_append_str(printmsg, "\n");
  for (i = ARES_SECTION_ANSWER; i < ARES_SECTION_ADDITIONAL + 1; i++) {
    size_t j;

    ares_buf_append_str(printmsg, ";; ");
    ares_buf_append_str(printmsg,
                        ares_dns_section_tostr((ares_dns_section_t)i));
    ares_buf_append_str(printmsg, " SECTION:\n");
    for (j = 0; j < ares_dns_record_rr_cnt(dnsrec, (ares_dns_section_t)i);
         j++) {
      size_t                   keys_cnt = 0;
      const ares_dns_rr_key_t *keys     = NULL;
      ares_dns_rr_t           *rr       = NULL;
      size_t                   k;

      rr = ares_dns_record_rr_get(dnsrec, (ares_dns_section_t)i, j);
      ares_buf_append_str(printmsg, ares_dns_rr_get_name(rr));
      ares_buf_append_str(printmsg, ".\t\t\t");
      ares_buf_append_str(printmsg,
                          ares_dns_class_tostr(ares_dns_rr_get_class(rr)));
      ares_buf_append_str(printmsg, "\t");
      ares_buf_append_str(printmsg,
                          ares_dns_rec_type_tostr(ares_dns_rr_get_type(rr)));
      ares_buf_append_str(printmsg, "\t");
      ares_buf_append_num_dec(printmsg, ares_dns_rr_get_ttl(rr), 0);
      ares_buf_append_str(printmsg, "\t");

      keys = ares_dns_rr_get_keys(ares_dns_rr_get_type(rr), &keys_cnt);
      for (k = 0; k < keys_cnt; k++) {
        char buf[256] = "";

        ares_buf_append_str(printmsg, ares_dns_rr_key_tostr(keys[k]));
        ares_buf_append_str(printmsg, "=");
        switch (ares_dns_rr_key_datatype(keys[k])) {
          case ARES_DATATYPE_INADDR:
            ares_inet_ntop(AF_INET, ares_dns_rr_get_addr(rr, keys[k]), buf,
                           sizeof(buf));
            ares_buf_append_str(printmsg, buf);
            break;
          case ARES_DATATYPE_INADDR6:
            ares_inet_ntop(AF_INET6, ares_dns_rr_get_addr6(rr, keys[k]), buf,
                           sizeof(buf));
            ares_buf_append_str(printmsg, buf);
            break;
          case ARES_DATATYPE_U8:
            ares_buf_append_num_dec(printmsg, ares_dns_rr_get_u8(rr, keys[k]),
                                    0);
            break;
          case ARES_DATATYPE_U16:
            ares_buf_append_num_dec(printmsg, ares_dns_rr_get_u16(rr, keys[k]),
                                    0);
            break;
          case ARES_DATATYPE_U32:
            ares_buf_append_num_dec(printmsg, ares_dns_rr_get_u32(rr, keys[k]),
                                    0);
            break;
          case ARES_DATATYPE_NAME:
          case ARES_DATATYPE_STR:
            ares_buf_append_byte(printmsg, '"');
            ares_buf_append_str(printmsg, ares_dns_rr_get_str(rr, keys[k]));
            ares_buf_append_byte(printmsg, '"');
            break;
          case ARES_DATATYPE_BIN:
            /* TODO */
            break;
          case ARES_DATATYPE_BINP:
            {
              size_t templen;
              ares_buf_append_byte(printmsg, '"');
              ares_buf_append_str(printmsg, (const char *)ares_dns_rr_get_bin(
                                              rr, keys[k], &templen));
              ares_buf_append_byte(printmsg, '"');
            }
            break;
          case ARES_DATATYPE_ABINP:
            {
              size_t a;
              for (a = 0; a < ares_dns_rr_get_abin_cnt(rr, keys[k]); a++) {
                size_t templen;

                if (a != 0) {
                  ares_buf_append_byte(printmsg, ' ');
                }
                ares_buf_append_byte(printmsg, '"');
                ares_buf_append_str(
                  printmsg,
                  (const char *)ares_dns_rr_get_abin(rr, keys[k], a, &templen));
                ares_buf_append_byte(printmsg, '"');
              }
            }
            break;
          case ARES_DATATYPE_OPT:
            /* TODO */
            break;
        }
        ares_buf_append_str(printmsg, " ");
      }
      ares_buf_append_str(printmsg, "\n");
    }
  }
  ares_buf_append_str(printmsg, ";; SIZE: ");
  ares_buf_append_num_dec(printmsg, size, 0);
  ares_buf_append_str(printmsg, "\n\n");

  printdata = ares_buf_finish_str(printmsg, NULL);
  printmsg  = NULL;

  /* Write it back out as a dns message to test writer */
  if (ares_dns_write(dnsrec, &datadup, &datadup_len) != ARES_SUCCESS) {
    goto done;
  }

done:
  ares_dns_record_destroy(dnsrec);
  ares_buf_destroy(printmsg);
  ares_free(printdata);
  ares_free(datadup);
  return 0;
}

#endif