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
#include <stdlib.h>
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
  ares_dns_record_t *dnsrec = NULL;
  size_t cnt;

  /* There is never a reason to have a size > 65535, it is immediately
   * rejected by the parser */
  if (size > 65535) {
    return 0;
  }

  if (size == 0) {
    return 0;
  }

  unsigned char mode = data[0];
  const unsigned char *rest = data + 1;
  size_t rest_size = size - 1;

  if (mode & 1) {
    /* Mode: Create a DNS record programmatically and add queries */
    unsigned char n = 0;
    unsigned char rec_type_idx = 0;
    unsigned char class_idx = 0;
    unsigned short id = 1234;
    unsigned short flags = 0;
    const unsigned char *name_ptr = NULL;
    size_t name_len = 0;

    /* Predefined arrays of valid record types and classes for queries */
    static const ares_dns_rec_type_t rec_types[] = {
      ARES_REC_TYPE_A,
      ARES_REC_TYPE_NS,
      ARES_REC_TYPE_CNAME,
      ARES_REC_TYPE_SOA,
      ARES_REC_TYPE_PTR,
      ARES_REC_TYPE_HINFO,
      ARES_REC_TYPE_MX,
      ARES_REC_TYPE_TXT,
      ARES_REC_TYPE_SIG,
      ARES_REC_TYPE_AAAA,
      ARES_REC_TYPE_SRV,
      ARES_REC_TYPE_NAPTR,
      ARES_REC_TYPE_OPT,
      ARES_REC_TYPE_TLSA,
      ARES_REC_TYPE_SVCB,
      ARES_REC_TYPE_HTTPS,
      ARES_REC_TYPE_ANY,
      ARES_REC_TYPE_URI,
      ARES_REC_TYPE_CAA,
      ARES_REC_TYPE_RAW_RR
    };
    static const ares_dns_class_t classes[] = {
      ARES_CLASS_IN,
      ARES_CLASS_CHAOS,
      ARES_CLASS_HESOID,
      ARES_CLASS_NONE,
      ARES_CLASS_ANY
    };

    if (rest_size > 0) {
      n = rest[0] % 21;  /* 0 to 20 queries */
    }
    if (rest_size > 1) {
      rec_type_idx = rest[1] % (sizeof(rec_types)/sizeof(rec_types[0]));
    }
    if (rest_size > 2) {
      class_idx = rest[2] % (sizeof(classes)/sizeof(classes[0]));
    }
    if (rest_size > 4) {
      id = (rest[3] << 8) | rest[4];
    }
    if (rest_size > 5) {
      flags = rest[5];
    }
    if (rest_size > 6) {
      name_ptr = rest + 6;
      name_len = rest_size - 6;
    }

    char *name = NULL;
    if (name_len > 0) {
      name = malloc(name_len + 1);
      memcpy(name, name_ptr, name_len);
      name[name_len] = '\0';
    } else {
      name = strdup("example.com");
    }

    ares_status_t status = ares_dns_record_create(&dnsrec, id, flags,
                                                  ARES_OPCODE_QUERY,
                                                  ARES_RCODE_NOERROR);
    if (status == ARES_SUCCESS) {
      for (unsigned char i = 0; i < n; i++) {
        status = ares_dns_record_query_add(dnsrec, name,
                                           rec_types[rec_type_idx],
                                           classes[class_idx]);
        if (status != ARES_SUCCESS) {
          break;
        }
      }
      if (status != ARES_SUCCESS) {
        ares_dns_record_destroy(dnsrec);
        dnsrec = NULL;
      } else {
        /* Call ares_dns_record_query_get for each query to exercise more code */
        for (unsigned char i = 0; i < n; i++) {
          const char *qname = NULL;
          ares_dns_rec_type_t qtype;
          ares_dns_class_t qclass;
          if (ares_dns_record_query_get(dnsrec, i, &qname, &qtype, &qclass) != ARES_SUCCESS) {
            break;
          }
        }
      }
    } else {
      dnsrec = NULL;
    }
    free(name);
  } else {
    /* Mode: Parse the rest as a DNS message */
    (void)ares_dns_parse(rest, rest_size, 0, &dnsrec);
  }

  /* Call the function under test */
  cnt = ares_dns_record_query_cnt(dnsrec);
  (void)cnt;

  if (dnsrec) {
    ares_dns_record_destroy(dnsrec);
  }

  return 0;
}

#endif