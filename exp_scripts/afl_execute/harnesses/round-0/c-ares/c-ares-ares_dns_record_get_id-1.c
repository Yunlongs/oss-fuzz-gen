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
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/in.h>
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
  ares_dns_record_t *parsed_rec = NULL;
  unsigned char *wire_buf = NULL;
  size_t wire_len = 0;
  ares_status_t status;
  unsigned short id, flags;
  unsigned char opcode, rcode;
  unsigned char num_q, num_an, num_ns, num_ar;
  char *name = NULL; /* dynamically allocated or fallback */
  const unsigned char *name_data;
  size_t name_data_len;
  size_t i;

  /* --- Path 1: Parse the input as a DNS message --- */
  if (size > 65535) {
    return -1;
  }

  if (ares_dns_parse(data, size, 0, &parsed_rec) == ARES_SUCCESS) {
    (void)ares_dns_record_get_id(parsed_rec);
    ares_dns_record_destroy(parsed_rec);
    parsed_rec = NULL;
  }

  /* --- Path 2: Create a DNS record with fuzzed parameters --- */
  if (size < 10) {
    /* Not enough bytes for all parameters, but we can still try with defaults */
    id = (size >= 2) ? (unsigned short)((data[0] << 8) | data[1]) : 0;
    flags = (size >= 4) ? (unsigned short)((data[2] << 8) | data[3]) : 0;
    opcode = (size >= 5) ? data[4] : 0;
    rcode = (size >= 6) ? data[5] : 0;
    num_q = (size >= 7) ? data[6] % 11 : 0;  /* limit to 0-10 */
    num_an = (size >= 8) ? data[7] % 11 : 0;
    num_ns = (size >= 9) ? data[8] % 11 : 0;
    num_ar = (size >= 10) ? data[9] % 11 : 0;
    name_data = (size > 10) ? data + 10 : NULL;
    name_data_len = (size > 10) ? size - 10 : 0;
  } else {
    id = (unsigned short)((data[0] << 8) | data[1]);
    flags = (unsigned short)((data[2] << 8) | data[3]);
    opcode = data[4];
    rcode = data[5];
    num_q = data[6] % 11;
    num_an = data[7] % 11;
    num_ns = data[8] % 11;
    num_ar = data[9] % 11;
    name_data = data + 10;
    name_data_len = size - 10;
  }

  /* Use the name_data as a domain name (if any) */
  if (name_data_len > 0) {
    /* Ensure the name is null-terminated for safety */
    name = malloc(name_data_len + 1);
    if (name) {
      memcpy(name, name_data, name_data_len);
      name[name_data_len] = '\0';
    }
  }
  /* If no name could be allocated, use a fallback */
  if (!name) {
    const char *default_name = "example.com";
    size_t default_len = strlen(default_name);
    name = malloc(default_len + 1);
    if (name) {
      memcpy(name, default_name, default_len + 1);
    } else {
      /* Memory allocation failed; cannot proceed */
      return 0;
    }
  }

  /* Create the DNS record with the fuzzed opcode and rcode */
  status = ares_dns_record_create(&dnsrec, id, flags,
                                  (ares_dns_opcode_t)opcode,
                                  (ares_dns_rcode_t)rcode);

  /* Call the function under test on the created record and on NULL */
  (void)ares_dns_record_get_id(dnsrec);
  (void)ares_dns_record_get_id(NULL);

  if (status == ARES_SUCCESS && dnsrec) {
    /* Get and set the ID */
    (void)ares_dns_record_get_id(dnsrec);
    (void)ares_dns_record_set_id(dnsrec, id + 1);
    (void)ares_dns_record_get_id(dnsrec);

    /* Get opcode and rcode */
    (void)ares_dns_record_get_opcode(dnsrec);
    (void)ares_dns_record_get_rcode(dnsrec);

    /* Add queries */
    for (i = 0; i < num_q; i++) {
      (void)ares_dns_record_query_add(dnsrec, name, ARES_REC_TYPE_A, ARES_CLASS_IN);
    }

    /* Add answer RRs (A records) */
    for (i = 0; i < num_an; i++) {
      ares_dns_rr_t *rr = NULL;
      struct in_addr addr;
      addr.s_addr = htonl(0x7f000001); /* 127.0.0.1 */
      (void)ares_dns_record_rr_add(&rr, dnsrec, ARES_SECTION_ANSWER,
                                   name, ARES_REC_TYPE_A, ARES_CLASS_IN, 300);
      if (rr) {
        (void)ares_dns_rr_set_addr(rr, ARES_RR_A_ADDR, &addr);
      }
    }

    /* Add authority RRs (NS records) */
    for (i = 0; i < num_ns; i++) {
      (void)ares_dns_record_rr_add(NULL, dnsrec, ARES_SECTION_AUTHORITY,
                                   name, ARES_REC_TYPE_NS, ARES_CLASS_IN, 300);
    }

    /* Add additional RRs (AAAA records) */
    for (i = 0; i < num_ar; i++) {
      ares_dns_rr_t *rr = NULL;
      struct ares_in6_addr addr6;
      memset(&addr6, 0, sizeof(addr6));
      addr6._S6_un._S6_u8[0] = 0x20;
      addr6._S6_un._S6_u8[1] = 0x01;
      addr6._S6_un._S6_u8[2] = 0x0d;
      addr6._S6_un._S6_u8[3] = 0xb8;
      (void)ares_dns_record_rr_add(&rr, dnsrec, ARES_SECTION_ADDITIONAL,
                                   name, ARES_REC_TYPE_AAAA, ARES_CLASS_IN, 300);
      if (rr) {
        (void)ares_dns_rr_set_addr6(rr, ARES_RR_AAAA_ADDR, &addr6);
      }
    }

    /* Get query and RR counts */
    (void)ares_dns_record_query_cnt(dnsrec);
    (void)ares_dns_record_rr_cnt(dnsrec, ARES_SECTION_ANSWER);
    (void)ares_dns_record_rr_cnt(dnsrec, ARES_SECTION_AUTHORITY);
    (void)ares_dns_record_rr_cnt(dnsrec, ARES_SECTION_ADDITIONAL);

    /* Serialize the record */
    if (ares_dns_write(dnsrec, &wire_buf, &wire_len) == ARES_SUCCESS) {
      /* Parse the serialized buffer back */
      if (ares_dns_parse(wire_buf, wire_len, 0, &parsed_rec) == ARES_SUCCESS) {
        /* Call the function under test on the parsed record */
        (void)ares_dns_record_get_id(parsed_rec);
        /* Also call other getters on the parsed record */
        (void)ares_dns_record_get_opcode(parsed_rec);
        (void)ares_dns_record_get_rcode(parsed_rec);
        (void)ares_dns_record_query_cnt(parsed_rec);
        (void)ares_dns_record_rr_cnt(parsed_rec, ARES_SECTION_ANSWER);
        (void)ares_dns_record_rr_cnt(parsed_rec, ARES_SECTION_AUTHORITY);
        (void)ares_dns_record_rr_cnt(parsed_rec, ARES_SECTION_ADDITIONAL);
        ares_dns_record_destroy(parsed_rec);
        parsed_rec = NULL;
      }
      ares_free(wire_buf);
      wire_buf = NULL;
    }
    ares_dns_record_destroy(dnsrec);
    dnsrec = NULL;
  }

  free(name);

  return 0;
}

#endif