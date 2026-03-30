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

#elif defined(TEST_DNS_RECORD_DESTROY)

/* Helper to read a length‑delimited string from the fuzz input. */
static const char *read_string(const unsigned char *data, size_t size,
                               size_t *offset, char *buf, size_t bufmax)
{
  if (*offset >= size) {
    return NULL;
  }
  unsigned char len = data[*offset] % (bufmax - 1);
  (*offset)++;
  if (*offset + len > size) {
    return NULL;
  }
  memcpy(buf, data + *offset, len);
  buf[len] = '\0';
  *offset += len;
  return buf;
}

int LLVMFuzzerTestOneInput(const unsigned char *data, unsigned long size)
{
  ares_dns_record_t *dnsrec = NULL;
  ares_status_t      status;
  size_t             offset = 0;
  char               strbuf[256];  /* reusable buffer for strings */

  /* We need at least 6 bytes to extract:
   *   data[0] -> opcode (lower 4 bits)
   *   data[1], data[2] -> id (2 bytes)
   *   data[3], data[4] -> flags (2 bytes)
   *   data[5] -> rcode (lower 4 bits)
   */
  if (size < 6) {
    return 0;
  }

  ares_dns_opcode_t opcode = (ares_dns_opcode_t)(data[0] & 0x0F);
  unsigned short    id     = (unsigned short)((data[1] << 8) | data[2]);
  unsigned short    flags  = (unsigned short)((data[3] << 8) | data[4]);
  ares_dns_rcode_t  rcode  = (ares_dns_rcode_t)(data[5] & 0x0F);
  offset = 6;

  status = ares_dns_record_create(&dnsrec, id, flags, opcode, rcode);
  if (status != ARES_SUCCESS) {
    return 0;
  }

  /* Add questions if we have enough data */
  if (offset < size) {
    unsigned char n_qd = data[offset] % 16; /* limit to 16 questions max */
    offset++;
    for (unsigned char i = 0; i < n_qd && offset < size; i++) {
      ares_dns_rec_type_t qtype = (ares_dns_rec_type_t)(data[offset] % 256);
      ares_dns_class_t    qclass = (ares_dns_class_t)(data[offset+1] % 256);
      offset += 2;
      /* Read a variable name for the question */
      const char *name = read_string(data, size, &offset, strbuf, sizeof(strbuf));
      if (name == NULL) {
        name = "example.com";
      }
      ares_dns_record_query_add(dnsrec, name, qtype, qclass);
      /* Ignore failures and continue */
    }
  }

  /* Add resource records if we have enough data */
  if (offset < size) {
    unsigned char n_rr = data[offset] % 16; /* limit to 16 RRs max */
    offset++;
    /* List of RR types we want to test (those with special free logic) */
    static const ares_dns_rec_type_t rr_types[] = {
      ARES_REC_TYPE_A,       /* no extra free, but included for variety */
      ARES_REC_TYPE_NS,
      ARES_REC_TYPE_CNAME,
      ARES_REC_TYPE_SOA,
      ARES_REC_TYPE_PTR,
      ARES_REC_TYPE_HINFO,
      ARES_REC_TYPE_MX,
      ARES_REC_TYPE_TXT,
      ARES_REC_TYPE_AAAA,
      ARES_REC_TYPE_SRV,
      ARES_REC_TYPE_NAPTR,
      ARES_REC_TYPE_OPT,
      ARES_REC_TYPE_TLSA,
      ARES_REC_TYPE_SVCB,
      ARES_REC_TYPE_HTTPS,
      ARES_REC_TYPE_URI,
      ARES_REC_TYPE_CAA,
      ARES_REC_TYPE_RAW_RR,
    };
    const size_t n_rr_types = sizeof(rr_types) / sizeof(rr_types[0]);

    for (unsigned char i = 0; i < n_rr && offset + 3 <= size; i++) {
      ares_dns_section_t sect = (ares_dns_section_t)((data[offset] % 3) + 1); /* 1=ANSWER,2=AUTHORITY,3=ADDITIONAL */
      unsigned char type_idx = data[offset+1] % n_rr_types;
      ares_dns_class_t rrclass = (ares_dns_class_t)(data[offset+2] % 256);
      offset += 3;

      ares_dns_rec_type_t rrtype = rr_types[type_idx];

      /* Read TTL (4 bytes) if available */
      unsigned int ttl = 3600;
      if (offset + 4 <= size) {
        ttl = (data[offset] << 24) | (data[offset+1] << 16) |
              (data[offset+2] << 8) | data[offset+3];
        offset += 4;
      }

      /* Read a variable name for the RR */
      const char *name = read_string(data, size, &offset, strbuf, sizeof(strbuf));
      if (name == NULL) {
        name = "example.com";
      }

      ares_dns_rr_t *rr = NULL;
      status = ares_dns_record_rr_add(&rr, dnsrec, sect, name, rrtype, rrclass, ttl);
      if (status != ARES_SUCCESS) {
        continue;
      }

      /* Set type‑specific fields using variable data from the fuzz input */
      switch (rrtype) {
        case ARES_REC_TYPE_NS:
          if (read_string(data, size, &offset, strbuf, sizeof(strbuf))) {
            ares_dns_rr_set_str(rr, ARES_RR_NS_NSDNAME, strbuf);
          }
          break;
        case ARES_REC_TYPE_CNAME:
          if (read_string(data, size, &offset, strbuf, sizeof(strbuf))) {
            ares_dns_rr_set_str(rr, ARES_RR_CNAME_CNAME, strbuf);
          }
          break;
        case ARES_REC_TYPE_SOA:
          if (read_string(data, size, &offset, strbuf, sizeof(strbuf))) {
            ares_dns_rr_set_str(rr, ARES_RR_SOA_MNAME, strbuf);
          }
          if (read_string(data, size, &offset, strbuf, sizeof(strbuf))) {
            ares_dns_rr_set_str(rr, ARES_RR_SOA_RNAME, strbuf);
          }
          if (offset + 16 <= size) {
            unsigned int serial   = (data[offset]<<24) | (data[offset+1]<<16) |
                                    (data[offset+2]<<8) | data[offset+3];
            unsigned int refresh  = (data[offset+4]<<24) | (data[offset+5]<<16) |
                                    (data[offset+6]<<8) | data[offset+7];
            unsigned int retry    = (data[offset+8]<<24) | (data[offset+9]<<16) |
                                    (data[offset+10]<<8) | data[offset+11];
            unsigned int expire   = (data[offset+12]<<24) | (data[offset+13]<<16) |
                                    (data[offset+14]<<8) | data[offset+15];
            offset += 16;
            ares_dns_rr_set_u32(rr, ARES_RR_SOA_SERIAL, serial);
            ares_dns_rr_set_u32(rr, ARES_RR_SOA_REFRESH, refresh);
            ares_dns_rr_set_u32(rr, ARES_RR_SOA_RETRY, retry);
            ares_dns_rr_set_u32(rr, ARES_RR_SOA_EXPIRE, expire);
          }
          break;
        case ARES_REC_TYPE_PTR:
          if (read_string(data, size, &offset, strbuf, sizeof(strbuf))) {
            ares_dns_rr_set_str(rr, ARES_RR_PTR_DNAME, strbuf);
          }
          break;
        case ARES_REC_TYPE_HINFO:
          if (read_string(data, size, &offset, strbuf, sizeof(strbuf))) {
            ares_dns_rr_set_str(rr, ARES_RR_HINFO_CPU, strbuf);
          }
          if (read_string(data, size, &offset, strbuf, sizeof(strbuf))) {
            ares_dns_rr_set_str(rr, ARES_RR_HINFO_OS, strbuf);
          }
          break;
        case ARES_REC_TYPE_MX:
          if (read_string(data, size, &offset, strbuf, sizeof(strbuf))) {
            ares_dns_rr_set_str(rr, ARES_RR_MX_EXCHANGE, strbuf);
          }
          if (offset + 2 <= size) {
            unsigned short preference = (data[offset] << 8) | data[offset+1];
            offset += 2;
            ares_dns_rr_set_u16(rr, ARES_RR_MX_PREFERENCE, preference);
          }
          break;
        case ARES_REC_TYPE_SRV:
          if (read_string(data, size, &offset, strbuf, sizeof(strbuf))) {
            ares_dns_rr_set_str(rr, ARES_RR_SRV_TARGET, strbuf);
          }
          if (offset + 6 <= size) {
            unsigned short priority = (data[offset] << 8) | data[offset+1];
            unsigned short weight   = (data[offset+2] << 8) | data[offset+3];
            unsigned short port     = (data[offset+4] << 8) | data[offset+5];
            offset += 6;
            ares_dns_rr_set_u16(rr, ARES_RR_SRV_PRIORITY, priority);
            ares_dns_rr_set_u16(rr, ARES_RR_SRV_WEIGHT, weight);
            ares_dns_rr_set_u16(rr, ARES_RR_SRV_PORT, port);
          }
          break;
        case ARES_REC_TYPE_URI:
          if (read_string(data, size, &offset, strbuf, sizeof(strbuf))) {
            ares_dns_rr_set_str(rr, ARES_RR_URI_TARGET, strbuf);
          }
          if (offset + 4 <= size) {
            unsigned short priority = (data[offset] << 8) | data[offset+1];
            unsigned short weight   = (data[offset+2] << 8) | data[offset+3];
            offset += 4;
            ares_dns_rr_set_u16(rr, ARES_RR_URI_PRIORITY, priority);
            ares_dns_rr_set_u16(rr, ARES_RR_URI_WEIGHT, weight);
          }
          break;
        case ARES_REC_TYPE_CAA:
          if (read_string(data, size, &offset, strbuf, sizeof(strbuf))) {
            ares_dns_rr_set_str(rr, ARES_RR_CAA_TAG, strbuf);
          }
          if (read_string(data, size, &offset, strbuf, sizeof(strbuf))) {
            ares_dns_rr_set_str(rr, ARES_RR_CAA_VALUE, strbuf);
          }
          if (offset + 1 <= size) {
            ares_dns_rr_set_u8(rr, ARES_RR_CAA_CRITICAL, data[offset]);
            offset += 1;
          }
          break;
        /* For other RR types we just create the record without extra fields;
           the destroy function will still free any default‑allocated structures. */
        default:
          /* nothing extra */
          break;
      }
    }
  }

  ares_dns_record_destroy(dnsrec);
  return 0;
}

#else

int LLVMFuzzerTestOneInput(const unsigned char *data, unsigned long size)
{
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