# dns-zone-verify

A Go tool that verifies DNS records from a BIND zone file against a DNS server. This is useful when migrating from one DNS server to another to ensure all records were imported correctly.

## Features

- Parse BIND zone files
- Query specified DNS server for each record
- Compare expected vs actual DNS records
- Display differences and errors
- Print summary of results
- Verbose mode to see each record checked

## Installation

```bash
go install github.com/perryh/dns-zone-verify@latest
```

## Usage

```bash
./dns-zone-verify -zone <zone-file> -server <host> [-verbose]
```

### Command Line Arguments

- `-zone <path>`: Path to the BIND zone file (required)
- `-server <host>`: DNS server address (IP or hostname) to check against (required)
- `-verbose`: Print each record as it's being checked (optional)
- `-csv <file>`: Output results to CSV file (optional)
- `-json <file>`: Output results to JSON file (optional)

## Examples

### Basic usage (show only differences):

```bash
./dns-zone-verify -zone /path/to/zone.file -server 8.8.8.8
```

### Verbose mode (show all records being checked):

```bash
./dns-zone-verify -zone /path/to/zone.file -server 8.8.8.8 -verbose
```

### Check against local DNS server:

```bash
./dns-zone-verify -zone /etc/bind/db.example.com -server 192.168.1.10
```

## Supported Record Types

The tool supports all current DNS record types (obsolete types excluded):

**Common Records:**
- A, AAAA, CNAME, MX, NS, TXT, PTR, SRV, SOA

**DNSSEC Records:**
- DNSKEY, DS, RRSIG, NSEC, NSEC3, NSEC3PARAM, CDS, CDNSKEY

**Security & Authentication:**
- TLSA, SSHFP, CAA, OPENPGPKEY, CERT, KEY, SIG

**Infrastructure Records:**
- DNAME, HINFO, LOC, RT

**Email & Services:**
- SPF, NAPTR, KX, DHCID, SVCB, HTTPS, URI, TALINK, CSYNC, ZONEMD

**Zone Transfer Records:**
- AXFR, IXFR

**Other:**
- HIP, EUI48, EUI64

### Exit Codes

- `0`: All records matched successfully
- `1`: There were mismatches or errors

## Example Output

```
Loaded 12 records from zone file
Checking against DNS server: 8.8.8.8

Differences found:
--------------------------------------------------------------------------------
Record: example.com. NS
  Expected: ns1.example.com.
  Actual:   hera.ns.cloudflare.com.

Record: example.com. A
  Expected: 192.0.2.1
  Actual:   93.184.216.34

Record: mail.example.com. A 192.0.2.3
  Error: no records found

================================================================================
Summary:
  Total records checked: 12
  Matches: 9
  Mismatches: 2
  Errors: 1
================================================================================
```
