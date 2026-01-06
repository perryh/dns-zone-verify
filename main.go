package main

import (
	"bufio"
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/miekg/dns"
)

type Record struct {
	Name  string
	Type  string
	Value string
	TTL   uint32
}

type Result struct {
	Record     Record
	Expected   string
	Actual     string
	Match      bool
	QueryError error
}

var (
	zoneFile   = flag.String("zone", "", "Path to BIND zone file")
	server     = flag.String("server", "", "DNS server IP address")
	verbose    = flag.Bool("verbose", false, "Print each record checked")
	csvOutput  = flag.String("csv", "", "Output results to CSV file")
	jsonOutput = flag.String("json", "", "Output results to JSON file")
)

func main() {
	flag.Parse()

	if *zoneFile == "" || *server == "" {
		fmt.Println("Usage: dns-zone-checker -zone <zone-file> -server <dns-server-ip> [-verbose]")
		flag.PrintDefaults()
		os.Exit(1)
	}

	records, err := parseZoneFile(*zoneFile)
	if err != nil {
		fmt.Printf("Error parsing zone file: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Loaded %d records from zone file\n", len(records))
	fmt.Printf("Checking against DNS server: %s\n\n", *server)

	results := checkRecords(records)

	printResults(results)
	printSummary(results)

	if *csvOutput != "" {
		if err := exportToCSV(results, *csvOutput); err != nil {
			fmt.Printf("Error writing CSV file: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("\nCSV output written to: %s\n", *csvOutput)
	}

	if *jsonOutput != "" {
		if err := exportToJSON(results, *jsonOutput); err != nil {
			fmt.Printf("Error writing JSON file: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("JSON output written to: %s\n", *jsonOutput)
	}
}

func parseZoneFile(path string) ([]Record, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var records []Record
	var origin string
	var defaultTTL uint32 = 3600

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()

		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, ";") || strings.HasPrefix(line, "//") {
			continue
		}

		if strings.HasPrefix(line, "$ORIGIN") {
			parts := strings.Fields(line)
			if len(parts) > 1 {
				origin = dns.Fqdn(parts[1])
			}
			continue
		}

		if strings.HasPrefix(line, "$TTL") {
			parts := strings.Fields(line)
			if len(parts) > 1 {
				fmt.Sscanf(parts[1], "%d", &defaultTTL)
			}
			continue
		}

		if !strings.ContainsAny(line, " \t") {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}

		var name, recordType, value string
		var ttl uint32
		var idx int

		if strings.Contains(fields[0], "@") || fields[0] == origin {
			name = origin
			idx = 1
		} else {
			name = fields[0]
			if !strings.HasSuffix(name, ".") && origin != "" {
				name = name + "." + origin
			}
			idx = 1
		}

		if _, err := fmt.Sscanf(fields[idx], "%d", &ttl); err == nil {
			idx++
		} else {
			ttl = defaultTTL
		}

		class := strings.ToUpper(fields[idx])
		if class == "IN" || class == "CH" || class == "HS" {
			idx++
		}

		recordType = strings.ToUpper(fields[idx])
		idx++

		if idx < len(fields) {
			value = strings.Join(fields[idx:], " ")
			if !strings.HasSuffix(value, ".") && (recordType == "CNAME" || recordType == "NS" || recordType == "MX") && origin != "" {
				value = value + "." + origin
			}
		}

		if isSupportedRecordType(recordType) {
			records = append(records, Record{
				Name:  dns.Fqdn(name),
				Type:  recordType,
				Value: value,
				TTL:   ttl,
			})
		}
	}

	return records, scanner.Err()
}

func isSupportedRecordType(recordType string) bool {
	supportedTypes := map[string]bool{
		"A": true, "AAAA": true, "CNAME": true, "MX": true,
		"NS": true, "TXT": true, "PTR": true, "SRV": true,
		"SOA": true, "DNSKEY": true, "DS": true, "RRSIG": true,
		"NSEC": true, "NSEC3": true, "NSEC3PARAM": true, "TLSA": true,
		"SSHFP": true, "CAA": true, "DNAME": true, "HINFO": true,
		"LOC": true, "RT": true, "SIG": true, "KEY": true,
		"SPF": true, "NAPTR": true, "KX": true, "CERT": true,
		"DHCID": true, "HIP": true, "TALINK": true, "CDS": true,
		"CDNSKEY": true, "OPENPGPKEY": true, "CSYNC": true,
		"ZONEMD": true, "SVCB": true, "HTTPS": true, "EUI48": true,
		"EUI64": true, "URI": true, "AXFR": true, "IXFR": true,
	}
	return supportedTypes[recordType]
}

func exportToCSV(results []Result, filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	header := []string{"Name", "Type", "Expected", "Actual", "Match", "Error"}
	if err := writer.Write(header); err != nil {
		return err
	}

	for _, result := range results {
		match := "false"
		if result.Match {
			match = "true"
		}

		errorMsg := ""
		if result.QueryError != nil {
			errorMsg = result.QueryError.Error()
		}

		record := []string{
			result.Record.Name,
			result.Record.Type,
			result.Expected,
			result.Actual,
			match,
			errorMsg,
		}

		if err := writer.Write(record); err != nil {
			return err
		}
	}

	return nil
}

func exportToJSON(results []Result, filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")

	return encoder.Encode(results)
}

func checkRecords(records []Record) []Result {
	var results []Result

	for _, record := range records {
		if *verbose {
			fmt.Printf("Checking: %s %s %s\n", record.Name, record.Type, record.Value)
		}

		result := checkRecord(record)
		results = append(results, result)

		if *verbose {
			if result.QueryError != nil {
				fmt.Printf("  -> Query error: %v\n", result.QueryError)
			} else if result.Match {
				fmt.Printf("  -> OK\n")
			} else {
				fmt.Printf("  -> MISMATCH\n")
			}
		}
	}

	return results
}

func checkRecord(record Record) Result {
	result := Result{
		Record:   record,
		Expected: record.Value,
	}

	c := new(dns.Client)
	m := new(dns.Msg)

	recordType := recordTypeToUint16(record.Type)
	m.SetQuestion(record.Name, recordType)
	m.RecursionDesired = true

	r, _, err := c.Exchange(m, *server+":53")
	if err != nil {
		result.QueryError = err
		return result
	}

	if len(r.Answer) == 0 {
		result.QueryError = fmt.Errorf("no records found")
		return result
	}

	found := false
	for _, ans := range r.Answer {
		if ans.Header().Rrtype == recordType {
			value := recordValueToString(ans)
			result.Actual = value

			if normalizeValue(record.Type, record.Value) == normalizeValue(record.Type, value) {
				result.Match = true
				found = true
				break
			}
		}
	}

	if !found {
		result.Match = false
	}

	return result
}

func recordTypeToUint16(recordType string) uint16 {
	types := map[string]uint16{
		"A":          dns.TypeA,
		"AAAA":       dns.TypeAAAA,
		"CNAME":      dns.TypeCNAME,
		"MX":         dns.TypeMX,
		"NS":         dns.TypeNS,
		"TXT":        dns.TypeTXT,
		"PTR":        dns.TypePTR,
		"SRV":        dns.TypeSRV,
		"SOA":        dns.TypeSOA,
		"DNSKEY":     dns.TypeDNSKEY,
		"DS":         dns.TypeDS,
		"RRSIG":      dns.TypeRRSIG,
		"NSEC":       dns.TypeNSEC,
		"NSEC3":      dns.TypeNSEC3,
		"NSEC3PARAM": dns.TypeNSEC3PARAM,
		"TLSA":       dns.TypeTLSA,
		"SSHFP":      dns.TypeSSHFP,
		"CAA":        dns.TypeCAA,
		"DNAME":      dns.TypeDNAME,
		"HINFO":      dns.TypeHINFO,
		"LOC":        dns.TypeLOC,
		"RT":         dns.TypeRT,
		"SIG":        dns.TypeSIG,
		"KEY":        dns.TypeKEY,
		"SPF":        dns.TypeSPF,
		"NAPTR":      dns.TypeNAPTR,
		"KX":         dns.TypeKX,
		"CERT":       dns.TypeCERT,
		"DHCID":      dns.TypeDHCID,
		"HIP":        dns.TypeHIP,
		"TALINK":     dns.TypeTALINK,
		"CDS":        dns.TypeCDS,
		"CDNSKEY":    dns.TypeCDNSKEY,
		"OPENPGPKEY": dns.TypeOPENPGPKEY,
		"CSYNC":      dns.TypeCSYNC,
		"ZONEMD":     dns.TypeZONEMD,
		"SVCB":       dns.TypeSVCB,
		"HTTPS":      dns.TypeHTTPS,
		"EUI48":      dns.TypeEUI48,
		"EUI64":      dns.TypeEUI64,
		"URI":        dns.TypeURI,
		"AXFR":       dns.TypeAXFR,
		"IXFR":       dns.TypeIXFR,
		"ANY":        dns.TypeANY,
	}
	return types[recordType]
}

func recordValueToString(rr dns.RR) string {
	switch r := rr.(type) {
	case *dns.A:
		return r.A.String()
	case *dns.AAAA:
		return r.AAAA.String()
	case *dns.CNAME:
		return dns.Fqdn(r.Target)
	case *dns.MX:
		return fmt.Sprintf("%d %s", r.Preference, dns.Fqdn(r.Mx))
	case *dns.NS:
		return dns.Fqdn(r.Ns)
	case *dns.TXT:
		return strings.Join(r.Txt, " ")
	case *dns.PTR:
		return dns.Fqdn(r.Ptr)
	case *dns.SRV:
		return fmt.Sprintf("%d %d %d %s", r.Priority, r.Weight, r.Port, dns.Fqdn(r.Target))
	case *dns.SOA:
		return fmt.Sprintf("%s %s %d %d %d %d %d", dns.Fqdn(r.Ns), dns.Fqdn(r.Mbox), r.Serial, r.Refresh, r.Retry, r.Expire, r.Minttl)
	case *dns.DNSKEY:
		return fmt.Sprintf("%d %d %d %s", r.Flags, r.Protocol, r.Algorithm, r.PublicKey)
	case *dns.DS:
		return fmt.Sprintf("%d %d %d %s", r.KeyTag, r.Algorithm, r.DigestType, r.Digest)
	case *dns.RRSIG:
		return fmt.Sprintf("%d %d %d %d %d %d %d %s %s", r.TypeCovered, r.Algorithm, r.Labels, r.OrigTtl, r.Expiration, r.Inception, r.KeyTag, dns.Fqdn(r.SignerName), r.Signature)
	case *dns.NSEC:
		return fmt.Sprintf("%s %s", dns.Fqdn(r.NextDomain), r.TypeBitMap)
	case *dns.NSEC3:
		return rr.String()
	case *dns.NSEC3PARAM:
		return rr.String()
	case *dns.TLSA:
		return rr.String()
	case *dns.SSHFP:
		return fmt.Sprintf("%d %d %s", r.Algorithm, r.Type, r.FingerPrint)
	case *dns.CAA:
		return fmt.Sprintf("%d %s \"%s\"", r.Flag, r.Tag, r.Value)
	case *dns.DNAME:
		return dns.Fqdn(r.Target)
	case *dns.HINFO:
		return fmt.Sprintf("%s %s", r.Cpu, r.Os)
	case *dns.LOC:
		return rr.String()
	case *dns.RT:
		return fmt.Sprintf("%d %s", r.Preference, dns.Fqdn(r.Host))
	case *dns.SIG:
		return fmt.Sprintf("%d %d %d %d %d %d %d %s %s", r.TypeCovered, r.Algorithm, r.Labels, r.OrigTtl, r.Expiration, r.Inception, r.KeyTag, dns.Fqdn(r.SignerName), r.Signature)
	case *dns.KEY:
		return fmt.Sprintf("%d %d %d %s", r.Flags, r.Protocol, r.Algorithm, r.PublicKey)
	case *dns.SPF:
		return strings.Join(r.Txt, " ")
	case *dns.NAPTR:
		return fmt.Sprintf("%d %d \"%s\" \"%s\" \"%s\" %s", r.Order, r.Preference, r.Flags, r.Service, r.Regexp, dns.Fqdn(r.Replacement))
	case *dns.KX:
		return fmt.Sprintf("%d %s", r.Preference, dns.Fqdn(r.Exchanger))
	case *dns.CERT:
		return fmt.Sprintf("%d %d %d %s", r.Type, r.KeyTag, r.Algorithm, r.Certificate)
	case *dns.DHCID:
		return rr.String()
	case *dns.HIP:
		return rr.String()
	case *dns.TALINK:
		return fmt.Sprintf("%s %s", dns.Fqdn(r.NextName), dns.Fqdn(r.PreviousName))
	case *dns.CDS:
		return fmt.Sprintf("%d %d %d %s", r.KeyTag, r.Algorithm, r.DigestType, r.Digest)
	case *dns.CDNSKEY:
		return fmt.Sprintf("%d %d %d %s", r.Flags, r.Protocol, r.Algorithm, r.PublicKey)
	case *dns.OPENPGPKEY:
		return r.PublicKey
	case *dns.CSYNC:
		return fmt.Sprintf("%d %d %s", r.Serial, r.Flags, r.TypeBitMap)
	case *dns.ZONEMD:
		return rr.String()
	case *dns.SVCB:
		return rr.String()
	case *dns.HTTPS:
		return rr.String()
	case *dns.EUI48:
		return rr.String()
	case *dns.EUI64:
		return rr.String()
	case *dns.URI:
		return fmt.Sprintf("%d %d %s", r.Priority, r.Weight, r.Target)
	default:
		return rr.String()
	}
}

func normalizeValue(recordType, value string) string {
	value = strings.TrimSpace(value)
	value = strings.Trim(value, `"`)
	if recordType != "A" && recordType != "AAAA" {
		value = dns.Fqdn(value)
	}
	return value
}

func printResults(results []Result) {
	hadDifferences := false
	for _, result := range results {
		if !result.Match && result.QueryError == nil {
			if !hadDifferences {
				fmt.Println("Differences found:")
				fmt.Println(strings.Repeat("-", 80))
				hadDifferences = true
			}
			fmt.Printf("Record: %s %s\n", result.Record.Name, result.Record.Type)
			fmt.Printf("  Expected: %s\n", result.Expected)
			fmt.Printf("  Actual:   %s\n\n", result.Actual)
		} else if result.QueryError != nil {
			if !hadDifferences {
				fmt.Println("Errors:")
				fmt.Println(strings.Repeat("-", 80))
				hadDifferences = true
			}
			fmt.Printf("Record: %s %s %s\n", result.Record.Name, result.Record.Type, result.Expected)
			fmt.Printf("  Error: %v\n\n", result.QueryError)
		}
	}
}

func printSummary(results []Result) {
	total := len(results)
	matches := 0
	mismatches := 0
	errors := 0

	for _, result := range results {
		if result.Match {
			matches++
		} else if result.QueryError != nil {
			errors++
		} else {
			mismatches++
		}
	}

	fmt.Println("\n" + strings.Repeat("=", 80))
	fmt.Println("Summary:")
	fmt.Printf("  Total records checked: %d\n", total)
	fmt.Printf("  Matches: %d\n", matches)
	fmt.Printf("  Mismatches: %d\n", mismatches)
	fmt.Printf("  Errors: %d\n", errors)
	fmt.Println(strings.Repeat("=", 80))

	if mismatches > 0 || errors > 0 {
		os.Exit(1)
	}
}
