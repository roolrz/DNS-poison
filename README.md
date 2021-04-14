# DNS poison tool

## Prerequisite:

 - github.com/google/gopacket

This can be installed by `$ go get github.com/google/gopacket`

## Build:

After installed the required package, run `$ go build` to generate the binary executable file, administrator's permission is required to run this.

## Usage:

 - -i  Specify the network interface name (e.g., enp0s3). If not specified, dnspoison would automatically select a default interface

 - -f  Specify the config file. DNS poison would read lines of IP address and it's domain name. If not specified, all domains would be direct to the attacter's IP. If specified, all domains out of the file would be ignored (would not be spoofed). example file domain.list is in examples

 - Extra arguments would be treated as BPF filter. Error would be raised if there's syntax error in the BPF expression

## Performance:
About 8ms-22ms delay (depending on system load), would win the race in most cases if the DNS server is outside LAN. Tested under Windows hosted VMware Workstation, with Intel Core i5 processor, guest OS is Debian buster, golang version 1.11.

## Implementation:
Used raw socket, the spoofing is begin from data link layer (layer 2), hence this program would use spoofed source MAC address and spoofed source IP address.

## Examples:
`$ sudo ./dnspoison [-f domain.list] [-i iFaceName] [filters]`

### Example file of domain.list
```
1.1.1.1        foo.example.com
2.2.2.2        bar.example.com
```
in the example file, foo.example.com would be directed to 1.1.1.1, and bar.example.com would be directed to 2.2.2.2. Domain names outside the file would be ignored.
