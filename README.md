# Introduction

NSE script using the Censys IPv4 API, allowing you to passively gather information about hosts.

# Installation

Simple place the censys-api.nse script into your nmap scripts folder. e.g:

	cp censys-api.nse /usr/share/nmap/scripts/

# Usage

Invoke the script like you would any other NSE script:

	nmap  -sn -Pn -n  --script censys-api  scanme.nmap.org


## API Keys

The Censys API ID and secret can be set with the `apiid` and `apisecret` script arguments, `CENSYS_API_ID` and `CENSYS_API_SECRET` environment variables, or hardcoded in the .nse file itself. You can get free API credentials from https://censys.io/api . 

## Saving to a File

The results can be written to file with the outfile script argument `censys-api.outfile`. 

## Warning

nmap will still scan the target host normally. If you only want to look up the target in Shodan you need to include the `-sn -Pn -n` flags.


# Example Output

	Starting Nmap 7.70 ( https://nmap.org ) at 2019-01-12 07:28 EST
	Nmap scan report for scanme.nmap.org (45.33.32.156)
	Host is up.
	Other addresses for scanme.nmap.org (not scanned): 2600:3c01::f03c:91ff:fe18:bb2f

	Host script results:
	| censys-api: Report for 45.33.32.156 ()
	| PORT  PROTO  PRODUCT  VERSION
	| 80    http   httpd    2.4.7
	|_22    ssh    OpenSSH  6.6.1p1

	Post-scan script results:
	|_censys-api: Censys done: 1 hosts up.
	Nmap done: 1 IP address (1 host up) scanned in 1.35 seconds

# Help

	nmap --script-help censys-api.nse
