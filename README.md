# Introduction

NSE script using the Censys Search API, allowing you to passively gather information about hosts.

## Installation

Simple place the censys-api.nse script into your nmap scripts folder. e.g:

```sh
cp censys-api.nse /usr/share/nmap/scripts/
```

If `nmap` is installed on macOS via [Homebrew](https://brew.sh/), the scripts folder might instead be located at `/usr/local/share/nmap/scripts/`.

```sh
cp censys-api.nse /usr/local/share/nmap/scripts/
```

## Usage

Invoke the script like you would any other NSE script:

```sh
nmap -sn -Pn -n --script censys-api scanme.nmap.org
```

### API Keys

The Censys API ID and secret can be set with the `apiid` and `apisecret` script arguments, `CENSYS_API_ID` and `CENSYS_API_SECRET` environment variables, or hardcoded in the .nse file itself. You can get free API credentials from <https://search.censys.io/account/api>.

### Saving to a File

The results can be written to file with the outfile script argument `censys-api.outfile`.

### Warning

nmap will still scan the target host normally. If you only want to look up the target in Censys you need to include the `-sn -Pn -n` flags.

## Example Output

```sh
$ nmap -sn -Pn -n --script censys-api scanme.nmap.org
Starting Nmap 7.92 ( https://nmap.org ) at 2021-12-03 12:02 EST
Nmap scan report for scanme.nmap.org (45.33.32.156)
Host is up.

Host script results:
| censys-api: Report for 45.33.32.156 ()
| PORT  PROTO  SERVICE  PRODUCT  VERSION
| 22    TCP    SSH      OpenSSH  6.6.1p1
| 80    TCP    HTTP     HTTPD    2.4.7
| 123   UDP    NTP               
|_9929  TCP    UNKNOWN           

Post-scan script results:
|_censys-api: Censys done: 1 hosts up.
Nmap done: 1 IP address (1 host up) scanned in 0.67 seconds
```

## Help

    nmap --script-help censys-api.nse
