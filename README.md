# route53

## About

I recently moved Internet providers from VirginMedia to Vodafone in the UK.

One difference I've found is that the Vodafone router will get a new IP every time it's rebooted. As I host a number of hobby sites locally this can cause a bit of an issue.

I host my DNS at AWS using Route53 which, fortunately, has a pretty good API.

I also have Dynamic DNS set up with no-ip.com, using their free tier to give me a single IP host name.

My Vodafone router has a DDNS client for no-ip.com and will update the record whenever it reboots.

This script is designed to grab that IP and update the A record of all my domains.

Note, because this uses the "upsert" command the script will create an A record is one does not exist.

## Usage

    usage: upsert.py [-h] (--ip IP | --domain DOMAIN) [--verbose] [--dry-run]

    options:
    -h, --help       show this help message and exit
    --ip IP          The IP address you want to use
    --domain DOMAIN  The domain to retrieve the IP address from
    --verbose, --v   Verbose output
    --dry-run        Don't do anything, just print out proposed actions

You must supply either an IP address to use or a domain to copy the IP address from.

## ToDo

TODO: Compare current A record to MY_IP and only update if necessary<br>
TODO: ~~Error handling~~<br>
TODO: ~~Pass domain or IP as arguments~~<br>
