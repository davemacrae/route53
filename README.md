# route53

## About

I recently moved Internet providers from VirginMedia to Vodafone in the UK.

One difference I've found is that the Vodafone router will get a new IP every time it's rebooted. As I host a number of hobby sites locally this can cause a bit of an issue.

I host my DNS at AWS using Route53 which, fortunately, has a pretty good API.

I also have Dynamic DNS set up with no-ip.com, using their free tier to give me a single IP host name.

My Vodafone router has a DDNS client for no-ip.com and will update the record whenever it reboots.

This script is designed to grab that IP and update the A record of all my domains.
