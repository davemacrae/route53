#!/usr/bin/env python

# pylint: disable=consider-using-f-string
# pylint: disable=raise-missing-from

'''
    DONE: Compare current A record to MY_IP and only update if necessary
    DONE: Error handling
    DONE: Pass domain or IP as arguments
'''

import socket
import re
import argparse
import sys
import dns.resolver
import botocore
import boto3

def whatsmyip():
    ''' Get the current external IP'''
    # pylint: disable=used-before-assignment

    resolver = dns.resolver.Resolver(configure=False)

    resolver.nameservers = get_ips_by_dns_lookup('resolver1.opendns.com')
    domain_name = 'myip.opendns.com'

    # Use the resolver to perform a DNS lookup for the domain's IP address
    try:
        current_ip = resolver.resolve(domain_name)[0].address
    except dns.resolver.NXDOMAIN:
        print (f"Cannot resolve {domain_name}")
        sys.exit(-1)
    except (dns.resolver.LifetimeTimeout,
            dns.resolver.YXDOMAIN,
            dns.resolver.NoAnswer,
            dns.resolver.NoNameservers) as err:
        print("help, something went wrong:", err)

    if args.verbose:
        print (f"Current external IP is {current_ip}")

    return current_ip


def domain_check(domain):
    ''' Check that the format of the domain is correct'''
    pattern = re.compile(
        r'^(([a-zA-Z]{1})|([a-zA-Z]{1}[a-zA-Z]{1})|'
        r'([a-zA-Z]{1}[0-9]{1})|([0-9]{1}[a-zA-Z]{1})|'
        r'([a-zA-Z0-9][-_.a-zA-Z0-9]{0,61}[a-zA-Z0-9]))\.'
        r'([a-zA-Z]{2,13}|[a-zA-Z0-9-]{2,30}.[a-zA-Z]{2,3})$'
    )
    return pattern.match(domain)


def ip_check(ip_address):
    ''' Check that we have a valid IP address '''
    pattern = re.compile(r"^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$")

    if pattern.match(ip_address):
        ip_slice = ip_address.split(".")

        for ip_byte in ip_slice:
            if int(ip_byte) < 0 or int(ip_byte) > 255:
                return False
        return True

    return False


def process_arguments():
    ''' Process the command line arguments '''

    # Validation Methods
    class IPAction(argparse.Action):
        ''' This will raise an exception if the IP address supplied is not valid '''
        def __call__(self, parser, namespace, values, option_string=None):
            if not ip_check(values):
                raise argparse.ArgumentError(self, f"{values} is not a valid IP address")
            setattr(namespace, self.dest, values)

    class DomainAction(argparse.Action):
        ''' This will raise an exception if the domain supplied is not valid '''
        def __call__(self, parser, namespace, values, option_string=None):
            if not domain_check(values):
                raise argparse.ArgumentError(self, f"{values} is not a valid domain")
            setattr(namespace, self.dest, values)

    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--ip", action=IPAction, help="The IP address you want to use")
    group.add_argument("--domain", action=DomainAction,
                        help="The domain to retrieve the IP address from")
    parser.add_argument("--verbose", "--v", help="Verbose output", action="store_true")
    parser.add_argument("--dry-run", action="store_true",
                        help="Don't do anything, just print out proposed actions")
    return parser.parse_args()


def get_ips_by_dns_lookup(target, port=None):
    '''
        Credit: https://stackoverflow.com/users/9319317/eatsfood

        This function takes the passed target and optional port and does a dns
        lookup. it returns the ips that it finds to the caller.

        :param target:  the URI that you'd like to get the ip address(es) for
        :type target:   string
        :param port:    which port do you want to do the lookup against?
        :type port:     integer
        :returns ips:   all of the discovered ips for the target
        :rtype ips:     list of strings

    '''

    if not port:
        port = 443

    if args.verbose:
        print (f"Look up IP address for {target}")

    try:
        ips = list(map(lambda x: x[4][0],
                       socket.getaddrinfo('{}.'.format(target),port,type=socket.SOCK_STREAM)))
    except socket.gaierror:
        print (f"Invalid Domain: {target}")
        sys.exit(-1)

    return ips

def boto_error_dump (err):
    ''' Function to dump error from a BOTO call '''
    if err.response['Error']['Code'] == 'InternalError': # Generic error
        # We grab the message, request ID, and HTTP code to give to customer support
        print('Error Message: {}'.format(err.response['Error']['Message']))
        print('Request ID: {}'.format(err.response['ResponseMetadata']['RequestId']))
        print('Http code: {}'.format(err.response['ResponseMetadata']['HTTPStatusCode']))
    else:
        raise err


def upsert (ip_address):
    ''' Main Programme '''
    client = boto3.client('route53')

    try:
        response = client.get_hosted_zone_count()

    except botocore.exceptions.NoCredentialsError as err:
        print (f"BOTO Error: Invalid credentials: {err}")
        exit(-1)
    except botocore.exceptions.ClientError as err:
        boto_error_dump(err)

    # How many hosted zones do we need to update
    num_zones = response['HostedZoneCount']

    # Check that we have some hosted zones
    if num_zones == 0:
        print ("Can't find any configured Hosted Zones")
        return

    zones = client.list_hosted_zones()

    # get the IP external IP address of our router
    router_ip = whatsmyip()

    for i in range(num_zones):
        # The Id string is /hosted/XXXXXXXXXXX but we only need the XXXXXXXXXXX part
        zone_id = zones['HostedZones'][i]['Id'].split('/')[2]
        # This gives us the base domain name with a trailing "." which we remove
        domain = zones['HostedZones'][i]['Name'][:-1]

        # We only want to make changes where the IP address of the A record doesn't match so
        # lets find out the current domain A record IP address and compare it the router IP.
        domain_ip = get_ips_by_dns_lookup(domain)[0]
        if args.verbose:
            print (f"Current ip of {domain} is {domain_ip}")

        if domain_ip == router_ip:
            if args.verbose:
                print (f"No update needed for {domain}")
            continue

        changes = {
            'Changes': [
                {
                    'Action': 'UPSERT',
                    'ResourceRecordSet': {
                        'Name': domain,
                        'ResourceRecords': [
                            {
                                'Value': ip_address
                            }
                        ],
                        'TTL': 300,
                        'Type': 'A',
                    },
                },
            ],
            'Comment': 'Upserted'
        }

        if args.verbose:
            print (f"Update {domain} to {ip_address}")

        if args.dry_run:
            print (f"DRY-RUN: Update {domain} to {ip_address}")
        else:
            try:
                client.change_resource_record_sets(ChangeBatch=changes, HostedZoneId=zone_id)
            except botocore.exceptions.ClientError as err:
                boto_error_dump(err)
    return

if __name__ == '__main__':

    args = process_arguments()

    if args.ip:
        ip = args.ip
    else:
        ip = get_ips_by_dns_lookup(args.domain)[0]

    upsert (ip)
