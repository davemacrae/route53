#!/usr/bin/python
'''
    TODO: Compare current A record to MY_IP and only update if necessary
    TODO: Error handling
    DONE: Pass domain or IP as arguments
'''

import socket
import re
import argparse
import boto3

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

    return list(map(lambda x: x[4][0],
                    socket.getaddrinfo('{}.'.format(target),port,type=socket.SOCK_STREAM)))


def upsert (ip_address):
    ''' Main Programme '''
    client = boto3.client('route53')

    response = client.get_hosted_zone_count()

    # How many hosted zones do we need to update
    num_zones = response['HostedZoneCount']

    zones = client.list_hosted_zones()

    for i in range(num_zones):
        # The Id string is /hosted/XXXXXXXXXXX but we only need the XXXXXXXXXXX part
        zone_id = zones['HostedZones'][i]['Id'].split('/')[2]
        # This gives us the base domain name with a trailing "." which we remove
        domain = zones['HostedZones'][i]['Name'][:-1]

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
            print (f"Update {domain} to {ip}")

        if args.dry_run:
            print (f"DRY-RUN: Update {domain} to {ip}")
        else:
            # TODO: Error handling
            client.change_resource_record_sets(ChangeBatch=changes, HostedZoneId=zone_id)



if __name__ == '__main__':

    args = process_arguments()

    if args.ip:
        ip = args.ip
    else:
        """
            TODO: We should move this to the domain validator function to check that it
            is a valid domain
        """
        ip = get_ips_by_dns_lookup(args.domain)[0]

    upsert (ip)
