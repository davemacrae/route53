import boto3
import sys
import json
import socket

'''
    TODO: Compare current A record to MY_IP and only update if necessary
    TODO: Error handling
    TODO: Pass domain or IP as arguments
'''

def upsert (ip):


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
                                'Value': ip
                            }
                        ],
                        'TTL': 300,
                        'Type': 'A',
                    },
                },
            ],
            'Comment': 'Upserted'
        }

        # TODO: Make this an option
        print (f"Update {domain} to {ip}")

        upsert_response = client.change_resource_record_sets(ChangeBatch=changes, HostedZoneId=zone_id)

    return

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

    return list(map(lambda x: x[4][0], socket.getaddrinfo('{}.'.format(target),port,type=socket.SOCK_STREAM)))


if __name__ == '__main__':

    ip = get_ips_by_dns_lookup('macrae.zapto.org')[0]

    upsert (ip)
