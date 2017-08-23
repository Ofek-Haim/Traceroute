"""
This code was written by Ofek Haim
           22.8.2017
"""
from scapy.all import *
from scapy.layers.inet import *
import argparse
import os
import urllib2

INPUT_ERROR_MESSAGE = "Input error - Try -ipaddress 8.8.8.8"
INTERNET_CONNECTION_ERROR_MESSAGE = "Internet connection does not exist"
ARGPARSE_HELP = "Enter an ip address"
TIMEOUT_FOR_HOP = 5
DOMAIN_FOR_CHECKING_A_NETWORK_CONNECTION = 'http://www.google.com'
CHECKING_A_NETWORK_CONNECTION_TIMEOUT = 5
CLS = "clear"
DESCRIPTION_LIST_A = "The list of the hops to : "
DESCRIPTION_LIST_B = " is : "
PARAM_TYPE = '-ipaddress'


def argparse_input():
    """
    This func get input from the client by argparse.
    :return:
    """
    parser = argparse.ArgumentParser()
    parser.add_argument(PARAM_TYPE, help=ARGPARSE_HELP)
    args = parser.parse_args()
    return args


def validate_ip(s):
    """
    This func get string and return
    True if the string is a legal.
    :param s: string.
    :return: True or False.
    """
    a = s.split('.')
    if len(a) != 4:
        return False
    for x in a:
        if not x.isdigit():
            return False
        i = int(x)
        if i < 0 or i > 255:
            return False
    return True


def hopes_list_by_ip(ip_from_c):
    """
    This Func get ip from the client and return
    list whit all the hops all the way to the dst.
    :param ip_from_c: The ip from the client.
    :return: List of hops all the way to the dst.
    """
    ip_list = []
    req_packet = IP() / ICMP()
    req_packet[IP].dst = ip_from_c
    check_ip = True
    ttl = 1
    req_packet[IP].ttl = ttl
    while check_ip:
        req = sr1(req_packet, timeout=TIMEOUT_FOR_HOP)
        if not req:
            ttl += 1
            req_packet[IP].ttl = ttl
        else:
            ttl += 1
            req_packet[IP].ttl = ttl
            if req[IP].src == ip_from_c:
                check_ip = False
                ip_list.append(ip_from_c)
            else:
                ip_list.append(req[IP].src)
    return ip_list


def internet_connection():
    try:
        urllib2.urlopen('http://216.58.192.142', timeout=1)
    except urllib2.URLError:
        sys.exit(INTERNET_CONNECTION_ERROR_MESSAGE)


__author__ = 'Ofek Haim'


def main():
    ipaddress = argparse_input().ipaddress
    print ipaddress
    if validate_ip(ipaddress):
        ip_list = hopes_list_by_ip(ipaddress)
        os.system(CLS)
        print DESCRIPTION_LIST_A + str(ipaddress) + DESCRIPTION_LIST_B + str(ip_list)
    else:
        sys.exit(INPUT_ERROR_MESSAGE)


if __name__ == '__main__':
    main()
