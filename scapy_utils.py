# coding=utf-8

"""
    A collection of utility function for use with Scapy module.

    ~ CodesWhite (aka WhiteCode) @ 2017
"""

from time import sleep
from typing import Optional


# Load Scapy
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)  # Quiet mode ;)
try:
    from scapy.sendrecv import sendp, srp, conf  # Try to load scapy
    from scapy.layers.l2 import Ether, ARP, get_if_hwaddr, get_if_addr
except ModuleNotFoundError:
    raise ImportError('Scapy module could not be loaded!')


def unpack_iface(iface: str) -> tuple:
    """ Return tuple(IP: str, MAC: str) """
    return get_if_addr(iface), get_if_hwaddr(iface)


def get_gw() -> tuple:
    """ Return tuple(gateway_IP: IPv4Addreess, gateway_MAC: str) """
    gw_ip, iface = [x for x in conf.route.routes if x[2] != '0.0.0.0'][0][2:4]
    resp = arp_request(unpack_iface(iface), gw_ip)
    if not resp:
        # prl('No ARP response received from supposed gateway!!', PRL_ERR)
        # exit(5)
        raise TimeoutError('No ARP response received from supposed gateway!')
    return gw_ip, resp


def arp_response(src, src_mac, dst, dst_mac, count=3, interval=0.1) -> None:
    """ Sends an ARP response """
    for i in range(count):
        sendp(Ether(dst=dst_mac, src=src_mac) /
              ARP(op="is-at", hwsrc=src_mac, psrc=src, hwdst=dst_mac, pdst=dst),
              verbose=False)
        if interval > 0:
            sleep(interval)


def arp_request(unpack_iface: tuple, dst: str, retry=2, timeout=1) -> Optional[str]:
    """ Sends an ARP request and returns target's MAC address """
    local_ip, local_mac = unpack_iface
    rsp = srp(Ether(dst='ff:ff:ff:ff:ff:ff', src=local_mac) /
              ARP(hwsrc=local_mac, psrc=local_ip,
                  hwdst='ff:ff:ff:ff:ff:ff', pdst=dst),
              timeout=timeout, retry=retry, verbose=False)
    if not rsp[0]:
        return None
    return rsp[0][0][1]['ARP'].hwsrc
