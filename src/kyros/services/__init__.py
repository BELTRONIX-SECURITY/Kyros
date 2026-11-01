"""Registro de servicios. Para añadir uno nuevo: crea el módulo y agrégalo a ALL_SERVICES."""

from kyros.services.dns_lookup import DnsLookup
from kyros.services.emailrep import EmailRep
from kyros.services.gravatar import Gravatar
from kyros.services.hibp import HaveIBeenPwned
from kyros.services.hunter import Hunter
from kyros.services.ipapi import IpApi

ALL_SERVICES = [DnsLookup, IpApi, Gravatar, EmailRep, Hunter, HaveIBeenPwned]
