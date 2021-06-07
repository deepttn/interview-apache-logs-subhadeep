#!/usr/bin/env python

import time
import random
import argparse
import logging

class Generate:

    def __init__(self,file):
        self.logfile = open(file,'a')
        self.logformat = "%(remote_host)s %(rfc931)s %(authuser)s [%(date)s] \"%(request)s\" %(status_code)s %(bytes)s \"%(referer)s\" \"%(user_agent)s\"\n"

    """
    Returns a random host from the
    list of valid remote hosts
    """
    def remote_host(self):
        # Generic and valid remote hosts
        hosts = [
            '127.0.0.1',
            'example.com',
            'localhost'
        ]
        return random.choice(hosts)

    """
    Placeholder function to return the remote
    logname of the user. Currently returns '-'
    """
    def rfc931(self):
        return '-'

    """
    Placeholder function to return the username as which the
    user has authenticated as. Currently returns '-'
    """
    def authuser(self):
        return '-'

    """
    Returns the current time in
    the HTTP log time format
    """
    def date(self):
        return time.strftime("%d/%b/%Y:%H:%M:%S +0000")

    def type(self):
        types = ['GET','POST']
        return random.choice(types)

    """
    Returns a random request from a list of sample requests
    """
    def request(self):
        requests = [
            '/api/create',
            '/api/delete/1234',
            '///',
            '/pages/create/',
            '/pics/1.jpg',
            '/pics/2.jpg',
            '/Pics/3.jpg',
            '/media//1.ts',
            '/media/media%201.ts',
        ]
        return "%s %s HTTP/1.1" % (self.type(),random.choice(requests))

    """
    Returns a status code between 100 and 599
    """
    def status_code(self):
        return random.randint(100,599)

    """
    Returns a random number of bytes
    """
    def bytes(self):
        return random.randint(100,9999999)

    """
    Returns a random referer from the list
    """
    def referer(self):
        referers = [
            '-',
            'http://mail.google.com/'
        ]
        return random.choice(referers)

    """
    Returns a random user agent from the list
    """
    def user_agent(self):
        user_agents = [
            '-',
            'Mozilla/4.0 (compatible; ms-office; MSOffice 16)',
            'Mozilla/5.0 (Windows NT 5.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.90 Safari/537.36',
            'Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 10.0; WOW64; Trident/7.0; .NET4.0C; .NET4.0E; .NET CLR 2.0.50727; .NET CLR 3.0.30729; .NET CLR 3.5.30729; InfoPath.3; Zoom 3.6.0; Zoom 3.6.0; Microsoft Outlook 15.0.5337; Microsoft Outlook 15.0.5337; ms-office; MSOffice 15)'
        ]
        return random.choice(user_agents)

    """
    Requests the random data and puts it into
    """
    def make_log_line(self):
        log_data = {
            'remote_host':self.remote_host(),
            'rfc931':self.rfc931(),
            'authuser':self.authuser(),
            'date':self.date(),
            'request':self.request(),
            'status_code':self.status_code(),
            'bytes':self.bytes(),
            'referer':self.referer(),
            'user_agent':self.user_agent(),
        }
        line = self.logformat % log_data
        logging.debug("Generated a line with the following data: %s" % line)
        return line

    """
    Writes to a logfile
    """
    def write_to_log(self,line):
        logging.info("Writing to logfile: \n%s" % line)
        self.logfile.write(line)
        self.logfile.flush()

def init():
    # Parse the arguments
    parser = argparse.ArgumentParser(
        description="Generates test logfile",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument('-f', '--file',  help='log file to generate', required=True)
    parser.add_argument('-v', '--verbose', help='show verbose output', action="store_true")
    parser.add_argument('--aggressive', help='generate logs at a faster rate', action="store_true")
    args = parser.parse_args()

    # If verbose is enabled, enable debug logging
    if args.verbose:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)
    logging.debug("File to generate set to: %s" % args.file)
    return args

args = init()
generator = Generate(args.file)
run_forever = True
divisor=1
if args.aggressive is True:
    divisor=10
while run_forever:
    generator.write_to_log(generator.make_log_line())
    time.sleep(random.randint(1,10)/divisor)
