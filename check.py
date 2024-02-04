import joblib

from ipaddress import ip_address
from urllib.parse import urlparse
import ssl
import socket
import whois
from datetime import datetime

import requests
requests.packages.urllib3.disable_warnings()
from urllib.request import urlopen
from bs4 import BeautifulSoup
import re

from termcolor import colored, cprint


COLORED = {
    -1: colored('NO', 'green'),
    0: colored('MAYBE', 'yellow'), 
    1: colored('YES', 'red'),
}
SHORTENING_SERVICES = {'bit.ly', 'tinyurl.com'}


def verify_ssl_certificate(hostname):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                ssock.do_handshake()
                cert = ssock.getpeercert()
                return -1
    except:
        return 1


def days_to_domain_expire(domain):
    now = datetime.now()
    w = whois.whois(domain)

    if type(w.expiration_date) == list:
        w.expiration_date = w.expiration_date[0]
    else:
        w.expiration_date = w.expiration_date
    timedelta = w.expiration_date - now
    days_to_expire = timedelta.days
    return days_to_expire


def check_favicon(soup, netloc):
    links = soup.findAll('link')
    if not links:
        return -1
    mismatch = 0
    for link in links:
        if 'rel' in link and 'href' in link:
            if link['rel'] == 'icon':
                src = urlparse(link.href['href'])
                if src.netloc != netloc:
                    mismatch += 1
    return mismatch > 0 and 1 or - 1


def check_iframe(soup):
    iframes = soup.findAll('iframe')
    if not iframes:
        return -1
    mismatch = 0
    for iframe in iframes:
        if 'frameborder' in iframe:
            mismatch += 1
    return mismatch > 0 and 1 or -1


def check_port(parsed_url):
    colon = parsed_url.netloc.split(':')
    if len(colon) == 1:
        return -1
    elif parsed_url.scheme == 'https' and colon[1] == '443':
        return 1
    elif parsed_url.scheme == 'http' and colon[1] == '80':
        return 1
    else:
        return -1


def check_url_request(soup, netloc):
    imgs = soup.findAll('img')
    if not imgs:
        return -1
    mismatch = 0
    tot = 0
    for img in imgs:
        if 'src' in img:
            src = urlparse(img['src'])
            tot += 1
            if src.netloc != netloc:
                mismatch += 1
    if tot == 0:
        return 1
    perc = mismatch * 100 / tot
    if perc < 22:
        return 1
    elif 22 <= perc < 61:
        return 0
    else:
        return -1


def check_url_anchors(soup, netloc):
    anchors = soup.findAll('a')
    if not anchors:
        return -1
    mismatch = 0
    tot = 0
    for anchor in anchors:
        if 'href' in anchor:
            src = urlparse(anchor['href'])
            tot += 1
            if src.netloc != netloc:  # Catches non-URL hrefs too
                mismatch += 1
    if tot == 0:
        return 1
    perc = mismatch * 100 / tot
    if perc < 31:
        return 1
    elif 31 <= perc < 67:
        return 0
    else:
        return -1


def check_link_in_tags(soup, netloc):
    mismatch = 0
    tot = 0
    scripts = soup.findAll('script')
    if scripts:
        for script in scripts:
            if 'src' in script:
                src = urlparse(scripts['src'])
                tot += 1
                if src.netloc != netloc:
                    mismatch += 1
    links = soup.findAll('link')
    if links:
        for link in links:
            if 'href' in link:
                href = urlparse(link['href'])
                tot += 1
                if href.netloc != netloc:
                    mismatch += 1
    if tot == 0:
        return 1
    perc = mismatch * 100 / tot
    if perc < 31:
        return 1
    elif 31 <= perc < 67:
        return 0
    else:
        return -1


def check_form_handlers(soup, netloc):
    forms = soup.findAll('form')
    if not forms:
        return -1
    for form in forms:
        if 'action' in form:
            action = urlparse(form['action'])
            if action.netloc != netloc:
                return 1
    return -1


def check_submit_email(soup):
    forms = soup.findAll('form')
    if not forms:
        return -1
    for form in forms:
        if 'action' in form:
            if 'mailto' in form['action']:
                return 1
    return -1


def check_abnormal_url(domain):
    w = whois.whois(domain)
    if 'domain_name' in w:
        del w['domain_name']  # This obviously doesn't have to be included in the check
    if domain in str(w):
        return -1
    else:
        return 1


def check_redirects(url):
    session = requests.Session()
    session.max_redirects = 1
    try:
        session.get(url, verify=False)
        return -1
    except requests.exceptions.TooManyRedirects as exc:
        return 1


def check_onmouseover(html):
    if 'onmouseover' in html and 'window.status' in html:
        return 1
    else:
        return -1


def check_rightclick(html):
    if 'event.button==2' in html:
        return 1
    else:
        return -1


def check_domain_age(domain):
    now = datetime.now()
    w = whois.whois(domain)
    if type(w.creation_date) == list:
        w.creation_date = w.creation_date[0]
    else:
        w.creation_date = w.creation_date
    timedelta = now - w.creation_date
    days_from_creation = timedelta.days
    return days_from_creation > 180 and -1 or 1


def check_dnsrecord(domain):
    try:
        socket.getaddrinfo(domain, None, socket.AF_UNSPEC)
        return -1
    except:
        return 1


def check_traffic(domain):
    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:122.0) Gecko/20100101 Firefox/122.0',
        }
        rank = requests.get(f"https://www.similarweb.com/website/{domain}/", headers=headers).json()
        if rank['GlobalRank']['Rank'] <= 100000:
            return -1
        else:
            return 1
    except:
        return -1


def get_ranks(domain):
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:122.0) Gecko/20100101 Firefox/122.0',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
        'Accept-Encoding': 'gzip, deflate, br',
        'Content-Type': 'application/x-www-form-urlencoded',
        'Origin': 'https://checkpagerank.net',
        'Connection': 'keep-alive',
        'Referer': 'https://checkpagerank.net/check-page-rank.php',
        'Upgrade-Insecure-Requests': '1',
        'Sec-Fetch-Dest': 'document',
        'Sec-Fetch-Mode': 'navigate',
        'Sec-Fetch-Site': 'same-origin',
        'Sec-Fetch-User': '?1',
        'Pragma': 'no-cache',
        'Cache-Control': 'no-cache',
    }
    data = {
        'name': domain
    }
    res = requests.post('https://checkpagerank.net/index.php', data=data, headers=headers).text
    ranks = [float(s.replace('<b>', '').replace('/10</b>', '')) for s in re.findall(r'<b>\d+\.?\d*/\d+</b>', res)]
    ranks.append(int(re.findall(r"External Backlinks: (\d+)", res)[0].replace(',', '')))
    return ranks


def check_statistical_report(domain):
    with open("phishing-domains.txt") as f:
        for line in f.readlines():
            if domain == line.strip():
                return 1
    return -1


def get_url_features(url):
    f = {}
    print(colored('[  0%]', 'magenta'), 'URL analysis...')
    parsed_url = urlparse(url)
    host = parsed_url.netloc.split(':')[0]
    try:
        ip_address(host)
        f['Having IP Address'] = 1
    except ValueError:
        f['Having IP Address'] = -1
    f['URL Length'] = (len(url) >= 54) and 1 or -1
    f['Shortening Service'] = host in SHORTENING_SERVICES and 1 or -1
    f['Having At Symbol'] = '@' in url and 1 or -1
    f['Double Slash Redirecting'] = parsed_url.path.startswith('//') and 1 or -1
    f['Prefix Suffix'] = '-' in host and 1 or -1
    if f['Having IP Address'] != 1:
        f['Having Sub Domain'] = host.replace('www.', '').count('.') > 1 and 1 or -1
    else:
        f['Having Sub Domain'] = -1  # IP addresses don't have subdomains...
    print(colored('[ 10%]', 'magenta'), 'SSL certificate...')
    f['SSL Final State'] = verify_ssl_certificate(host)
    print(colored('[ 20%]', 'magenta'), 'Expiry date...')
    f['Domain Registration Length'] = days_to_domain_expire(host) < 365 and 1 or -1
    f['Port'] = check_port(parsed_url)
    f['HTTPS Token'] = 'https' in host and 1 or -1
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    html = requests.get(url, verify=False).text
    soup = BeautifulSoup(html, 'html.parser')
    f['Favicon'] = check_favicon(soup, parsed_url.netloc)
    f['Request URL'] = check_url_request(soup, parsed_url.netloc)
    f['URL of Anchor'] = check_url_anchors(soup, parsed_url.netloc)
    f['Links in Tags'] = check_link_in_tags(soup, parsed_url.netloc)
    f['SFH'] = check_form_handlers(soup, parsed_url.netloc)
    f['PopUp Window'] = check_form_handlers(soup, parsed_url.netloc)
    f['IFrame'] = check_iframe(soup)
    f['Submitting to Email'] = check_submit_email(soup)
    print(colored('[ 30%]', 'magenta'), 'WHOIS...')
    f['Abnormal URL'] = check_abnormal_url(host)
    f['Redirect'] = check_redirects(url)
    f['On Mouseover'] = check_onmouseover(html)
    f['Right Click'] = check_rightclick(html)
    print(colored('[ 45%]', 'magenta'), 'Domain registration age...')
    f['Age of Domain'] = check_domain_age(host)
    f['DNS Record'] = check_dnsrecord(host)
    print(colored('[ 60%]', 'magenta'), 'Website traffic...')
    f['Web Traffic'] = check_traffic(host)
    print(colored('[ 75%]', 'magenta'), 'Website ranking...')
    try:
        ranks = get_ranks(host)
        if len(ranks) == 3:
            f['Page Rank'] = ranks[1] / 10 < 0.2 and 1 or -1
            f['Google Index'] = -1
        if ranks[2] == 0:
            f['Links Pointing to Page'] = 1
        elif 0 < ranks[2] <= 2:
            f['Links Pointing to Page'] = 0
        else:
            f['Links Pointing to Page'] = -1
    except:
        f['Page Rank'] = 1  # No information = suspicious
        f['Google Index'] = 1  # No information = suspicious
        f['Links Pointing to Page'] = 0  # No information = cannot draw conclusions...
    print(colored('[ 90%]', 'magenta'), 'Statistical report...')
    f['Statistical Report'] = check_statistical_report(host)
    print("\n".join(f.keys()))
    print(colored('[100%]', 'magenta'), 'Done.')
    return f


def print_features(features):
    for k, v in features.items():
        print(f"  {k} =", COLORED[v])


if __name__ == '__main__':
    # See https://openphish.com/ for live phishing examples
    #website = 'http://ploshadka.top/irsus/payment.html'
    print()
    cprint(' --- PHISHING WEBSITE CHECKER --- ', 'white', 'on_cyan')
    print()
    print(colored('URL = ', 'white'), end='')
    website = input()
    print(colored('\nAnalyzing website...', 'cyan'))
    f = get_url_features(website)
    print()
    print_features(f)
    fselect = joblib.load('fselect.joblib')
    clf = joblib.load('rf.joblib')
    print(colored('\nLoading classifier...', 'cyan'))
    X = [[float(v) for v in f.values()]]
    X_new = fselect.transform(X)
    y = clf.predict(X_new)
    if y[0] == 1:
        print(colored('ACHTUNG: POSSIBLE PHISHING ATTEMPT', 'red'))
    else:
        print(colored("It doesn't look like a phishing attempt", 'green'))
