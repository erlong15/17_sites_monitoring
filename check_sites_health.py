import argparse
from urllib.parse import urlparse
from datetime import datetime
from dateutil.relativedelta import relativedelta
import requests
import whois

phrases = {'STATUS_OK': 'Все отлично',
           'STATUS_BAD': 'Внимание!!! Что то не так',
           'INCORRECT_ADDR': 'Некорректный адрес',
           'UNKNOWN_DOMAIN': 'несуществующие домен',
           'DOMAIN_PAID': 'Домен оплачен до',
           'SHOULD_PAID': 'Внимание!!! Нужно оплатить домен до '}


def load_urls4check(path):
    with open(path, 'r') as url_file:
        return [url for url in (line.strip() for line in url_file) if url]


def get_server_status_code(url):
    response = requests.get(url)
    return response.status_code


def get_domain_name(url):
    parsed = urlparse(url)
    return parsed.hostname


def get_domain_info(in_domain_name):
    exp_date = None
    if in_domain_name:
        domain_info = whois.whois(in_domain_name)
        if domain_info.status is not None:
            if type(domain_info.expiration_date) is list:
                exp_date = domain_info.expiration_date[0]
            else:
                exp_date = domain_info.expiration_date

    return exp_date


def format_status_phrase(url):
    status_code = get_server_status_code(url)
    status_tmpl = '{phrase}, статус {status}'
    phrase = phrases['STATUS_OK'] if status_code == 200 \
        else phrases['STATUS_BAD']

    return status_tmpl.format(phrase=phrase, status=status_code)


def format_domain_phrase(exp_date):
    domain_tmpl = '{phrase} {date}'
    date_cond = exp_date - relativedelta(months=1) > datetime.now()
    phrase = phrases['DOMAIN_PAID'] if date_cond else phrases['SHOULD_PAID']

    return domain_tmpl.format(phrase=phrase,
                              date=exp_date.strftime('%d-%m-%Y'))


def format_output(url, in_domain_name, in_exp_date):
    status_phrase = ''
    if not in_domain_name:
        domain_phrase = phrases['INCORRECT_ADDR']
    else:
        if in_exp_date:
            domain_phrase = format_domain_phrase(in_exp_date)
            status_phrase = format_status_phrase(url)
        else:
            domain_phrase = phrases['UNKNOWN_DOMAIN']

    output = """{url}
             {status_res}
             {domain_res}
    """.format(url=url,
               status_res=status_phrase,
               domain_res=domain_phrase)
    return output


def get_args():
    parser = argparse.ArgumentParser(description='Site/domain monitor.')
    parser.add_argument('-f', '--urlfile',
                        help='File with list of URLs',
                        required=True)
    args = parser.parse_args()
    return args


if __name__ == '__main__':
    args = get_args()
    for check_url in load_urls4check(args.urlfile):
        domain_name = get_domain_name(check_url)
        exp_date = get_domain_info(domain_name)
        print(format_output(check_url, domain_name, exp_date))
