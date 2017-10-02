import sys
from urllib.parse import urlparse
from datetime import datetime
from dateutil.relativedelta import relativedelta
import requests
import whois


def load_urls4check(path):
    with open(path, 'r') as url_file:
        return [url for url in (line.strip() for line in url_file) if url]


def is_server_respond_with_200(url):
    request = requests.get(url)
    if request.ok:
        return "Все отлично, статус %d" % request.status_code
    else:
        return "Внимание!!! Что то не так, статус %d" % request.status_code


def get_domain_expiration_date(url):
    parsed = urlparse(url)
    if not bool(parsed.netloc):
        return False, "Некорректный адрес"

    domain_name = parsed.hostname
    domain_info = whois.whois(domain_name)

    if domain_info.status is None:
        return False, "Несуществующий домен"

    if type(domain_info.expiration_date) is list:
        exp_date = domain_info.expiration_date[0]
    else:
        exp_date = domain_info.expiration_date

    if exp_date - relativedelta(months=1) > datetime.now():
        return True, "Домен оплачен до %s" % exp_date.strftime('%d-%d-%Y')
    else:
        return True, "Внимание!!! Нужно оплатить домен до %s" % \
                      exp_date.strftime('%d-%d-%Y')


def format_output(url):
    domain_result = get_domain_expiration_date(url)
    status_result = is_server_respond_with_200(url) if domain_result[0] else ''
    output = """{url}
             {stat_res}
             {domain_res}
    """.format(url=url, stat_res=status_result, domain_res=domain_result[1])
    return output


if __name__ == '__main__':
    for url in load_urls4check(sys.argv[1]):
        print(format_output(url))
