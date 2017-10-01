import sys
from urllib.parse import urlparse
from datetime import datetime
from dateutil.relativedelta import relativedelta
import requests
import whois


def load_urls4check(path):
    with open(path,'r') as url_file:
        return url_file.read().splitlines()


def is_server_respond_with_200(url):
    request = requests.get(url)
    if request.status_code == 200:
        return "Все отлично, статус %d" % request.status_code
    else:
        return "Внимание!!! Что то не так, статус %d" % request.status_code


def get_domain_expiration_date(url):
    domain_name = urlparse(url).hostname
    domain_info = whois.whois(domain_name)
    exp_date = domain_info.expiration_date[0] if type(domain_info.expiration_date) is list else domain_info.expiration_date

    if exp_date - relativedelta(months=1) > datetime.now():
        return "Домен оплачен до %s" % exp_date.strftime('%d-%d-%Y')
    else:
        return "Внимание!!! Нужно оплатить домен до %s" % exp_date.strftime('%d-%d-%Y')


def format_output(url):
    output = """{url}
             {stat_res}
             {domain_res}
             """.format(url=url, 
                        stat_res=is_server_respond_with_200(url), 
                        domain_res=get_domain_expiration_date(url))
    return output


if __name__ == '__main__':
    for url in load_urls4check(sys.argv[1]):
        print(format_output(url))
