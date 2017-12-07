#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Python script gives : No such file or directory
# http://stackoverflow.com/questions/19764710/python-script-gives-no-such-file-or-directory


import re
import socket
import subprocess
import json
import argparse
from operator import itemgetter
from time import strptime
from datetime import datetime, timedelta, date
from elasticsearch import Elasticsearch, ConnectionError
from subprocess import CalledProcessError


parser = argparse.ArgumentParser(
    description="Script para tickets de perda de mensagens.\n \
                 Funcional apenas para caixas postais no NFS .",
    usage="Exemplo de Uso:\n~$ perda_de_mensagens \'666999666#id\' ronnie.james.dio\n"
          "Onde \"666999666#id\"é o id completo com o brand,\n"
          "e o \"ronnie.james.dio\" é o user. \m/")

parser.add_argument("id", help="id com brand. Ex: 666999666#id")
parser.add_argument("user", help='user sem o dominio. Ex: ronnie.james.dio')
args = parser.parse_args()
_id = args._id
user = args.user

path_prefix = "/tmp/"

# Elastic Search HOST para consulta
es_host = "host01.com"

# Indexes do Elastic Search
mercBr = "mercury-br"
mercLatam = "mercury-latam"
doveProxy = "dovecot-proxy-log"
doveBox = "dovecot-box-log"
trrClean = "trrcleaner-log"

# Body da request passada ao ES
req_body = {"query": {"bool": {"must": {"query_string": {"query": "\"" + _id + "\""}}}}}

# Arquivos temporarios
fmercBr = path_prefix + user + "_mercury-BR-ES.tmp"
fmercLa = path_prefix + user + "_mercury-LA-ES.tmp"
fdoveBox = path_prefix + user + "_dovecot-box-ES.tmp"
fdoveProx = path_prefix + user + "_dovecot-proxy-ES.tmp"
ftrrClean = path_prefix + user + "_trrcleaner-log.tmp"

# instancia objeto do ES
es = Elasticsearch(hosts=[{'host': es_host, 'port': 9200}])

# Informações para o usuário que está executando o script via terminal
search_date = datetime.now()
dia_menos_7 = search_date - timedelta(days=7)
dia_menos_7 = dia_menos_7.strftime('%d/%m')
dia_7 = search_date.strftime('%d/%m')

print "############################################################"
print ""
print "    Script para Tickets de Perda de Mensagens:"
print "    Pesquisando pelo usuario {user}, _id {_id}".format(user=user, _id=_id)
print "    Entre dias {de} e {ate}.".format(de=dia_menos_7, ate=dia_7)
print ""
print "############################################################"
print "\n"

# Criação do arquivo de saída do script
exit_print = open(path_prefix + user + "_relatorio_final.txt", 'w')
exit_print.write("\n")
exit_print.write("Prezados,\n")
exit_print.write("Pesquisa realizada entre " + dia_menos_7 + " a " + dia_7 +
                 " pois o período máximo de pesquisa é de 7 dias a partir da data de abertura do ticket.\n")
exit_print.write("Este relatório mostra deleções que partiram de ações do lado do cliente (exceto o cleaner).\n")
exit_print.write("Mensagens deletadas pelo cliente não têm backup e de nenhuma forma temos como recuperar.\n")
exit_print.write("Segue abaixo as deleções constatadas na caixa postal do usuário: " + user + ".\n")
exit_print.write("\n")
exit_print.write("\n")

# Lista de Ips que vão ser usados pela deleção do mercury.
# Declarado num escopo mais externo para que qualquer função possa usar os ips do usuário que são salvos nesta lista
user_ip_list_dict = []

# REGEXES USADOS NAS FUNÇÕES
regex_line_date = re.compile(ur'^.{17}')
regex_protocol = re.compile(ur'dovecot: (pop3\[|imap\[)')
regex_customer_ip = re.compile(ur'from [0-9]*\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}|from (([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))')  # from 10.235.200.169:
regex_user_real_ip = re.compile(ur'userIp:\[[0-9]*\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}|userIp:\[(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))')
regex_del = re.compile(ur'del=[^0][0-9]*')
regex_msgid = re.compile(ur'msgid=.*?,')  # msgid=orHsbZgEg5oC6orIebUYNT,
regex_action = re.compile(ur'expunge|delete|save')
regex_pasta = re.compile(ur'Pasta \[.+?\]')
regex_qtd_msgs = re.compile(ur'bytes e \[.\d?\]')
regex_box = re.compile(ur'box=.*?,')  # box=Spam


def raw_time_to_datetime(raw_date):
    """ Transforma a data crua do log em timedate """
    raw_date = raw_date.strip()
    for char in ['"', '[']:
        raw_date = raw_date.replace(char, "").strip()
    _date = raw_date[:-9].split()
    _time = raw_date[8:].split(':')
    _year = datetime.now().year
    _month = strptime(_date[0], '%b').tm_mon
    _day = int(_date[1])
    _hour = int(_time[0])
    _min = int(_time[1])
    _sec = int(_time[2])
    _data_log = datetime(_year, _month, _day, _hour, _min, _sec)

    # Quando é horário de verão
    return _data_log - timedelta(hours=2)
    # horário normal
    # return _data_log


def imap_client():
    """IMAP CLIENT Monta o dicionário dos logs imap client"""

    imap_client_list = []
    try:
        _file = open(fdoveBox, 'r')
    except IOError as err:
        print "Erro ao abrir o arquivo {err}".format(err=err)
    else:
        for line in _file:
            if re.search(regex_protocol, line) is not None \
                    and re.search(regex_customer_ip, line) is not None \
                    and re.search(regex_action, line) is not None:
                # IMAP
                if re.search(regex_protocol, line).group(0)[9:-1] == "imap" \
                        and "10." in re.search(regex_customer_ip, line).group(0)[5:] in line:
                    imap_client_list.append(line)
        _file.close()

    list_dict = []
    log_line = {'date': '',
                'customer_ip': '',
                'msgid': '',
                'box': ''}

    for dic in imap_client_list:
        if re.search(regex_line_date, dic):
            log_line['date'] = raw_time_to_datetime(re.search(regex_line_date, dic).group(0))
        else:
            log_line['date'] = ''
        if re.search(regex_customer_ip, dic):
            log_line['customer_ip'] = re.search(regex_customer_ip, dic).group(0)[5:]
        else:
            log_line['customer_ip'] = ''

        if re.search(regex_msgid, dic) is not None:
            log_line['msgid'] = re.search(regex_msgid, dic).group(0)[6:-1]
        else:
            log_line['msgid'] = ''

        if re.search(regex_action, dic):
            log_line['action'] = re.search(regex_action, dic).group(0)
        else:
            log_line['action'] = ''

        if re.search(regex_box, dic) is not None:
            log_line['box'] = re.search(regex_box, dic).group(0)[4:-1]
        else:
            log_line['box'] = ''

        list_dict.append(log_line.copy())
    return list_dict


def matrix_imap(lista_dict):
    """IMAP CLIENT Monta a Lista de Lista de Dicionarios do Imap Client.\n
       Necessário para as validações de deleção
    """
    init_data = datetime(1970, 1, 1, 1, 1)
    lista_lista_dict = [[{
                            'line_date': init_data,
                            'customer_ip': '',
                            'box': '',
                            'msgid': '',
                        }]]

    for d in lista_dict:
        valida = False
        for n, l in enumerate(lista_lista_dict):
            count_dic = 0
            for dic in l:
                count_dic += 1
                if dic['msgid'] != d['msgid'] and n + 1 == len(lista_lista_dict):
                    lista_lista_dict.append([d])
                    break
                elif dic['msgid'] != d['msgid']:
                    break
                elif cmp(dic, d) == 0:
                    valida = True
                    break
                elif count_dic == len(l):
                    lista_lista_dict[n].append(d)
                    valida = True
                    break
            if valida is True:
                break
    # Remove o map inicial pra não te-lo nas comparações de data.
    lista_lista_dict.pop(0)

    return lista_lista_dict


# Não está sendo usado mas é uma função muito útil
def remove_dict_duplicado(list_dict, key_to_sort):
    """
    Remove dicionários duplicados de uma lista de dicionarios
    :param list_dict: qualquer lista de dicionario
    :param key_to_sort: a chave do dicionario a qual se quer ordenar
    :return: lista de dicionarios sem dicionarios duplicados
    """
    list_dict = sorted(list_dict, key=itemgetter(key_to_sort))
    seen = set()
    new_l = []
    for d in list_dict:
        t = tuple(d.items())
        if t not in seen:
            seen.add(t)
            new_l.append(d)
    return new_l


def get_mercury_user_ip():
    """
    Função que guarda todas as Datas e IP's utilizados nas conexões via webmail
    É usado para validar o IP do user usado nas deleções via webmail
    :return: Lista de dicionarios com data e IP
    """
    user_ip_dict = {'date': '', 'user_ip': ''}

    try:
        _file = open(fmercBr, 'r')
    except Exception as err:
        print "Arquivo não existe ou erro ao abrir {err}".format(err=err)
    else:
        for line in _file:
            if re.search(regex_user_real_ip, line):
                user_ip_dict['date'] = raw_time_to_datetime(re.search(regex_line_date, line).group(0))
                user_ip_dict['user_ip'] = re.search(regex_user_real_ip, line).group(0)[8:]
                user_ip_list_dict.append(user_ip_dict.copy())
        _file.close()

    try:
        _file = open(fmercLa, 'r')
    except Exception as err:
        print "Arquivo não existe ou erro ao abrir {err}".format(err=err)
    else:
        for line in _file:
            if re.search(regex_user_real_ip, line):
                user_ip_dict['date'] = raw_time_to_datetime(re.search(regex_line_date, line).group(0))
                user_ip_dict['user_ip'] = re.search(regex_user_real_ip, line).group(0)[8:]
                user_ip_list_dict.append(user_ip_dict.copy())
        _file.close()


def webmail():
    """WEBMAIL Monta o dicionário dos logs que confirmam que as mensagens foram excluidas"""

    list_dict = []
    webmail_list = []

    # Executa a busca pelos ips do user nos logs do mercury-br e mercury-la
    get_mercury_user_ip()

    try:
        _file = open(fdoveBox, 'r')
    except IOError as err:
        print "Arquivo não existe ou erro ao abrir {err}".format(err=err)
    else:
        for line in _file:
            if re.search(regex_protocol, line) is not None \
                    and re.search(regex_customer_ip, line) is not None \
                    and re.search(regex_action, line) is not None \
                    and re.search(regex_box, line) is not None:
                # WEBMAIL
                if re.search(regex_protocol, line).group(0)[9:-1] == "imap" \
                        and "10." in re.search(regex_customer_ip, line).group(0)[5:] \
                        and re.search(regex_action, line).group(0) == "expunge" \
                        and re.search(regex_box, line).group(0)[4:-1] == "Spam" in line \
                        or re.search(regex_protocol, line).group(0)[9:-1] == "imap" \
                                and "10." in re.search(regex_customer_ip, line).group(0)[5:] \
                                and re.search(regex_action, line).group(0) == "expunge" \
                                and re.search(regex_box, line).group(0)[4:-1] == "Lixeira" in line:
                    webmail_list.append(line)
        _file.close()

    log_line = {'date': '',
                'customer_ip': '',
                'box': ''}

    for dic in webmail_list:
        if re.search(regex_line_date, dic):
            log_line['date'] = raw_time_to_datetime(re.search(regex_line_date, dic).group(0))
        else:
            log_line['date'] = ''

        if re.search(regex_box, dic):
            log_line['box'] = re.search(regex_box, dic).group(0)[4:-1]
        else:
            log_line['box'] = ''

        log_line['customer_ip'] = ''

        list_dict.append(log_line.copy())

    # Loop que encontra os IP's usados para as deleções via webmail.
    # Usa a lista de dicionarios salva pela def get_mercury_user_ip()
    for email in list_dict:
        l_dif = []
        # conexoes
        for conn in user_ip_list_dict:
            dif_in_secs = (email['date'] - conn['date']).total_seconds()
            if dif_in_secs > 0:
                conn['secs'] = dif_in_secs
                l_dif.append(conn)
        l_dif = sorted(l_dif, key=itemgetter('secs'))
        email['customer_ip'] = l_dif[0]['user_ip']

    return list_dict


def saida_ips(lista_ips):
    """Imprime os IP's Utilizados nas Conexões """
    lista_ips = set(lista_ips)
    if len(lista_ips) == 1:
        exit_print.write("IP utilizado na conexão:\n")
    elif len(lista_ips) > 1:
        exit_print.write("IP's utilizados nas conexões:\n")

    for i in lista_ips:
        try:
            host = socket.gethostbyaddr(i)
            exit_print.write("%s (%s)\n" % (i, host[0]))
        except socket.gaierror as e:
            exit_print.write("%s (Hostname ou Serviço desconhecidos)\n" % i)
        except socket.herror as e:
            exit_print.write("%s (Hostname ou Serviço desconhecidos)\n" % i)
        except socket.error as e:
            exit_print.write("%s (Hostname ou Serviço desconhecidos)\n" % i)


def pop3():
    """POP3 Monta o dicionário dos logs que confirmam que as mensagens foram baixadas ex: del=5/5"""
    list_dict = []
    pop3_list = []
    log_line = {'date': '',
                'customer_ip': '',
                'del': ''}
    try:
        _file = open(fdoveBox, 'r')
    except IOError as err:
        print "Erro ao abrir o arquivo {err}".format(err=err)
    else:
        for line in _file:
            if re.search(regex_protocol, line):
                # aqui, depois que a engenharia ajustar o log pra vir o IP do user
                # tem que trocar o |"10." in| por |"10. not in|  pra excuir ips de back dos servidores.
                if re.search(regex_protocol, line).group(0)[9:-1] == "pop3" \
                        and "10." in re.search(regex_customer_ip, line).group(0)[5:] in line:
                    pop3_list.append(line)
        _file.close()

    for dic in pop3_list:
        if re.search(regex_del, dic):
            if re.search(regex_line_date, dic):
                log_line['date'] = raw_time_to_datetime(re.search(regex_line_date, dic).group(0))
            else:
                log_line['date'] = ''

            if re.search(regex_customer_ip, dic):
                log_line['customer_ip'] = re.search(regex_customer_ip, dic).group(0)[5:]
            else:
                log_line['customer_ip'] = ''

            if re.search(regex_del, dic):
                log_line['del'] = int(re.search(regex_del, dic).group(0)[4:])
            else:
                log_line['del'] = ''

            list_dict.append(log_line.copy())
    return list_dict


def valida_exclusao_imap_client(mail_dict_):
    """Lógica que valida a exclusão de mensagens via IMAP CLIENT"""
    aux_list = []
    # Ordena os logs para cada 'msgid'
    for i in mail_dict_:
        i = sorted(i, key=itemgetter('date'))
        aux_list.append(i)

    deletion_list = []

    for i in aux_list:
        if i[len(i) - 1]['action'] == 'expunge':
            deletion_list.append(i[len(i) - 1])

    return sorted(deletion_list)


def cleaner():
    """
    Faz a pesquisa nos losgs do cleaner para as mensagens que foram expurgadas pela regra de negocio
    :return: Lista de dicionarios com as remoções do cleaner
    """
    re_inbox = re.compile(ur'INBOX\(\d+')
    re_spam = re.compile(ur'Spam\(\d+')
    re_lixeira = re.compile(ur'Lixeira\(\d+')
    re_enviados = re.compile(ur'E-mails enviados\(\d+')

    list_re = [re_inbox, re_spam, re_lixeira, re_enviados]

    dic_clean = {'date': datetime(1970, 1, 1, 1, 1), 'box': '', 'msg_qtd': 0}
    list_cleaned = []
    list_dict_cleaned = [dic_clean]
    try:
        _file = open(ftrrClean, 'r')
    except Exception as err:
        print "Arquivo não existe ou erro ao abrir {err}".format(err=err)
    else:
        for line in _file:
            if "[Oper ." in line and "[" + _id in line:
                list_cleaned.append(line)
                for r in list_re:
                    if re.search(r, line) is not None:
                        dic_clean['date'] = raw_time_to_datetime(re.search(regex_line_date, line).group(0))
                        l = re.search(r, line).group(0).split('(')
                        dic_clean['box'] = l[0]
                        dic_clean['msg_qtd'] = l[1]
                        list_dict_cleaned.append(dic_clean.copy())
        _file.close()
    list_dict_cleaned.pop(0)  # Remove o dicionario inicial
    return list_dict_cleaned


def pastas():
    dic_c = {'date': '', 'folder': '', 'msg_qtd': ''}
    l_dict_clean = []

    try:
        _file = open(fdoveBox, 'r')
    except IOError as err:
        print "Erro ao abrir o arquivo {err}".format(err=err)
    else:
        for line in _file:
            if "delete folder: " in line:
                if re.search(regex_line_date, line):
                    dic_c['date'] = raw_time_to_datetime(re.search(regex_line_date, line).group(0))
                else:
                    dic_c['date'] = ''

                if re.search(regex_pasta, line):
                    dic_c['folder'] = re.search(regex_pasta, line).group(0)[7:-1]
                else:
                    dic_c['folder'] = ''

                if re.search(regex_qtd_msgs, line):
                    dic_c['msg_qtd'] = re.search(regex_qtd_msgs, line).group(0)[9:-1]
                else:
                    dic_c['msg_qtd'] = ''

                l_dict_clean.append(dic_c.copy())
    finally:
        _file.close()
    return l_dict_clean


# Sort dos arqs temporarios
def sort_file(temp_file):
    try:
        subprocess.check_call(['/usr/bin/sort', '-u', temp_file, '-o', temp_file], stderr=False)
    except CalledProcessError as e:
        print "Arquivo nao encontrado: {file}. O principal motivo é não existir logs para o user em questão.".format(file=temp_file)
        # print "Erro : {e}".format(e=e)


# Func que faz as reqs pagina por pagina e escreve no arq temporario
def get_es_index_request(es_index, max_docs, output_file):
    page = 0

    with open(output_file, 'a') as f:
        while page <= max_docs:
            es_resp = es.search(index=es_index, body=req_body, size=1000, from_=page, _source='message',
                                request_timeout=30)
            for hit in es_resp['hits']['hits']:
                a = json.dumps(hit['_source']['message'], encoding="utf-8-sig")
                f.write("%s\n" % a.decode())
            page += 100


def busca_por_dia(indice_prefix, out_file):
    n = 7  # aqui vão 7 dias por padrão
    i = 0
    while i < n:
        date_n_days_ago = datetime.now() - timedelta(days=i)
        index_date = "%s-%i.%02d.%02d" % (
        indice_prefix, date_n_days_ago.year, date_n_days_ago.month, date_n_days_ago.day)
        print "Pesquisando em : " + index_date
        try:
            num_pagina = es.search(index=index_date, body=req_body, size=0)
            nnum_pagina = int(num_pagina['hits']['total'])
            if nnum_pagina > 0:
                get_es_index_request(index_date, nnum_pagina, out_file)
            i += 1
        except IOError as e:
            i += 1
            print "Index " + index_date + "do Eslastic Search não encontrado para pesquisa do Log. Erro :", e
        except ConnectionError as e:
            i += 1
            print "Falha em estabelecer a conexção com o server ", es_host + " ", e


# ==========  SAIDAS QUE ESCREVEM NO ARQUIVO ============ #

def saida_imap_client(last_imap_client_logs_):
    """IMAP CLIENT Monta a Lista de Lista de Dicionarios"""

    data = date(1970, 1, 1)
    pasta = ''
    print_dictio = [{'box': '', 'data': data, 'count': 0, 'ip': ''}]  # Inicialização do dicionario
    # dic_clean = {'line_date': data, 'folder': '', 'msg_qtd': 0}
    # l_dict_clean = []
    pd_control = 0

    # Sem esse sort, lógica do for abaixo é quebrada, pois depende da lista de dicionarios estar ordenada por data
    last_imap_client_logs_ = sorted(last_imap_client_logs_, key=itemgetter('date'))

    exit_print.write("#################   DELEÇÕES VIA \"IMAP(CLIENT DE EMAIL)\"  #################\n")
    exit_print.write("\n")
    for dic in last_imap_client_logs_:
        dia = dic['date'].date()
        box = dic['box']
        if dia == data and pasta == box:
            print_dictio[pd_control]['count'] += 1
        elif dia == data and pasta != box:
            data = dia
            pasta = box
            pd_control += 1
            print_dictio.append(
                {'box': dic['box'], 'data': dic['date'], 'count': 1, 'ip': dic['customer_ip']})
        elif dia > data and pasta != box:
            data = dia
            pasta = box
            pd_control += 1
            print_dictio.append(
                {'box': dic['box'], 'data': dic['date'], 'count': 1, 'ip': dic['customer_ip']})
        elif dia > data and pasta == box:
            data = dia
            pasta = box
            pd_control += 1
            print_dictio.append(
                {'box': dic['box'], 'data': dic['date'], 'count': 1, 'ip': dic['customer_ip']})

    # Retira o dicionario de inicialização
    print_dictio.pop(0)

    lista_ips = []
    for dic in print_dictio:
        exit_print.write(
            'Dia {}, deletadas {} mensagem(ns) da pasta {}.\n'.format(dic['data'].strftime('%d/%m/%Y'),
                                                                      dic['count'], dic['box']))
        lista_ips.append(dic['ip'])

    exit_print.write("\n")

    if saida_ips > 0:
        saida_ips(lista_ips)

    exit_print.write("\n")


def saida_webmail(list_dicio_delecoes_webmail):
    """WEBMAIL imprime a saída das pesquisas de webmail"""
    # Ordena os logs de deleção por data crescente.
    list_dicio_delecoes_webmail = sorted(list_dicio_delecoes_webmail, key=itemgetter('box', 'date'))

    # variaveis de inicialização do metodo
    data = date(1991, 1, 1)

    print_dictio = [{'box': '', 'data': data, 'count': 0, 'ip': ''}]  # Inicialização do dicionario
    pd_control = 0
    print_box = 'empty'
    exit_print.write("#################   DELEÇÕES VIA \"WEBMAIL\"  #################\n")
    exit_print.write("\n")

    for dic in list_dicio_delecoes_webmail:
        dia = dic['date'].date()
        if dia == data and dic['box'] == print_box:
            print_dictio[pd_control]['count'] += 1
        elif dia >= data and dic['box'] != print_box:
            print_box = dic['box']
            data = dia
            pd_control += 1
            print_dictio.append({'box': dic['box'], 'data': dic['date'], 'count': 1, 'ip': dic['customer_ip']})

    # Retira o dicionario de inicialização
    print_dictio.pop(0)
    lista_ips = []
    for dic in print_dictio:
        exit_print.write(
            'Dia {}, deletadas {} mensagem(ns) da pasta {}. \n'.format(dic['data'].strftime('%d/%m/%Y'), dic['count'], dic['box']))
        lista_ips.append(dic['ip'])

    exit_print.write("\n")

    if lista_ips > 0:
        saida_ips(lista_ips)

    exit_print.write("\n")


def saida_pop3(list_dicio_delecoes_pop3):
    """POP3 imprime a saída das pesquisas de pop3"""
    # Ordena os logs de deleção por data crescente.
    list_dicio_delecoes_pop3 = sorted(list_dicio_delecoes_pop3, key=itemgetter('date'))

    # variaveis de inicialização do metodo
    data = date(1970, 1, 1)

    print_dictio = [{'date': data, 'count': 0, 'ip': ''}]  # Inicialização do dicionario
    pd_control = 0

    exit_print.write("#################  MENSAGENS BAIXADAS VIA \"POP3\"  #################\n")
    exit_print.write("\n")
    for dic in list_dicio_delecoes_pop3:
        dia = dic['date'].date()
        if dia == data:
            print_dictio[pd_control]['count'] += dic['del']
        elif dia > data:
            data = dia
            print_dictio.append(
                {'date': dic['date'], 'count': dic['del'], 'ip': dic['customer_ip']})
            pd_control += 1

    # Retira o dicionario de inicialização
    print_dictio.pop(0)

    lista_ips = []
    for dic in print_dictio:
        exit_print.write('Dia {}, baixadas {} mensagem(ns) via pop3.\n'.format(dic['date'].strftime('%d/%m/%Y'), dic['count']))
        lista_ips.append(dic['ip'])

    exit_print.write("\n")

    if saida_ips > 0:
        saida_ips(lista_ips)

    exit_print.write("\n")


def saida_cleaner(list_dict_cleaned):

    exit_print.write("#################  MENSAGENS REMOVIDAS VIA \"CLEANER\"  #################\n")
    exit_print.write("\n")
    exit_print.write("Remoções via cleaner são baseadas em regras definidas no sistema de e-mail e removem mensagens antigas automaticamente.\nSe houver duvida, contate seu coordenador")
    exit_print.write("\n")
    for dic in list_dict_cleaned:
        exit_print.write('Dia {}, removidas {} mensagem(ns) da pasta {}. \n'.format(dic['date'].strftime('%d/%m/%Y'), dic['msg_qtd'], dic['box']))
    exit_print.write("\n")


def saida_pastas(dictio_pastas_):

    exit_print.write("#################   DELEÇÃO DE \"PASTAS\"  #################\n")
    exit_print.write("\n")

    for dic in dictio_pastas_:
        exit_print.write('Dia {}, deletada a pasta \"{}\" contendo {} mensagem(ns). \n'.format(dic['date'].strftime('%d/%m/%Y'), dic['folder'], dic['msg_qtd']))

    exit_print.write("\n")


# ========== PONTO DE ENTRADA ========== #

# Executa a busca pelo id nos logs
busca_por_dia(trrClean, ftrrClean)
busca_por_dia(mercBr, fmercBr)
busca_por_dia(mercLatam, fmercLa)
busca_por_dia(doveProxy, fdoveProx)
busca_por_dia(doveBox, fdoveBox)

# Faz o sort dos logs usando o sort do SO Linux
sort_file(ftrrClean)
sort_file(fmercBr)
sort_file(fdoveProx)
sort_file(fdoveBox)
sort_file(fmercLa)

# monta as listas de dicionários
dictio_pastas = pastas()
dictio_cleaner = cleaner()
dictio_pop3 = pop3()
dictio_webmail = webmail()
dictio_imap_client = imap_client()


# ========== BLOCO QUE ESCREVE NO ARQUIVO =========== #
if len(dictio_pop3) > 0:
    saida_pop3(dictio_pop3)
else:
    exit_print.write("#################   DELEÇÕES VIA \"POP3\"  #################\n")
    exit_print.write("\n")
    exit_print.write("Não houve deleções via \"POP3\".\n")
    exit_print.write("\n")

if len(dictio_webmail) > 0:
    saida_webmail(dictio_webmail)
else:
    exit_print.write("#################   DELEÇÕES VIA \"WEBMAIL\"  #################\n")
    exit_print.write("\n")
    exit_print.write("Não houve deleções via \"WEBMAIL\".\n")
    exit_print.write("\n")

if len(dictio_imap_client) > 0:
    # retorna uma lista de lista de dicionario ordenada
    # sendo cada uma das listas, toda a "trajetoria" de um email na caixa postal
    mail_dict = matrix_imap(dictio_imap_client)
    # função que tem a lógica de validação dos emails
    last_imap_client_logs = valida_exclusao_imap_client(mail_dict)
    if len(last_imap_client_logs) > 0:
        saida_imap_client(last_imap_client_logs)
    else:
        exit_print.write("#################   DELEÇÕES VIA \"IMAP(CLIENT DE EMAIL)\"  #################\n")
        exit_print.write("\n")
        exit_print.write("Não houve deleções via \"IMAP(CLIENT DE EMAIL)\".\n")
        exit_print.write("\n")
else:
    exit_print.write("#################   DELEÇÕES VIA \"IMAP(CLIENT DE EMAIL)\"  #################\n")
    exit_print.write("\n")
    exit_print.write("Não houve deleções via \"IMAP(CLIENT DE EMAIL)\".\n")
    exit_print.write("\n")

if len(dictio_cleaner) > 0:
    saida_cleaner(dictio_cleaner)
else:
    exit_print.write("#################   REMOÇÕES VIA \"CLEANER\"  #################\n")
    exit_print.write("\n")
    exit_print.write("Não houve remoções via \"CLEANER\".\n")
    exit_print.write("\n")

if len(dictio_pastas) > 0:
    saida_pastas(dictio_pastas)
else:
    exit_print.write("#################   DELEÇÃO DE \"PASTAS\"  #################\n")
    exit_print.write("\n")
    exit_print.write("Não houve deleções de \"PASTAS\".\n")
    exit_print.write("\n")

print "############################################################"
print ""
print "    Pesquisa finalizada, verificar o arquivo de saída em:    "
print "   " + path_prefix + user + "_relatorio_final.txt"
print ""
print "############################################################"

exit_print.close()
