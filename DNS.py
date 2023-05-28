import binascii
import pickle
import socket
from time import time

types = {1: "A", 2: "NS", 3: "MD", 4: "MF", 5: "CNAME", 6: "SOA", 7: "MB", 8: "MG", 9: "MR", 10: "NULL", 11: "WKS",
         12: "PTR", 13: "HINFO", 14: "MINFO", 15: "MX"}


# Один символ 4 бита т.к. 16 значная система исчисления, что по поводу
# TRUST_SERVER = "8.8.8.8"


class Head:
    def __init__(self, some: str):
        self.id = some[:4]
        self.flags = some[4:8]
        self.QDCount = some[8:12]
        self.ANCount = some[12:16]
        self.AUCount = some[16:20]
        self.ADCount = some[20:24]


class Query:
    def __init__(self, question, position1):
        self.name, position, self.byte_name = get_name(question, position1)
        position += 2
        self.type = question[position: position + 4]
        position += 4
        self.NClass = question[position: position + 4]
        position += 4
        self.pos = position
        self.all = self.byte_name + self.type + self.NClass


class Answers:
    def __init__(self, answers, answer_count):
        self.answer = answers
        self.ANCount = answer_count


class Answer:
    def __init__(self, answer, position1):
        s = ""
        self.name, position, self.byte_name = get_name(answer, position1)
        self.name_len = len(self.name)
        self.type = answer[position: position + 4]
        position += 4
        self.NClass = answer[position: position + 4]
        position += 4
        self.TTL_byte = answer[position: position + 8]
        self.TTL = int(round(time())) + int(self.TTL_byte, 16)
        position += 8
        self.data_length = answer[position: position + 4]
        position += 4
        self.data = answer[position:position + (int(self.data_length, 16) * 2)]
        position += int(self.data_length, 16) * 2
        self.pos = position
        self.all = self.byte_name + "00" + self.type + self.NClass + self.TTL_byte + self.data_length + self.data


def dump_cache(cache):
    with open('cache_dns.pkl', 'wb') as cache_file:
        pickle.dump(cache, cache_file)


def load():
    try:
        with open('cache_dns.pkl', 'rb+') as cache_file:
            cache = pickle.load(cache_file)
            return cache
    except FileNotFoundError:
        return {}


def clear_cache(cache):
    now = int(round(time()))
    for key, one_answer in cache.items():
        if one_answer.TTL <= now:
            del one_answer

        for key in cache.keys():
            if cache[key] is None or cache[key] == []:
                cache.pop(key)
    return cache


def take_from_pointer(answer, binary_pointer):
    real_pointer = int(bin(binary_pointer)[4:], 2) * 2 - 24
    return get_name(answer, real_pointer)


def get_label_length(answer, pointer, pos):
    result = ""
    counter = int(bin(int(pointer[:2], 16))[2:], 2)
    i = 0
    while counter > 0:
        letter = chr(int(answer[pos:][i:i + 2], 16))
        result += letter
        counter -= 1
        i += 2
    result += "."
    return result, i


# Надо чтобы не до конца файла доходило, т.к. потом идёт, Type, Class,  TTL,
def get_name(answer, position):
    byte = ""
    name = ""
    pos = position
    while (answer[position:position + 2] != "00"):
        pointer = answer[position:position + 4]
        binary_pointer = int(pointer, 16)
        if binary_pointer > 49152:
            byte1 = answer[pos:position]
            position += 4
            word, i, byte = take_from_pointer(answer, binary_pointer)
            name += word
            return name, position, byte1 + byte
        else:
            position += 2
            word, i = get_label_length(answer, pointer, position)
            name += word
            position += i
    byte = answer[pos:position]
    return name, position, byte


def parse_resp(data, cache):
    pos = 0
    all_answers = ""
    with socket.socket(
            socket.AF_INET, socket.SOCK_DGRAM) as sock_for_request:
        sock_for_request.settimeout(2)
        try:
            sock_for_request.sendto(data, ('8.8.8.8', 53))
            answer_from_trust_server = sock_for_request.recv(2400)
        except TimeoutError:
            return b''

    h = binascii.hexlify(answer_from_trust_server).decode('utf-8')[:24]
    head = Head(h)
    other = binascii.hexlify(answer_from_trust_server).decode('utf-8')[24:]
    for i in range(int(head.QDCount)):
        query = Query(other, pos)
        pos = query.pos
    for i in range(int(head.ANCount, 16)):
        answer = Answer(other, pos)
        pos = answer.pos
        answer.all = answer_from_trust_server
        cache[(answer.byte_name, answer.type)] = answer
    # = Answers(all_answers, head.ANCount)
    return answer_from_trust_server


def start(data, cache):
    pos = 0
    res = ""
    h = binascii.hexlify(data).decode('utf-8')[:24]
    head = Head(h)
    other = binascii.hexlify(data).decode('utf-8')[24:]
    print(cache.keys())

    for i in range(int(head.QDCount)):
        query = Query(other, pos)
        pos = query.pos
        if (query.byte_name, query.type) in cache.keys():
            print(
                "have in the cache")
            answer_from_cache = cache.get((query.byte_name, query.type))  # можно массивом типо соединённый answer несколько

            res = answer_from_cache.all
        else:
            o = parse_resp(data, cache)
            cache = clear_cache(cache)
            answer_from_cache = cache.get((query.byte_name, query.type))
            res = o

    return res, cache


sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
server_address = ('localhost', 53)
sock.bind(server_address)
cache = clear_cache(load())
data, addr = sock.recvfrom(1024)
print('Server launched on 127.0.0.1: 53')
while True:
    print(1)
    cache = clear_cache(load())
    print("HI", cache.keys())
    try:
        data, addr = sock.recvfrom(1024)
        res, cache = start(data, cache)
        sock.sendto(res, addr)
        dump_cache(cache)
        if not data:
            break
    except ConnectionResetError:
        continue

sock.close()
cache_size = 10000
