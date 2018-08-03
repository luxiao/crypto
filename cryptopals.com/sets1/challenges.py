# coding: utf-8
import binascii
from collections import Counter
from base64 import b64encode as b6e, b64decode as b6d


def s1c1():
    print b64encode(binascii.unhexlify('49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d'))


def s1c2():
    pass
    
def s1c3():
    s3 = '1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736'
    nums = binascii.unhexlify(s3)
    strings = []
    for key in range(128):
        strings.append(''.join(chr(ord(num) ^ key) for num in nums))
    print max(strings, key=lambda s: s.count(' '))


def s1c4():
    with open('s1c4.txt') as input:
        lines = input.readlines()
        for key in range(128):
            for line in lines:
                nums = binascii.unhexlify(line.strip())
                st = ''.join(chr(ord(num) ^ key) for num in nums)
                if len(st.split(' ')) > 5:
                    print st
            print '----------------', key
    # answer: Now that the party is jumping


def xor_repeat_key(s, k):
    target = ''
    m = len(k) # as mod
    for i, ss in enumerate(s):
        target += hex(int(binascii.hexlify(ss), 16) ^
                      int(binascii.hexlify(k[i % m]), 16))[2:]
    return target


def chunks(l, n=2):
    for i in range(0, len(l), n):
        yield l[i: i+n]

# chuncks=lambda l, n: (l[i: i+n] for i in range(0, len(l), n))


def decrypt_repeat_key(hexs, k):
    print 'decrypt with key:', k
    m = len(k)
    hexk = [binascii.hexlify(s) for s in k]
    target = ''
    for i, s in enumerate(chunks(hexs, 2)):
        target += chr(int(s, 16) ^ int(hexk[i % m], 16))
    print target


def s1c5():
    s = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
    s = '''ICE'''
    k = 'ICE'
    encrypt = xor_repeat_key(s, k)
    print encrypt
    print(decrypt_repeat_key(encrypt, k))

def test_s1c5():
    email = '''致全体的小仙女们：

在5.25我爱我女性职场健康关怀日这天，生命将与各位小仙女分享如何更好地爱自己。

时间：5月25日（周五） 14:00-16:00
地点：一号楼2楼会议室1-2

我们准备了超暖心内容，涵盖精致女孩保养术、神奇的基因一探究竟、深扒HPV疫苗的前世今生以及专属福利大放送 ！ 
此外还为现场每位伙伴准备了价值799元的皮肤管理大礼包，通通等你来PICK! 
期待你们的到来！详情请见如下活动海报。

*现场进行女性基因检测内部优惠购
*本场皮肤管理代金券由绿叶爱丽美医疗美容提供'''
    key = 'test'
    a = xor_repeat_key(email, key)
    print a
    print decrypt_repeat_key(a, key)


def hamming_dis(str1, str2):
    assert len(str1) == len(str2)
    int1 = int(binascii.hexlify(str1), 16)
    int2 = int(binascii.hexlify(str2), 16)
    return Counter(bin(int1 ^ int2))['1']


def s1c6():
    with open('s1c6.txt') as input:
        raw = ''.join([line.strip() for line in input.readlines()])
        print raw

def test():
    email = '''致众安全体的小仙女们：

在5.25我爱我女性职场健康关怀日这天，众安生命将与各位小仙女分享如何更好地爱自己。

时间：5月25日（周五） 14:00-16:00
地点：一号楼2楼会议室1-2

我们准备了超暖心内容，涵盖精致女孩保养术、神奇的基因一探究竟、深扒HPV疫苗的前世今生以及专属福利大放送 ！ 
此外还为现场每位伙伴准备了价值799元的皮肤管理大礼包，通通等你来PICK! 
期待你们的到来！详情请见如下活动海报。

*现场进行女性基因检测内部优惠购
*本场皮肤管理代金券由绿叶爱丽美医疗美容提供'''
    key = 'luxiao'
    a = xor_repeat_key(email, key)
    print a
    print decrypt_repeat_key(a, key)

    
def main():
    s1c5()


if __name__ == '__main__':
    main()
