AES256加解密规格

key = 共享密钥
pw=hexlify(aes256(key, pw))
加密规格：AES256，block_size=16 MODE_CBC 随机向量iv（16字节）
对齐（PKCS7padding）：s + (block_size - len(s) % block_size) * chr(block_size - len(s) % block_size)

01

02 02

03 03 03

04 04 04 04

05 05 05 05 05

06 06 06 06 06 06

...


详细加密过程：先对原始字节raw进行对齐，对齐后，随机一个初始向量IV，生成一个AES256的密钥，AES.new(key, AES.MODE_CBC, IV)， 调用AES.encrypt(pad(raw))得到二进制密文cipher，hexlify(IV+cipher)输出。解密反之。
请使用如下示例进行加密算法测试：
key = 'f180eb1071f43a2b8c79be00edc8cd4bba115896947c9585287955dcd08d83f1'
iv = '99aee03df9aee3f1213c263cd7782fc1'
密钥和iv是十六进制格式，需要对其反十六进制进行处理，拿到真实密钥和随机向量才能使用。以下是反十六进制之后的iv和key字节：

iv = '\x99\xae\xe0=\xf9\xae\xe3\xf1!<&<\xd7x/\xc1'

key = '\xf1\x80\xeb\x10q\xf4:+\x8cy\xbe\x00\xed\xc8\xcdK\xba\x11X\x96\x94|\x95\x85(yU\xdc\xd0\x8d\x83\xf1'

 

plain = '123456abcd'

最终加密结果：99aee03df9aee3f1213c263cd7782fc10f59605dfc1386c8d44cd7f3ae1717c0

注： 标红部分是本次加密的随机向量iv
