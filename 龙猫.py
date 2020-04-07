# @Time : 2020/3/30 11:31 
# @Author : 老飞机
# @File : 龙猫.py 
# @Software: PyCharm

from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import algorithms
from threading import Thread
from Crypto.Cipher import AES
from binascii import b2a_hex, a2b_hex
import requests
import json

'''
AES/CBC/PKCS7Padding 加密解密
环境需求:
pip3 install pycryptodome
'''

class PrpCrypt(object):

    def __init__(self, key='625202f9149e061d'):
        self.key = key.encode('utf-8')
        self.mode = AES.MODE_CBC
        self.iv = b'5efd3f6060e20330'
        self.short_video_url = 'https://lmavh8r.xyz/api/Shortfilm/lists'#短片列表
        self.video_url = 'https://lmavh8r.xyz/api/Shortfilm/detail'#短片解析

        self.video_log_url = 'https://lmavh8r.xyz/api/Featurefilm/detail'#长片解析
        self.long_url = 'https://lmavh8r.xyz/api/Featurefilm/lists'#79  长片列表
        self.headers = {'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.149 Safari/537.36'}
        # block_size 128位

    # 加密函数，如果text不足16位就用空格补足为16位，
    # 如果大于16但是不是16的倍数，那就补足为16的倍数。
    def encrypt(self, text):
        cryptor = AES.new(self.key, self.mode, self.iv)
        text = text.encode('utf-8')

        # 这里密钥key 长度必须为16（AES-128）,24（AES-192）,或者32 （AES-256）Bytes 长度
        # 目前AES-128 足够目前使用

        text=self.pkcs7_padding(text)

        self.ciphertext = cryptor.encrypt(text)

        # 因为AES加密时候得到的字符串不一定是ascii字符集的，输出到终端或者保存时候可能存在问题
        # 所以这里统一把加密后的字符串转化为16进制字符串
        return b2a_hex(self.ciphertext).decode().upper()

    @staticmethod
    def pkcs7_padding(data):
        if not isinstance(data, bytes):
            data = data.encode()

        padder = padding.PKCS7(algorithms.AES.block_size).padder()

        padded_data = padder.update(data) + padder.finalize()

        return padded_data

    @staticmethod
    def pkcs7_unpadding(padded_data):
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        data = unpadder.update(padded_data)

        try:
            uppadded_data = data + unpadder.finalize()
        except ValueError:
            raise Exception('无效的加密信息!')
        else:
            return uppadded_data

    # 解密后，去掉补足的空格用strip() 去掉
    def decrypt(self, text):
        #  偏移量'iv'
        cryptor = AES.new(self.key, self.mode, self.iv)
        plain_text = cryptor.decrypt(a2b_hex(text))
        # return plain_text.rstrip('\0')
        return bytes.decode(plain_text).rstrip("\x01").\
            rstrip("\x02").rstrip("\x03").rstrip("\x04").rstrip("\x05").\
            rstrip("\x06").rstrip("\x07").rstrip("\x08").rstrip("\x09").\
            rstrip("\x0a").rstrip("\x0b").rstrip("\x0c").rstrip("\x0d").\
            rstrip("\x0e").rstrip("\x0f").rstrip("\x10")

    #处理请求短片
    def get_html_data(self,a):
        for c in range(50):
            try:
                for i in range(1,158):
                    page = '{"kind_id":"","page":%s,"label_id":"","writer_id":"","date":""}'%i#158
                    data = self.encrypt(page)
                    data1 = {'params': data}
                    response = requests.post(url = self.short_video_url , headers = self.headers , data = data1,timeout = 2.5).text
                    decrypt_data = json.loads(str(self.decrypt(response)))['data']['data']
                    for jon in decrypt_data[:-1]:
                        id1 = jon['id']
                   #     print(id1)
                        self.video_m3u8(id1)
                break
            except Exception as d:
                print("短片列表请求超时",'正在重试',c)

    # 解析短片视频
    def video_m3u8(self,ID1):
        for a in range(50):
            try:
                video_data = '{"id":%s}'%ID1
                v_data = self.encrypt(video_data)
                video_response = requests.post(url = self.video_url , headers = self.headers,data = {'params': v_data},timeout = 2.5).text
                decrypt_data = json.loads(str(self.decrypt(video_response)))['data']['data']
                title = decrypt_data['name']
                image = decrypt_data['image']
                url1 = decrypt_data['url']#流畅
                vip_url = decrypt_data['vip_url']#高清
                download_mp4 = decrypt_data['download_url']#mp4
                zhousi_url = decrypt_data['zhousi_url']#宙斯浏览器专用
                xunlei_download_url = decrypt_data['xunlei_download_url']#迅雷直链
                aggregate = '''
                <h2><div><p class="txt">{}</p><img src="{}">
                <a class="chain" href = "{}">流畅画质</ a>
                <a class="chain" href = "{}">最高画质</a>
                <a class="chain" href = "{}">mp4格式</a>
                <a class="chain" href = "{}">宙斯浏览器播放</a>
                <a class="chain" href = "{}">迅雷下载</a>
                </div></h2>\n'''.format(title,image,url1,vip_url,download_mp4,zhousi_url,xunlei_download_url)
                print('=' * 34, '当前在爬短片', '=' * 35)
                print(aggregate)
                with open('短片.html', 'a')as f:
                    f.write(aggregate)
                break

            except Exception as d:
                print("短片请求超时",d)

    #处理请求长片列表
    def get_long_html_data(self,a):
        for c in range(50):
            try:
                for i in range(1,74):
                    page = '{"kind_id":"","cup":"","type_id":"","page":%s,"label_id":"","sort":"1","distributor_id":""}'%i#74
                    data = self.encrypt(page)
                    data1 = {'params': data}
                    response = requests.post(url = self.long_url , headers = self.headers , data = data1,timeout = 2.5).text
                    decrypt_data = json.loads(str(self.decrypt(response)))['data']['data']
                    for jon in decrypt_data[:-1]:
                        id1 = jon['id']
                        self.long_video_m3u8(id1)
                      #  print(id1)
                break
            except Exception as d:
                print("长片列表请求超时",'正在重试',c)

    #解析长片视频
    def long_video_m3u8(self,ID1):
        for a in range(50):
            try:
                video_data = '{"id":%s}'%ID1
                v_data = self.encrypt(video_data)
                video_response = requests.post(url = self.video_log_url , headers = self.headers,data = {'params': v_data},timeout = 2.5).text
                decrypt_data = json.loads(str(self.decrypt(video_response)))['data']['data']
                title = decrypt_data['name']
                image = decrypt_data['image']
                url1 = decrypt_data['url']#流畅
                vip_url = decrypt_data['vip_url']#高清
                download_mp4 = decrypt_data['download_url']#mp4
                zhousi_url = decrypt_data['zhousi_url']#宙斯浏览器专用
                xunlei_download_url = decrypt_data['xunlei_download_url']#迅雷直链
                aggregate = '''
                <h2><div><p class="txt">{}</p><img src="{}">
                <a class="chain" href = "{}">流畅画质</ a>
                <a class="chain" href = "{}">最高画质</a>
                <a class="chain" href = "{}">mp4格式</a>
                <a class="chain" href = "{}">宙斯浏览器播放</a>
                <a class="chain" href = "{}">迅雷下载</a>
                </div></h2>\n'''.format(title, image, url1, vip_url, download_mp4, zhousi_url, xunlei_download_url)
                print('=' * 34, '当前在爬长片', '=' * 35)
                print(aggregate)
                with open('长片.html', 'a')as f:
                    f.write(aggregate)
                break

            except Exception as d:
                print("长片请求超时",d)
    def run(self):
        t = Thread(target=self.get_html_data, args=('线程1',))
        t.start()
        t1 = Thread(target=self.get_long_html_data, args=('线程2',))
        t1.start()

# 加解密
if __name__ == '__main__':
    html = '''
    <title>测试</title>

    <style>
    .chain{
    	text-align:center;
    	display: inline-block;
    	padding: 25px 0;
    	text-decoration: none;
    	overflow: hidden;
    	text-overflow: ellipsis;
    	white-space: nowrap;
    	background-color: #888;
    	border-radius: 25px;
    	font-size: 25px;
    	color: #eee;
    }


    .txt{
    text-align:center;
    margin: 0px 0% 0 0%;
    <!--居中-->}

    .chain{
    	width: 28%;
    	margin: 15px 2% 0 2%;
    <!--控件大小-->}	
    .boss div{
        width:100%;
        border:solid 3px gray;
        float:left;}
    .boss div img{
    display:block;
    width:100%;}

    </style>
    <body>

    <div class="boss">
        '''
    with open('短片.html', 'w+')as f:
        f.write(html + '\n')
    with open('长片.html', 'w+')as f:
        f.write(html + '\n')
    pc = PrpCrypt('625202f9149e061d')  # 初始化密钥
    pc.run()
