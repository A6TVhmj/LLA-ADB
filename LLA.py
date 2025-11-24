import os
import sys
import json
import threading
import subprocess
import re
from time import time
from random import choice
from base64 import b64decode
from hashlib import md5
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from tkinter import filedialog, messagebox, StringVar, DoubleVar, Listbox, Scrollbar, PhotoImage
from tkinter.constants import *
from ttkbootstrap import Style, Window, Frame, Label, Button, Entry, Combobox, Progressbar, Text, Menu, Toplevel
from requests import get, post, utils
def resource_path(relative_path):
    try:
        base_path = sys._MEIPASS  # PyInstaller临时文件夹
    except Exception:
        base_path = os.path.dirname(os.path.abspath(__file__))  # 正常运行时的路径
    return os.path.join(base_path, relative_path)
class SongInfo:
    def __init__(self, song_id=None, name=None, artists=None, album=None, url=None, pic_url=None, 
                 quality=None, size=None, file_path=None, duration=0):
        self.id = song_id
        self.name = name
        self.artists = artists
        self.album = album
        self.url = url
        self.pic_url = pic_url
        self.quality = quality
        self.size = size
        self.file_path = file_path
        self.duration = duration
    
    def get_display_name(self):
        """获取显示名称"""
        name = f"{self.artists} - {self.name}"
        if self.album:
            name += f" ({self.album})"
        if self.quality:
            name += f" [{self.quality}]"
        return name
class BilibiliVideoDownloader:
    SECRET_KEY = "5Q0NvQxD0zdQ5RLQy5xs"  # 签名使用的密钥
    DECRYPT_KEY = "12345678901234567890123456789013"  # 解密使用的32字节密钥
    XOR_KEY = 0x5a  # XOR操作使用的密钥
    STANDARD_B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    CUSTOM_B64 = "P3xL7mKb8nZ5vF2dRqYtJ1GcV4iW0g6Ae9pUfEhHjSaCpTNOXQDyMkIlBsuozrw+"
    def __init__(self, parent_window):
        self.parent = parent_window
        self.window = None
        self.temp_download_dir = os.path.join(os.path.expanduser("~"), "BilibiliTemp")
        os.makedirs(self.temp_download_dir, exist_ok=True)
        self.on_files_downloaded = None
        self.is_downloading = False
        self.download_thread = None
        
    def show(self):
        """显示下载器窗口"""
        if self.window is not None and self.window.winfo_exists():
            self.window.focus()
            return
        
        self.window = Toplevel(self.parent)
        self.window.title("Bilibili视频下载器")
        self.window.geometry("600x400")
        self.window.resizable(False, False)
        self.window.transient(self.parent)

        icon_path = resource_path("icon.png")
        if os.path.exists(icon_path):
            icon_image = PhotoImage(file=icon_path)
            self.window.iconphoto(False, icon_image)
        
        # 设置主题
        self.style = Style()
        
        self.create_widgets()
        
        # 设置窗口关闭事件
        self.window.protocol("WM_DELETE_WINDOW", self.on_close)
    def create_widgets(self):
        """创建控件"""
        main_frame = Frame(self.window, padding=20)
        main_frame.pack(fill="both", expand=True)
        
        # 输入行
        input_row = Frame(main_frame)
        input_row.pack(fill="x", pady=(0, 10))
        
        Label(input_row, text="Bilibili视频链接:", width=15, anchor="e").pack(side="left", padx=(0, 5))
        self.url_entry = Entry(input_row, width=40)
        self.url_entry.pack(side="left", padx=2)
        
        Button(input_row, text="解析并下载", command=self.start_download, style="primary.TButton", width=12).pack(side="left", padx=5)
        
        # 信息显示区域
        self.info_text = Text(main_frame, height=15, width=70, relief="solid", borderwidth=1, state="disabled")
        self.info_text.pack(fill="both", expand=True)
        # 状态和进度
        status_frame = Frame(main_frame)
        status_frame.pack(fill="x", pady=10)
        self.status_label = Label(status_frame, text="就绪", foreground="#666")
        self.status_label.pack(side="left")
        self.cancel_button = Button(status_frame, text="取消下载", command=self.cancel_download,
                           style="danger.TButton", width=10, state="disabled")
        self.cancel_button.pack(side="right", padx=10)
        self.progress_var = DoubleVar(value=0)
        self.progressbar = Progressbar(status_frame, variable=self.progress_var, maximum=100,
                                        style="success.Horizontal.Tprogressbar")
        self.progressbar.pack(side="right", fill="x", expand=True, padx=10)
    def start_download(self):
        """开始下载视频"""
        if self.is_downloading:
            messagebox.showwarning("警告", "已有下载任务进行中")
            return
        video_url = self.url_entry.get().strip()
        if not video_url:
            messagebox.showwarning("输入错误", "请输入Bilibili视频链接")
            return
        if not ("bilibili.com" in video_url or "b23.tv" in video_url):
            if messagebox.askyesno("URL验证", "输入的链接似乎不是Bilibili链接，是否继续？"):
                pass
            else:
                return
                
        self.is_downloading = True
        self.root_after(lambda: self.cancel_button.config(state="normal"))
        self.download_thread = threading.Thread(target=self._download_thread, args=(video_url,), daemon=True)
        self.download_thread.start()
    def cancel_download(self):
        """取消当前下载"""
        if self.is_downloading:
            self.is_downloading = False
            self.root_after(lambda: self.status_label.config(text="正在取消下载..."))
    def _download_thread(self, video_url):
        """下载视频线程"""
        self.root_after(lambda: self.progressbar.pack(fill="x", pady=5))
        self.root_after(lambda: self.progress_var.set(0))
        
        try:
            # 步骤1: 解析URL
            self.root_after(lambda: self.status_label.config(text="正在解析视频链接..."))
            self.root_after(lambda: self.progress_var.set(10))
            
            result = self.parse_video_url(video_url)
            if not result or result.get("status") != 0 or "data" not in result:
                error_msg = result.get("msg", "解析失败") if result else "无效的API响应"
                raise ValueError(f"视频解析失败: {error_msg}")
            
            data = result["data"]
            video_url = data.get("url")
            title = data.get("title", "未命名视频")
            
            if not video_url:
                raise ValueError("未找到有效的视频下载链接")
            
            # 显示视频信息
            info_text = f"标题: {title}\n状态: 准备下载..."
            self.root_after(lambda: self.update_info_text(info_text))
            
            # 步骤2: 下载视频
            self.root_after(lambda: self.status_label.config(text="正在下载视频..."))
            self.root_after(lambda: self.progress_var.set(20))
            
            saved_file = self.save_video(video_url, title)
            if not saved_file:
                raise ValueError("视频下载失败或被取消")
            
            # 步骤3: 完成
            file_size = os.path.getsize(saved_file) / (1024 * 1024)
            info_text = f"标题: {title}\n大小: {file_size:.2f} MB\n状态: 下载完成\n保存位置: {saved_file}"
            self.root_after(lambda: self.update_info_text(info_text))
            
            self.root_after(lambda: self.status_label.config(text=f"下载完成: {os.path.basename(saved_file)}"))
            self.root_after(lambda: self.progress_var.set(100))
            
            # 触发回调
            if self.on_files_downloaded:
                self.root_after(lambda: self.on_files_downloaded([saved_file]))
                
        except Exception as e:
            if self.is_downloading:  # 只有在未取消的情况下才显示错误
                self.root_after(lambda: self.status_label.config(text=f"下载失败: {str(e)}"))
                self.root_after(lambda e=e: messagebox.showerror("错误", f"下载失败: {str(e)}"))
        finally:
            self.root_after(lambda: self.progressbar.pack_forget())
            self.root_after(lambda: self.progress_var.set(0))
            self.is_downloading = False
            self.root_after(lambda: self.cancel_button.config(state="disabled"))

    def generate_signature(self, params, salt, ts, secret_key):
        """
        生成MD5签名，与JS中的generateSignatureWithMD5函数功能一致
        """
        replace_bd= lambda s:s.replace('b', '#').replace('d', 'b').replace('#', 'd')
        # 1. 获取参数对象的所有键并按字母顺序排序
        sorted_keys = sorted(params.keys())
        
        # 2. 将键值对转换为URL查询字符串格式
        query_items = [f"{key}={params[key]}" for key in sorted_keys]
        query_string = "&".join(query_items)
        
        # 3. 拼接签名字符串
        sign_str = f"{query_string}&salt={salt}&ts={ts}&secret={secret_key}"
        
        # 4. 计算MD5哈希
        md5_hash = md5(sign_str.encode('utf-8')).hexdigest()
        
        # 5. 应用字符替换混淆（b和d互换）
        return replace_bd(md5_hash)

    def generate_signed_params(self, request_url, captcha_key="", captcha_input="", user_id=None):
        """
        生成带签名的请求参数
        """
        # 准备基础参数
        params = {
            "requestURL": request_url,
            "captchaKey": captcha_key,
            "captchaInput": captcha_input
        }
        
        if user_id:
            params["userID"] = user_id
        
        # 生成时间戳(秒级)
        ts = int(time())
        
        # 生成随机salt (8位16进制)
        salt = ''.join(choice('0123456789abcdef') for _ in range(8))
        
        # 生成签名
        sign = self.generate_signature(params, salt, ts, self.SECRET_KEY)
        
        # 添加签名参数
        params["ts"] = ts
        params["salt"] = salt
        params["sign"] = sign
        
        return params

    def decrypt_response(self, encrypted_data: str, iv: str, key: str = DECRYPT_KEY) -> dict:
        """
        解密 Kukude 加密的响应数据
        """
        
        def xor_string(s: str, key: int = 0x5a) -> str:
            return ''.join(chr(ord(c) ^ key) for c in s)
        
        def block_reverse(s: str, block_size: int = 8) -> str:
            return ''.join(
                s[i:i+block_size][::-1] 
                for i in range(0, len(s), block_size)
            )
        
        def base64_custom_decode(s: str) -> str:
            custom_charset = "ZYXABCDEFGHIJKLMNOPQRSTUVWzyxabcdefghijklmnopqrstuvw9876543210-_"
            std_charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
            mapping = str.maketrans(custom_charset, std_charset)
            return s.translate(mapping)
        
        try:
            # 预处理密文数据
            data = xor_string(encrypted_data)
            data = block_reverse(data)
            data = base64_custom_decode(data)
            ciphertext = b64decode(data)  # 标准 Base64 解码

            iv_data = xor_string(iv)
            iv_data = block_reverse(iv_data)
            iv_data = base64_custom_decode(iv_data)
            iv_bytes = b64decode(iv_data)  # 标准 Base64 解码
            if len(iv_bytes) != 16:
                raise ValueError(f"Invalid IV length: {len(iv_bytes)} bytes (expected 16)")

            key_bytes = key.encode('utf-8')
            cipher = AES.new(key_bytes, AES.MODE_CBC, iv=iv_bytes)
            decrypted = cipher.decrypt(ciphertext)

            unpadded = unpad(decrypted, AES.block_size)

            return json.loads(unpadded.decode('utf-8'))
        
        except (ValueError, json.JSONDecodeError, UnicodeDecodeError) as e:
            raise ValueError(f"数据解密失败: {str(e)}") from e

    def parse_video_url(self, video_url):
        """
        解析视频URL，获取无水印视频
        """
        # 1. 生成签名参数
        signed_params = self.generate_signed_params(video_url)
        
        # 2. 发送请求
        url = "https://dy.kukutool.com/api/parse"
        headers = {
            "Content-Type": "application/json",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
            "Origin": "https://dy.kukutool.com",
            "Referer": "https://dy.kukutool.com/"
        }
        
        try:
            response = post(url, data=json.dumps(signed_params), headers=headers, verify=False)
            response.raise_for_status()
            
            # 3. 解析响应
            result = response.json()
            
            # 4. 检查是否需要解密
            if "encrypt" in result and result["encrypt"] and "data" in result and "iv" in result:
                decrypted_data = self.decrypt_response(result["data"], result["iv"])
                result["data"] = decrypted_data
            return result
        except Exception as e:
            self.root_after(lambda e=e:messagebox.showerror("错误", f"解析视频URL失败: {str(e)}"))
            return None

    def save_video(self, video_url, title):
        """保存视频到本地"""
        try:
            headers = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36"
            }
            response = get(video_url, headers=headers, stream=True, timeout=60)
            response.raise_for_status()
            
            # 清理文件名
            safe_title = re.sub(r'[\\/*?:"<>|]', '', title)
            safe_title = safe_title[:100]  # 限制文件名长度
            filename = f"{safe_title}.mp4"
            file_path = os.path.join(self.temp_download_dir, filename)
            
            # 获取内容长度
            content_length = response.headers.get('Content-Length')
            total_size = int(content_length) if content_length else None
            downloaded_size = 0
            start_time = time()
            last_update_time = start_time
            last_downloaded = 0
            with open(file_path, 'wb') as f:
                for chunk in response.iter_content(chunk_size=16384):
                    if not self.is_downloading:
                        f.close()
                        if os.path.exists(file_path):
                            os.remove(file_path)
                        self.root_after(self.info_text.config(text="就绪"))
                        return None
                    if chunk:
                        f.write(chunk)
                        downloaded_size += len(chunk)
                        if total_size:
                            progress = 20 + (downloaded_size / total_size * 80)
                            self.root_after(lambda p=progress: self.progress_var.set(p))
                    current_time = time()
                    if current_time - last_update_time > 1:  # 每秒更新一次
                        downloaded_this_second = downloaded_size - last_downloaded
                        speed = downloaded_this_second / (current_time - last_update_time) / 1024  # KB/s
                        speed_text = f"{speed:.1f} KB/s" if speed < 1024 else f"{speed/1024:.1f} MB/s"
                        self.root_after(lambda s=speed_text: self.status_label.config(text=f"下载速度: {s}"))
                        last_update_time = current_time
                        last_downloaded = downloaded_size
            return file_path
        except Exception as e:
            raise Exception(f"视频保存失败: {str(e)}")

    def update_info_text(self, text):
        """更新信息文本"""
        self.info_text.config(state="normal")
        self.info_text.delete(1.0, END)
        self.info_text.insert(END, text)
        self.info_text.config(state="disabled")
    
    def root_after(self, callback):
        """在主线程中执行回调"""
        if self.window and self.window.winfo_exists():
            self.window.after(0, callback)
    
    def on_close(self):
        """窗口关闭事件"""
        if self.is_downloading:
            if messagebox.askyesno("确认", "有下载任务正在进行，确定要关闭吗？"):
                self.is_downloading = False
                self.root_after(lambda: self.cancel_button.config(state="disabled"))
                self.window.destroy()
                self.window = None
        else:
            self.window.destroy()
            self.window = None
class NeteaseMusicDownloader:
    def __init__(self, parent_window):
        self.parent = parent_window
        self.window = None
        self.current_songs = []
        self.search_results = []
        self.temp_download_dir = os.path.join(os.path.expanduser("~"), "NeteaseMusicTemp")
        os.makedirs(self.temp_download_dir, exist_ok=True)
        
        # API配置
        self.api_base_url = "https://wyapi.toubiec.cn"
        self.search_api_url = "https://apis.netstart.cn/music/search"
        
        # 设置请求头为实例变量
        self.headers = {
            'Content-Type': 'application/json',
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Referer': 'https://wyapi.toubiec.cn/',
            'Origin': 'https://wyapi.toubiec.cn',
            'Sec-Fetch-Mode': 'cors',  
            'Sec-Fetch-Site': 'same-origin',
        }
        
        self.current_page = 1
        self.total_pages = 1
        self.page_size = 20
        
        self.on_files_downloaded = None
    
    def show(self):
        """显示下载器窗口"""
        if self.window is not None and self.window.winfo_exists():
            self.window.focus()
            return
        
        self.window = Toplevel(self.parent)
        self.window.title("网易云音乐下载器")
        self.window.geometry("700x800")
        self.window.resizable(False, False)
        self.window.transient(self.parent)

        icon_path = resource_path("icon.png")
        if os.path.exists(icon_path):
            icon_image = PhotoImage(file=icon_path)
            self.window.iconphoto(False, icon_image)
        
        # 设置主题
        self.style = Style()
        self.style.configure("success.TButton", font=("Helvetica", 10))
        self.style.configure("warning.TButton", font=("Helvetica", 10))
        self.style.configure("danger.TButton", font=("Helvetica", 10))
        self.style.configure("primary.TButton", font=("Helvetica", 10))
        self.style.configure("info.TButton", font=("Helvetica", 10))
        
        self.create_widgets()
        
        # 设置窗口关闭事件
        self.window.protocol("WM_DELETE_WINDOW", self.on_close)
    
    def on_close(self):
        """窗口关闭事件"""
        self.window.destroy()
        self.window = None
    
    def create_widgets(self):
        """创建控件"""
        main_frame = Frame(self.window, padding=20)
        main_frame.pack(fill="both", expand=True)
        
        # 搜索区域
        search_frame = Frame(main_frame)
        search_frame.pack(fill="x", pady=(0, 15))
        
        # 搜索行
        search_row = Frame(search_frame)
        search_row.pack(fill="x", pady=2)
        
        Label(search_row, text="搜索音乐:", width=12, anchor="e").pack(side="left", padx=(0, 5))
        self.search_entry = Entry(search_row, width=30)
        self.search_entry.pack(side="left", padx=2)
        self.search_entry.bind("<Return>", lambda e: self.search_music())
        
        Button(search_row, text="搜索", command=self.search_music, style="primary.TButton", width=8).pack(side="left", padx=2)
        
        self.search_result_label = Label(search_row, text="共找到 0 首歌曲", foreground="#666")
        self.search_result_label.pack(side="left", padx=10)
        
        # 分页控件
        pagination_frame = Frame(search_row)
        pagination_frame.pack(side="right")
        
        self.prev_page_btn = Button(pagination_frame, text="<", command=self.prev_page, width=3, state="disabled")
        self.prev_page_btn.pack(side="left", padx=2)
        
        self.page_info_label = Label(pagination_frame, text="1/1")
        self.page_info_label.pack(side="left", padx=5)
        
        self.next_page_btn = Button(pagination_frame, text=">", command=self.next_page, width=3, state="disabled")
        self.next_page_btn.pack(side="left", padx=2)
        
        # 链接解析行
        url_row = Frame(search_frame)
        url_row.pack(fill="x", pady=2)
        
        Label(url_row, text="或输入歌曲链接:", width=12, anchor="e").pack(side="left", padx=(0, 5))
        self.url_entry = Entry(url_row, width=30, foreground="#999")
        self.url_entry.pack(side="left", padx=2)
        self.url_entry.insert(0, "请输入歌曲链接")
        self.url_entry.bind("<FocusIn>", self.on_url_focus_in)
        self.url_entry.bind("<FocusOut>", self.on_url_focus_out)
        
        Button(url_row, text="解析链接", command=self.parse_url, style="info.TButton", width=8).pack(side="left", padx=2)
        
        # 歌单链接行
        playlist_row = Frame(search_frame)
        playlist_row.pack(fill="x", pady=2)
        
        Label(playlist_row, text="或输入歌单链接:", width=12, anchor="e").pack(side="left", padx=(0, 5))
        self.playlist_entry = Entry(playlist_row, width=30, foreground="#999")
        self.playlist_entry.pack(side="left", padx=2)
        self.playlist_entry.insert(0, "请输入歌单链接")
        self.playlist_entry.bind("<FocusIn>", self.on_playlist_focus_in)
        self.playlist_entry.bind("<FocusOut>", self.on_playlist_focus_out)
        
        Button(playlist_row, text="解析歌单", command=self.parse_playlist, style="info.TButton", width=8).pack(side="left", padx=2)
        
        # 专辑链接行
        album_row = Frame(search_frame)
        album_row.pack(fill="x", pady=2)
        
        Label(album_row, text="或输入专辑链接:", width=12, anchor="e").pack(side="left", padx=(0, 5))
        self.album_entry = Entry(album_row, width=30, foreground="#999")
        self.album_entry.pack(side="left", padx=2)
        self.album_entry.insert(0, "请输入专辑链接")
        self.album_entry.bind("<FocusIn>", self.on_album_focus_in)
        self.album_entry.bind("<FocusOut>", self.on_album_focus_out)
        
        Button(album_row, text="解析专辑", command=self.parse_album, style="info.TButton", width=8).pack(side="left", padx=2)
        
        # 音质选择
        quality_row = Frame(search_frame)
        quality_row.pack(fill="x", pady=2)
        
        Label(quality_row, text="音质:", width=12, anchor="e").pack(side="left", padx=(0, 5))
        self.quality_var = StringVar(value="无损")
        self.quality_combo = Combobox(quality_row, textvariable=self.quality_var, width=15, 
                                     values=["标准", "极高", "无损", "Hi-Res", "高清环绕"], state="readonly")
        self.quality_combo.pack(side="left", padx=2)
        
        # 搜索结果区域
        result_frame = Frame(main_frame)
        result_frame.pack(fill="both", expand=True, pady=(0, 10))
        
        # 搜索结果列表
        Label(result_frame, text="搜索结果", font=("Helvetica", 10, "bold")).pack(anchor="w", pady=(0, 5))
        
        list_frame = Frame(result_frame)
        list_frame.pack(fill="both", expand=True)
        
        # 创建列表框 - 使用标准tkinter Listbox
        self.search_listbox = Listbox(list_frame, height=10, width=80, selectmode="extended")
        self.search_listbox.pack(side="left", fill="both", expand=True)
        
        # 添加滚动条
        scrollbar = Scrollbar(list_frame, orient="vertical", command=self.search_listbox.yview)
        scrollbar.pack(side="right", fill="y")
        self.search_listbox.config(yscrollcommand=scrollbar.set)
        
        # 双击添加到下载列表
        self.search_listbox.bind("<Double-1>", lambda e: self.add_selected_to_download())
        
        # 操作区域
        action_frame = Frame(main_frame)
        action_frame.pack(fill="x", pady=5)
        
        # 添加到下载列表按钮
        Button(action_frame, text="添加到下载列表", command=self.add_selected_to_download, 
               style="success.TButton", width=15).pack(side="left", padx=2)
        
        # 清除列表按钮
        Button(action_frame, text="清除下载列表", command=self.clear_download_list, 
               style="danger.TButton", width=15).pack(side="left", padx=2)
        
        # 下载按钮
        self.download_btn = Button(action_frame, text="下载全部", command=self.download_all_songs, 
                                  style="warning.TButton", width=15, state="disabled")
        self.download_btn.pack(side="right", padx=2)
        
        # 歌曲信息区域
        info_frame = Frame(main_frame)
        info_frame.pack(fill="both", expand=True, pady=(10, 0))
        
        Label(info_frame, text="下载管理", font=("Helvetica", 10, "bold")).pack(anchor="w", pady=(0, 5))
        
        # 歌曲信息显示
        self.info_text = Text(info_frame, height=6, width=80, relief="solid", borderwidth=1, state="disabled")
        self.info_text.pack(fill="both", expand=True, pady=(0, 10))
        
        # 下载列表
        Label(info_frame, text="下载列表", font=("Helvetica", 10, "bold")).pack(anchor="w", pady=(0, 5))
        
        # 使用标准tkinter Listbox
        self.download_listbox = Listbox(info_frame, height=8, width=80, selectmode="extended")
        self.download_listbox.pack(fill="both", expand=True)
        
        # 状态和进度
        status_frame = Frame(main_frame)
        status_frame.pack(fill="x", pady=10)
        
        self.status_label = Label(status_frame, text="就绪", foreground="#666")
        self.status_label.pack(side="left")
        
        self.progress_var = DoubleVar(value=0)
        self.progressbar = Progressbar(status_frame, variable=self.progress_var, maximum=100, 
                                      style="success.Horizontal.Tprogressbar")
        self.progressbar.pack(side="right", fill="x", expand=True, padx=10)
        self.progressbar.pack_forget()  # 初始隐藏
    
    def on_url_focus_in(self, event):
        """URL输入框获得焦点"""
        if self.url_entry.get() == "请输入歌曲链接":
            self.url_entry.delete(0, END)
            self.url_entry.config(foreground="#000")
    
    def on_url_focus_out(self, event):
        """URL输入框失去焦点"""
        if not self.url_entry.get():
            self.url_entry.insert(0, "请输入歌曲链接")
            self.url_entry.config(foreground="#999")
    
    def on_playlist_focus_in(self, event):
        """歌单输入框获得焦点"""
        if self.playlist_entry.get() == "请输入歌单链接":
            self.playlist_entry.delete(0, END)
            self.playlist_entry.config(foreground="#000")
    
    def on_playlist_focus_out(self, event):
        """歌单输入框失去焦点"""
        if not self.playlist_entry.get():
            self.playlist_entry.insert(0, "请输入歌单链接")
            self.playlist_entry.config(foreground="#999")
    
    def on_album_focus_in(self, event):
        """专辑输入框获得焦点"""
        if self.album_entry.get() == "请输入专辑链接":
            self.album_entry.delete(0, END)
            self.album_entry.config(foreground="#000")
    
    def on_album_focus_out(self, event):
        """专辑输入框失去焦点"""
        if not self.album_entry.get():
            self.album_entry.insert(0, "请输入专辑链接")
            self.album_entry.config(foreground="#999")
    
    def search_music(self):
        """搜索音乐"""
        keywords = self.search_entry.get().strip()
        if not keywords:
            messagebox.showwarning("输入错误", "请输入搜索关键词")
            return
        
        threading.Thread(target=self._search_music_thread, args=(keywords,), daemon=True).start()
    
    def _search_music_thread(self, keywords):
        """搜索音乐线程"""
        self.root_after(lambda: self.status_label.config(text="正在搜索..."))
        self.root_after(lambda: self.progressbar.pack(fill="x", pady=5))
        self.root_after(lambda: self.progress_var.set(10))
        
        try:
            # 构建搜索URL
            search_url = f"{self.search_api_url}?keywords={utils.quote(keywords)}&offset={(self.current_page - 1) * self.page_size}&limit={self.page_size}"
            
            # 使用实例变量headers
            response = get(search_url, headers=self.headers, timeout=15)
            response.raise_for_status()
            
            data = response.json()
            
            if data.get('code') != 200 or not data.get('result', {}).get('songs'):
                self.root_after(lambda: self.status_label.config(text="未找到相关歌曲"))
                self.root_after(lambda: self.search_result_label.config(text="共找到 0 首歌曲"))
                self.root_after(lambda: self.search_listbox.delete(0, END))
                self.root_after(lambda: self.prev_page_btn.config(state="disabled"))
                self.root_after(lambda: self.next_page_btn.config(state="disabled"))
                return
            
            result = data['result']
            songs = result['songs']
            total = result['songCount']
            
            # 计算总页数
            self.total_pages = (total + self.page_size - 1) // self.page_size
            self.total_pages = max(1, self.total_pages)
            
            # 更新当前页（确保在范围内）
            self.current_page = max(1, min(self.current_page, self.total_pages))
            
            # 清空搜索结果
            self.search_results = []
            
            # 处理搜索结果
            for song in songs:
                song_info = SongInfo(
                    song_id=str(song.get('id', '')),
                    name=song.get('name', '未知歌曲'),
                    artists=', '.join([artist.get('name', '') for artist in song.get('artists', [])]),
                    album=song.get('album', {}).get('name', '未知专辑'),
                    duration=song.get('duration', 0)
                )
                self.search_results.append(song_info)
            
            # 更新UI
            self.root_after(self.update_search_results_ui)
            self.root_after(lambda: self.status_label.config(text=f"找到 {total} 首歌曲"))
            self.root_after(lambda: self.progress_var.set(100))
            
        except Exception as e:
            self.root_after(lambda: self.status_label.config(text=f"搜索失败: {str(e)}"))
            self.root_after(lambda e=e: messagebox.showerror("错误", f"搜索失败: {str(e)}"))
        finally:
            self.root_after(lambda: self.progressbar.pack_forget())
    
    def update_search_results_ui(self):
        """更新搜索结果UI"""
        self.search_listbox.delete(0, END)
        
        for song in self.search_results:
            duration = self.format_duration(int(song.duration))
            display_text = f"{song.name} - {song.artists} ({song.album}) [{duration}]"
            self.search_listbox.insert(END, display_text)
        
        self.search_result_label.config(text=f"共找到 {len(self.search_results)} 首歌曲")
        self.page_info_label.config(text=f"{self.current_page}/{self.total_pages}")
        
        self.prev_page_btn.config(state="normal" if self.current_page > 1 else "disabled")
        self.next_page_btn.config(state="normal" if self.current_page < self.total_pages else "disabled")
    
    def format_duration(self, milliseconds: int) -> str:
        """格式化持续时间"""
        if not milliseconds:
            return "00:00"
        
        seconds = milliseconds // 1000
        minutes = seconds // 60
        seconds = seconds % 60
        return f"{minutes:02d}:{seconds:02d}"
    
    def prev_page(self):
        """上一页"""
        if self.current_page > 1:
            self.current_page -= 1
            self.search_music()
    
    def next_page(self):
        """下一页"""
        if self.current_page < self.total_pages:
            self.current_page += 1
            self.search_music()
    
    def parse_url(self):
        """解析歌曲链接"""
        url = self.url_entry.get().strip()
        if url == "请输入歌曲链接":
            messagebox.showwarning("输入错误", "请输入有效的歌曲链接")
            return
        
        threading.Thread(target=self._parse_url_thread, args=(url,), daemon=True).start()
    
    def _parse_url_thread(self, url):
        """解析歌曲链接线程"""
        self.root_after(lambda: self.status_label.config(text="正在解析..."))
        self.root_after(lambda: self.progressbar.pack(fill="x", pady=5))
        self.root_after(lambda: self.progress_var.set(10))
        
        try:
            # 提取歌曲ID
            song_id = self.extract_song_id(url)
            if not song_id:
                raise ValueError("无法从链接中提取歌曲ID")
            
            # 获取歌曲详情
            self.root_after(lambda: self.status_label.config(text="获取歌曲详情..."))
            song_detail = self.get_song_detail(song_id)
            if not song_detail:
                raise ValueError("无法获取歌曲详情")
            
            self.root_after(lambda: self.progress_var.set(50))
            self.root_after(lambda: self.status_label.config(text="获取下载链接..."))
            
            # 获取下载URL
            quality_level = self.get_quality_level(self.quality_var.get())
            song_url_info = self.get_song_url(song_id, quality_level)
            
            if not song_url_info or not song_url_info.get('url'):
                raise ValueError("无法获取歌曲下载链接")
            
            # 创建歌曲信息
            song = SongInfo(
                song_id=song_id,
                name=song_detail.get('name', '未知歌曲'),
                artists=song_detail.get('singer', '未知艺术家'),
                album=song_detail.get('album', '未知专辑'),
                pic_url=song_detail.get('picimg', ''),
                url=song_url_info.get('url', ''),
                quality=song_url_info.get('level', ''),
                size=self.format_size(song_url_info.get('size', 0)),
                duration=song_detail.get('duration', 0)
            )
            
            # 添加到下载列表
            self.root_after(lambda: self.add_song_to_download_list(song))
            
            # 显示歌曲信息
            info_text = f"歌曲: {song.name}\n艺术家: {song.artists}\n专辑: {song.album}\n时长: {song.duration}\n音质: {song.quality}\n大小: {song.size}"
            
            self.root_after(lambda: self.update_info_text(info_text))
            self.root_after(lambda: self.status_label.config(text="解析完成"))
            
        except Exception as e:
            self.root_after(lambda: self.status_label.config(text=f"解析失败: {str(e)}"))
            self.root_after(lambda e=e: messagebox.showerror("错误", f"解析失败: {str(e)}"))
        finally:
            self.root_after(lambda: self.progressbar.pack_forget())
    
    def extract_song_id(self, url):
        """提取歌曲ID"""
        # 正则表达式匹配各种格式的网易云音乐链接
        patterns = [
            r'music\.163\.com/(?:#/)?song\?id=(\d+)',
            r'y\.music\.163\.com/m/song/(\d+)',
            r'163cn\.tv/([a-zA-Z0-9]+)',
            r'(\d+)'  # 直接输入ID
        ]
        
        for pattern in patterns:
            match = re.search(pattern, url, re.IGNORECASE)
            if match:
                return match.group(1)
        
        return None
    
    def get_song_detail(self, song_id):
        """获取歌曲详情"""
        url = f"{self.api_base_url}/api/music/detail"
        
        # 使用实例变量headers
        data = json.dumps({"id": song_id})
        response = post(url, headers=self.headers, data=data, timeout=15)
        response.raise_for_status()
        
        result = response.json()
        if result.get('code') == 200:
            return result.get('data', {})
        
        return None
    
    def get_song_url(self, song_id, quality_level):
        """获取歌曲URL"""
        url = f"{self.api_base_url}/api/music/url"
        
        # 使用实例变量headers
        data = json.dumps({"id": song_id, "level": quality_level})
        response = post(url, headers=self.headers, data=data, timeout=15)
        response.raise_for_status()
        
        result = response.json()
        if result.get('code') == 200 and result.get('data'):
            return result['data'][0]  # 取第一个结果
        
        return None
    
    def get_quality_level(self, quality_name):
        """获取音质级别"""
        quality_map = {
            "标准(2~5MB)": "standard",
            "极高(5~10MB)": "exhigh", 
            "无损(10~30MB)": "lossless",
            "Hi-Res(>30MB)": "hires",
            "沉浸环绕声(>50MB)": "sky",
            "杜比全景声(>50MB)": "dolby"
        }
        return quality_map.get(quality_name, "lossless")
    
    def format_size(self, size_bytes):
        """格式化文件大小"""
        if size_bytes <= 0:
            return "未知大小"
        
        size_mb = size_bytes / (1024 * 1024)
        return f"{size_mb:.1f} MB"
    
    def add_song_to_download_list(self, song):
        """添加歌曲到下载列表"""
        if any(s.id == song.id for s in self.current_songs):
            return  # 已存在
        self.current_songs.append(song)
        self.download_listbox.insert(END, song.get_display_name())
        self.download_btn.config(state="normal")
    
    def update_info_text(self, text):
        """更新信息文本"""
        self.info_text.config(state="normal")
        self.info_text.delete(1.0, END)
        self.info_text.insert(END, text)
        self.info_text.config(state="disabled")
    
    def add_selected_to_download(self):
        """添加选中的歌曲到下载列表"""
        selected_indices = self.search_listbox.curselection()
        if not selected_indices:
            messagebox.showinfo("提示", "请先选择要添加的歌曲")
            return
        
        threading.Thread(target=self._add_selected_thread, args=(selected_indices,), daemon=True).start()
    
    def _add_selected_thread(self, selected_indices):
        """添加选中的歌曲线程"""
        self.root_after(lambda: self.status_label.config(text="正在获取歌曲信息..."))
        self.root_after(lambda: self.progressbar.pack(fill="x", pady=5))
        self.root_after(lambda: self.progress_var.set(0))
        
        try:
            total = len(selected_indices)
            for i, index in enumerate(selected_indices):
                if index < len(self.search_results):
                    song = self.search_results[index]
                    
                    # 更新进度
                    progress = (i / total) * 80
                    self.root_after(lambda p=progress: self.progress_var.set(p))
                    self.root_after(lambda i=i, t=total: self.status_label.config(text=f"处理歌曲 ({i+1}/{t})..."))
                    
                    # 获取详细信息
                    song_detail = self.get_song_detail(song.id)
                    if song_detail:
                        song.album = song_detail.get('album', song.album)
                        song.pic_url = song_detail.get('picimg', song.pic_url)
                        song.duration = song_detail.get('duration', song.duration)
                    
                    # 获取下载URL
                    quality_level = self.get_quality_level(self.quality_var.get())
                    song_url_info = self.get_song_url(song.id, quality_level)
                    
                    if song_url_info and song_url_info.get('url'):
                        song.url = song_url_info.get('url', '')
                        song.quality = song_url_info.get('level', '')
                        song.size = self.format_size(song_url_info.get('size', 0))
                    
                    # 添加到下载列表
                    if any(s.id == song.id for s in self.current_songs):
                        total -= 1  # 已存在，减少总数
                    else:
                        self.current_songs.append(song)
            
            # 更新UI
            self.root_after(self.update_download_list_ui)
            self.root_after(lambda: self.status_label.config(text=f"已添加 {total} 首歌曲到下载列表"))
            self.root_after(lambda: self.progress_var.set(100))
            
        except Exception as e:
            self.root_after(lambda: self.status_label.config(text=f"添加失败: {str(e)}"))
            self.root_after(lambda e=e: messagebox.showerror("错误", f"添加歌曲失败: {str(e)}"))
        finally:
            self.root_after(lambda: self.progressbar.pack_forget())
    
    def update_download_list_ui(self):
        """更新下载列表UI"""
        self.download_listbox.delete(0, END)
        for song in self.current_songs:
            self.download_listbox.insert(END, song.get_display_name())
        
        if self.current_songs:
            self.download_btn.config(state="normal")
    
    def clear_download_list(self):
        """清空下载列表"""
        self.current_songs = []
        self.download_listbox.delete(0, END)
        self.download_btn.config(state="disabled")
        self.update_info_text("歌曲列表已清空")
        self.status_label.config(text="已清空下载列表")
    
    def download_all_songs(self):
        """下载所有歌曲"""
        if not self.current_songs:
            messagebox.showinfo("提示", "下载列表为空")
            return
        
        threading.Thread(target=self._download_all_thread, daemon=True).start()
    
    def _download_all_thread(self):
        """下载所有歌曲线程"""
        self.root_after(lambda: self.status_label.config(text="准备下载..."))
        self.root_after(lambda: self.progressbar.pack(fill="x", pady=5))
        self.root_after(lambda: self.progress_var.set(0))
        self.root_after(lambda: self.download_btn.config(state="disabled"))
        
        downloaded_files = []
        songs_to_download = [song for song in self.current_songs if not song.file_path or not os.path.exists(song.file_path)]
        total = len(songs_to_download)

        if total == 0:
            self.root_after(lambda: self.status_label.config(text="所有歌曲都已下载完成"))
            self.root_after(lambda: self.progressbar.pack_forget())
            self.root_after(lambda: self.download_btn.config(state="normal"))
            return
        
        for i, song in enumerate(songs_to_download):
            if not song.url:
                # 尝试获取URL
                quality_level = self.get_quality_level(self.quality_var.get())
                song_url_info = self.get_song_url(song.id, quality_level)
                if song_url_info and song_url_info.get('url'):
                    song.url = song_url_info.get('url', '')
                    song.quality = song_url_info.get('level', '')
                    song.size = self.format_size(song_url_info.get('size', 0))
            
            if not song.url:
                self.root_after(lambda i=i: self.status_label.config(text=f"跳过 {self.current_songs[i].name} (URL不可用)"))
                continue
            
            try:
                # 下载文件
                self.root_after(lambda i=i, t=total: self.status_label.config(text=f"正在下载 ({i+1}/{t})..."))
                
                # 生成文件名
                is_flac = 'flac' in song.url.lower()
                file_ext = '.flac' if is_flac else '.mp3'
                filename = f"{song.name}-{song.artists}{file_ext}"
                filename = re.sub(r'[\\/*?:"<>|]', "_", filename)  # 替换非法字符
                file_path = os.path.join(self.temp_download_dir, filename)
                
                # 下载文件 - 使用实例变量headers
                response = get(song.url, headers=self.headers, stream=True, timeout=60)
                response.raise_for_status()
                
                total_size = int(response.headers.get('content-length', 0))
                downloaded_size = 0
                
                with open(file_path, 'wb') as f:
                    for chunk in response.iter_content(chunk_size=16384):
                        if chunk:
                            f.write(chunk)
                            downloaded_size += len(chunk)
                            
                            # 更新进度（文件内进度 + 文件间进度）
                            file_progress = downloaded_size / total_size if total_size > 0 else 0
                            overall_progress = ((i + file_progress) / total) * 100
                            self.root_after(lambda p=overall_progress: self.progress_var.set(p))
                
                song.file_path = file_path
                downloaded_files.append(file_path)
                
            except Exception as e:
                self.root_after(lambda i=i, e=str(e): self.status_label.config(text=f"下载失败 {self.current_songs[i].name}: {e}"))
        
        # 下载完成
        self.root_after(lambda: self.progress_var.set(100))
        self.root_after(lambda: self.status_label.config(text="下载完成"))
        self.root_after(lambda: self.download_btn.config(state="normal"))
        self.root_after(lambda: messagebox.showinfo("下载完成", f"成功下载 {len(downloaded_files)} 首歌曲到临时目录"))
        
        # 通知主程序
        if self.on_files_downloaded and downloaded_files:
            self.root_after(lambda: self.on_files_downloaded(downloaded_files))
    
    def root_after(self, callback):
        """在主线程中执行回调"""
        if self.window and self.window.winfo_exists():
            self.window.after(0, callback)
    
    def parse_playlist(self):
        """解析歌单"""
        url = self.playlist_entry.get().strip()
        if url == "请输入歌单链接":
            messagebox.showwarning("输入错误", "请输入有效的歌单链接")
            return
        
        threading.Thread(target=self._parse_playlist_thread, args=(url,), daemon=True).start()
    
    def _parse_playlist_thread(self, url):
        """解析歌单线程"""
        self.root_after(lambda: self.status_label.config(text="正在解析歌单..."))
        self.root_after(lambda: self.progressbar.pack(fill="x", pady=5))
        self.root_after(lambda: self.progress_var.set(10))
        
        try:
            # 提取歌单ID
            playlist_id = self.extract_playlist_id(url)
            if not playlist_id:
                raise ValueError("无法从链接中提取歌单ID")
            
            # 获取歌单详情（这里需要实现，暂时模拟）
            self.root_after(lambda: self.status_label.config(text="获取歌单详情..."))
            
            # 模拟歌单数据
            playlist_name = "示例歌单"
            song_count = 10
            
            # 清空搜索结果
            self.search_results = []
            
            # 模拟添加一些歌曲
            for i in range(song_count):
                song = SongInfo(
                    song_id=f"123456{i}",
                    name=f"歌曲 {i+1}",
                    artists=f"艺术家 {i+1}",
                    album=f"专辑 {i+1}",
                    duration=180000  # 3分钟
                )
                self.search_results.append(song)
            
            # 更新UI
            self.root_after(self.update_search_results_ui)
            self.root_after(lambda: self.search_result_label.config(text=f"歌单《{playlist_name}》共 {song_count} 首歌曲"))
            self.root_after(lambda: self.status_label.config(text=f"已加载歌单《{playlist_name}》"))
            self.root_after(lambda: self.progress_var.set(100))
            
        except Exception as e:
            self.root_after(lambda: self.status_label.config(text=f"解析歌单失败: {str(e)}"))
            self.root_after(lambda e=e: messagebox.showerror("错误", f"解析歌单失败: {str(e)}"))
        finally:
            self.root_after(lambda: self.progressbar.pack_forget())
    
    def extract_playlist_id(self, url):
        """提取歌单ID"""
        patterns = [
            r'music\.163\.com/(?:#/)?playlist\?id=(\d+)',
            r'y\.music\.163\.com/m/playlist/(\d+)',
            r'music\.163\.com/discover/toplist\?id=(\d+)',
            r'(\d+)'  # 直接输入ID
        ]
        
        for pattern in patterns:
            match = re.search(pattern, url, re.IGNORECASE)
            if match:
                return match.group(1)
        
        return None
    
    def parse_album(self):
        """解析专辑"""
        url = self.album_entry.get().strip()
        if url == "请输入专辑链接":
            messagebox.showwarning("输入错误", "请输入有效的专辑链接")
            return
        
        threading.Thread(target=self._parse_album_thread, args=(url,), daemon=True).start()
    
    def _parse_album_thread(self, url):
        """解析专辑线程"""
        self.root_after(lambda: self.status_label.config(text="正在解析专辑..."))
        self.root_after(lambda: self.progressbar.pack(fill="x", pady=5))
        self.root_after(lambda: self.progress_var.set(10))
        
        try:
            # 提取专辑ID
            album_id = self.extract_album_id(url)
            if not album_id:
                raise ValueError("无法从链接中提取专辑ID")
            
            # 获取专辑详情（这里需要实现，暂时模拟）
            self.root_after(lambda: self.status_label.config(text="获取专辑详情..."))
            
            # 模拟专辑数据
            album_name = "示例专辑"
            song_count = 8
            
            # 清空搜索结果
            self.search_results = []
            
            # 模拟添加一些歌曲
            for i in range(song_count):
                song = SongInfo(
                    song_id=f"234567{i}",
                    name=f"专辑歌曲 {i+1}",
                    artists=f"专辑艺术家 {i+1}",
                    album=album_name,
                    duration=200000  # 3分20秒
                )
                self.search_results.append(song)
            
            # 更新UI
            self.root_after(self.update_search_results_ui)
            self.root_after(lambda: self.search_result_label.config(text=f"专辑《{album_name}》共 {song_count} 首歌曲"))
            self.root_after(lambda: self.status_label.config(text=f"已加载专辑《{album_name}》"))
            self.root_after(lambda: self.progress_var.set(100))
            
        except Exception as e:
            self.root_after(lambda: self.status_label.config(text=f"解析专辑失败: {str(e)}"))
            self.root_after(lambda e=e: messagebox.showerror("错误", f"解析专辑失败: {str(e)}"))
        finally:
            self.root_after(lambda: self.progressbar.pack_forget())
    
    def extract_album_id(self, url):
        """提取专辑ID"""
        patterns = [
            r'music\.163\.com/(?:#/)?album\?id=(\d+)',
            r'music\.163\.com/(?:#/)?album/(\d+)',
            r'y\.music\.163\.com/m/album/(\d+)',
            r'(\d+)'  # 直接输入ID
        ]
        
        for pattern in patterns:
            match = re.search(pattern, url, re.IGNORECASE)
            if match:
                return match.group(1)
        
        return None

class AdbFileUploader:
    def __init__(self, root):
        self.root = root
        self.root.title("Lemon Link Assistant 6.0 - ADB文件上传器")
        self.root.geometry("700x800")
        self.root.resizable(False, False)
        # 设置图标
        icon_path = resource_path("icon.png")
        if os.path.exists(icon_path):
            self.icon_image = PhotoImage(file=icon_path)
            self.root.iconphoto(False, self.icon_image)
        
        # 设置现代化主题
        self.style = Style(theme="litera")
        self.style.configure("success.TButton", font=("Helvetica", 10))
        self.style.configure("warning.TButton", font=("Helvetica", 10))
        self.style.configure("danger.TButton", font=("Helvetica", 10))
        self.style.configure("primary.TButton", font=("Helvetica", 10))
        self.style.configure("info.TButton", font=("Helvetica", 10))
        
        # 变量初始化
        self.upload_files = []
        self.adb_path = self.find_adb_path()
        self.common_target_paths = [
            "/storage/emulated/0/Documents/",
            "/storage/emulated/0/Pictures/",
            "/storage/emulated/0/DCIM/Camera/",
            "/storage/emulated/0/Movies/",
            "/storage/emulated/0/Music/",
            "/storage/emulated/0/Download/",
            "/storage/emulated/0/Recordings/",
            "/storage/emulated/0/"
        ]
        
        self.create_menu()
        self.create_widgets()
        self.check_connected_devices()

    def find_adb_path(self):
        """查找ADB路径"""
        current_dir = os.path.dirname(os.path.abspath(__file__))
        adb_path = os.path.join(current_dir, "adb.exe")
        
        if os.path.exists(adb_path):
            return adb_path
        
        # 检查系统PATH
        path_env = os.environ.get("PATH", "")
        for path in path_env.split(os.pathsep):
            test_path = os.path.join(path, "adb.exe")
            if os.path.exists(test_path):
                return test_path
        
        return None
    
    def create_menu(self):
        """创建菜单栏"""
        self.menubar = Menu(self.root)
        
        # 文件菜单
        file_menu = Menu(self.menubar, tearoff=0)
        file_menu.add_command(label="从网易云音乐下载", command=self.open_netease_downloader)
        file_menu.add_command(label="从Bilibili下载", command=self.open_bilibili_downloader)
        file_menu.add_separator()
        file_menu.add_command(label="退出", command=self.root.quit)
        
        self.menubar.add_cascade(label="文件", menu=file_menu)
        self.root.config(menu=self.menubar)
    
    def create_widgets(self):
        """创建主界面控件"""
        main_frame = Frame(self.root, padding=20)
        main_frame.pack(fill=BOTH, expand=True)
        
        # 上传文件列表
        Label(main_frame, text="上传文件列表", font=("Helvetica", 12, "bold")).grid(row=0, column=0, sticky="w", pady=(0, 5))
        
        file_frame = Frame(main_frame)
        file_frame.grid(row=1, column=0, columnspan=2, sticky="ew", pady=(0, 10))
        
        # 使用标准tkinter Listbox
        self.file_listbox = Listbox(file_frame, height=6, width=60, selectmode=EXTENDED)
        self.file_listbox.pack(side=LEFT, fill=BOTH, expand=True)
        
        scrollbar = Scrollbar(file_frame, orient=VERTICAL, command=self.file_listbox.yview)
        scrollbar.pack(side=RIGHT, fill=Y)
        self.file_listbox.config(yscrollcommand=scrollbar.set)
        
        # 文件操作按钮
        btn_frame = Frame(main_frame)
        btn_frame.grid(row=2, column=0, columnspan=2, sticky="ew", pady=(0, 15))
        
        Button(btn_frame, text="添加文件", command=self.add_files, style="primary.TButton", width=10).pack(side=LEFT, padx=2)
        Button(btn_frame, text="添加目录", command=self.add_directory, style="success.TButton", width=10).pack(side=LEFT, padx=2)
        Button(btn_frame, text="删除", command=self.remove_selected_files, style="danger.TButton", width=10).pack(side=LEFT, padx=2)
        
        self.file_count_label = Label(btn_frame, text="已选择 0 项", font=("Helvetica", 9))
        self.file_count_label.pack(side=RIGHT)
        
        # 设备列表
        Label(main_frame, text="连接设备", font=("Helvetica", 12, "bold")).grid(row=3, column=0, sticky="w", pady=(10, 5))
        
        device_frame = Frame(main_frame)
        device_frame.grid(row=4, column=0, columnspan=2, sticky="ew", pady=(0, 15))
        
        # 使用标准tkinter Listbox
        self.device_listbox = Listbox(device_frame, height=4, width=60, selectmode=SINGLE)
        self.device_listbox.pack(side=LEFT, fill=BOTH, expand=True)
        
        device_scrollbar = Scrollbar(device_frame, orient=VERTICAL, command=self.device_listbox.yview)
        device_scrollbar.pack(side=RIGHT, fill=Y)
        self.device_listbox.config(yscrollcommand=device_scrollbar.set)
        
        Button(main_frame, text="刷新设备", command=self.check_connected_devices, style="info.TButton", width=10).grid(row=4, column=2, padx=10)
        
        # 目标路径
        Label(main_frame, text="目标路径", font=("Helvetica", 12, "bold")).grid(row=5, column=0, sticky="w", pady=(10, 5))
        
        self.target_path_var = StringVar(value="/storage/emulated/0/")
        self.target_path_combo = Combobox(main_frame, textvariable=self.target_path_var, width=50, values=self.common_target_paths)
        self.target_path_combo.grid(row=6, column=0, columnspan=2, sticky="ew", pady=(0, 15))
        
        # 进度条和状态
        self.progress_var = DoubleVar(value=0)
        self.progressbar = Progressbar(main_frame, variable=self.progress_var, maximum=100, style="success.Horizontal.Tprogressbar")
        self.progressbar.grid(row=7, column=0, columnspan=2, sticky="ew", pady=(10, 5))
        
        self.status_label = Label(main_frame, text="就绪", font=("Helvetica", 9), foreground="#666")
        self.status_label.grid(row=8, column=0, columnspan=2, sticky="w", pady=(5, 10))
        
        # 上传按钮
        self.upload_button = Button(main_frame, text="开始上传", command=self.start_upload, style="warning.TButton", width=15)
        self.upload_button.grid(row=9, column=0, columnspan=2, pady=10)
        
        # 提示说明
        Label(main_frame, text="提示说明", font=("Helvetica", 12, "bold")).grid(row=10, column=0, sticky="w", pady=(10, 5))

        default_tips = """传输文件前，请先按照下列步骤开启ADB调试：
1. 打开青鹿-头像-联系我们，长按电话号码，选择拨打电话。
   另一种方法：开机右上角点击头像-退出登录，会有一个密码框，点击眼睛图标显示密码，随便输入五位数然后长按文本，选择拨打电话。
2. 输入 *#*#83781#*#*，在上方菜单中的第一项 TELEPHONY 中下滑找到 USB 接口激活，打开在第二项 DEBUG&LOG 中找到 USB Debug，打开它。
3. 使用数据线连接电脑，打开本程序，平板应该会提示：是否使用本台计算机调试，勾选一律使用，点确定即可。
4. 重启软件，开始搞机吧 ~"""
        
        self.tips_text = Label(main_frame, width=70, text=default_tips, wraplength=450, justify=LEFT)
        self.tips_text.grid(row=11, column=0, columnspan=2, sticky="ew", pady=(0, 10))
    
    def add_files(self):
        """添加文件"""
        files = filedialog.askopenfilenames(
            title="选择文件",
            filetypes=[
                ("所有文件", "*.*"),
                ("文档文件", "*.doc *.docx *.pdf *.txt"),
                ("演示文件", "*.ppt *.pptx"),
                ("图片文件", "*.jpg *.png *.gif"),
                ("视频文件", "*.mp4 *.avi *.mov"),
                ("音频文件", "*.mp3 *.wav *.flac")
            ]
        )
        
        if files:
            for file in files:
                if file not in self.upload_files:
                    self.upload_files.append(file)
            self.update_file_list()
    
    def add_directory(self):
        """添加目录"""
        directory = filedialog.askdirectory(title="选择目录")
        if directory and directory not in self.upload_files:
            self.upload_files.append(directory)
            self.update_file_list()
    
    def remove_selected_files(self):
        """删除选中的文件"""
        selected_indices = self.file_listbox.curselection()
        if selected_indices:
            # 从后往前删除，避免索引问题
            for index in reversed(selected_indices):
                del self.upload_files[index]
            self.update_file_list()
    
    def update_file_list(self):
        """更新文件列表"""
        self.file_listbox.delete(0, END)
        for file in self.upload_files:
            self.file_listbox.insert(END, file)
        
        self.file_count_label.config(text=f"已选择 {len(self.upload_files)} 项")
        self.update_upload_button_state()
    
    def update_upload_button_state(self):
        """更新上传按钮状态"""
        has_devices = self.device_listbox.size() > 0
        has_files = len(self.upload_files) > 0
        self.upload_button.config(state=NORMAL if (has_devices and has_files) else DISABLED)
    
    def check_connected_devices(self):
        """检查连接的设备"""
        if not self.adb_path:
            self.status_label.config(text="未找到ADB，请将adb.exe放在程序目录下")
            self.upload_button.config(state=DISABLED)
            return
        
        try:
            result = subprocess.run([self.adb_path, "devices"], capture_output=True, text=True, timeout=17)
            output = result.stdout
            
            self.device_listbox.delete(0, END)
            devices = []
            
            lines = output.strip().split('\n')
            for line in lines[1:]:  # 跳过第一行 "List of devices attached"
                if "device" in line and not line.startswith("List"):
                    device_id = line.split('\t')[0].strip()
                    if device_id:
                        devices.append(device_id)
                        self.device_listbox.insert(END, device_id)
            
            if devices:
                self.device_listbox.selection_set(0)
                self.status_label.config(text=f"找到 {len(devices)} 个设备")
            else:
                self.status_label.config(text="未找到连接的设备，请确保设备已启用调试模式")
            
            self.update_upload_button_state()
            
        except Exception as e:
            self.status_label.config(text=f"检查设备时出错: {str(e)}")
            raise e
    
    def start_upload(self):
        """开始上传"""
        if not self.upload_files:
            messagebox.showerror("错误", "请至少添加一个文件或目录")
            return
        
        if not self.device_listbox.curselection():
            messagebox.showerror("错误", "请选择一个设备")
            return
        
        target_path = self.target_path_var.get().strip()
        if not target_path:
            target_path = "/storage/emulated/0/"
        
        if not target_path.endswith("/"):
            target_path += "/"
        
        # 禁用UI
        self.upload_button.config(state=DISABLED)
        self.progress_var.set(0)
        self.status_label.config(text="准备上传...")
        
        # 在新线程中执行上传
        upload_thread = threading.Thread(target=self.upload_files_thread, args=(target_path,))
        upload_thread.daemon = True
        upload_thread.start()
    
    def upload_files_thread(self, target_path):
        """上传文件线程"""
        try:
            total_files = len(self.upload_files)
            for i, source_path in enumerate(self.upload_files):
                current_file = i + 1
                filename = os.path.basename(source_path)
                
                # 更新UI
                self.root.after(0, lambda cf=current_file, tf=total_files, fn=filename: 
                    self.status_label.config(text=f"正在上传 ({cf}/{tf}): {fn}")
                )
                self.root.after(0, lambda cf=current_file, tf=total_files: 
                    self.progress_var.set((cf / tf) * 100)
                )
                
                # 检查是文件还是目录
                is_directory = os.path.isdir(source_path)
                
                try:
                    if is_directory:
                        # 上传目录
                        cmd = [self.adb_path, "push", source_path, target_path]
                    else:
                        # 上传文件
                        full_target_path = f"{target_path}{filename}"
                        cmd = [self.adb_path, "push", source_path, full_target_path]
                    
                    result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
                    
                    if result.returncode != 0:
                        error_msg = result.stderr.strip() or result.stdout.strip()
                        self.root.after(0, lambda msg=error_msg, fn=filename: 
                            messagebox.showerror("错误", f"文件 '{fn}' 上传失败: {msg}")
                        )
                
                except Exception as e:
                    self.root.after(0, lambda err=str(e), fn=filename: 
                        messagebox.showerror("错误", f"文件 '{fn}' 上传出错: {err}")
                    )
            
            # 上传完成
            self.root.after(0, lambda: self.progress_var.set(100))
            self.root.after(0, lambda: self.status_label.config(text=f"上传完成: 共 {total_files} 个文件/目录"))
            self.root.after(0, lambda: messagebox.showinfo("成功", f"已成功上传 {total_files} 个文件/目录到\n{target_path}"))
            self.root.after(0, lambda: self.upload_button.config(state=NORMAL))
            
        except Exception as e:
            self.root.after(0, lambda: self.status_label.config(text=f"上传出错: {str(e)}"))
            self.root.after(0, lambda: messagebox.showerror("错误", f"上传出错: {str(e)}"))
            self.root.after(0, lambda: self.upload_button.config(state=NORMAL))
    
    def open_netease_downloader(self):
        """打开网易云音乐下载器"""
        downloader = NeteaseMusicDownloader(self.root)
        downloader.on_files_downloaded = self.handle_downloaded_files
        downloader.show()

    def open_bilibili_downloader(self):
        """打开Bilibili下载器"""
        downloader = BilibiliVideoDownloader(self.root)
        downloader.on_files_downloaded = self.handle_downloaded_files
        downloader.show()
    
    def handle_downloaded_files(self, files):
        """处理下载的文件"""
        for file in files:
            if file not in self.upload_files:
                self.upload_files.append(file)
        self.update_file_list()

if __name__ == "__main__":
    root = Window(themename="litera")
    app = AdbFileUploader(root)
    root.mainloop()
