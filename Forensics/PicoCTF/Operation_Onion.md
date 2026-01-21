# Operation_Onion
<img width="500" height="400" alt="image" src="https://github.com/user-attachments/assets/9a6575e6-46e5-45eb-9d9d-2544cf22441f" />

*file: disk.img*

**TỔNG QUAN:** Đây là dạng bài disk forensics, đã cung cấp file disk imgae và yêu cầu người chơi tìm key_file tức là private key để ssh vào máy chủ pico đang chứa public key tương ứng

**TIẾN HÀNH:**
1. Mở file img bằng Autopsy, rà soát các phân vùng và file/folder, ta nhận thấy tại vol3 có chứa folder root - đây là folder đầu tiên mà người chơi nên chú ý kiếm tra kỹ vì các challenge ở mức thấp hay giấu manh mối ở chỗ này.

   <img width="200" height="300" alt="image" src="https://github.com/user-attachments/assets/a4f80498-fbd7-4cf5-a596-cd5da1ec92e3" />

2. Ở đây, ta dò được những file sau:

File history ghi lại lịch sử dòng lệnh rằng máy đã được generate ra cặp khóa id_ed25519 -> liệt kê folder .ssh/ -> tắt máy.
<img width="600" height="200" alt="image" src="https://github.com/user-attachments/assets/4495427f-ead2-4ce6-be93-ccc4cf96042a" />

Đi sâu vào ./ssh ta tìm được 2 file chứa private/public key rõ ràng như sau
<img width="600" height="200" alt="image" src="https://github.com/user-attachments/assets/04a39a96-0dd7-4877-8f57-6935d8919df2" />
<img width="600" height="200" alt="image" src="https://github.com/user-attachments/assets/7c7bc97e-1c64-43eb-8b4b-9331535e4880" />

3. Việc còn lại là tạo hoặc trích xuất file private key có tên và nội dung tương tự để ssh vào máy chủ pico thôi.
 Ở đây mình sẽ dùng Webshell của pico để chạy, bạn có thể dùng terrminal, wsl, vm, hay bất cứ thứ gì khác.
 
 ```bash
ValKhanh-picoctf@webshell:/tmp/onion$ nano id_ed25519 
ValKhanh-picoctf@webshell:/tmp/onion$ chmod 600 id_ed25519
ValKhanh-picoctf@webshell:/tmp/onion$ ssh -i id_ed25519 -p 50348 ctf-player@saturn.picoctf.net
```

Câu lệnh <ssh -i id_ed25519 -p 50348 ctf-player@saturn.picoctf.net> có nghĩa là ssh vào user ctf-player có địa chỉ saturn.picoctf.net bằng private key file là id_ed25519 qua cổng 50348

Tuyệt vời, challenge tới đây không còn gì để vọc nữa rồi, tìm chall khác chiến tiếp đi người anh em <3

```bash
ValKhanh-picoctf@webshell:/tmp/onion$ ssh -i id_ed25519 -p 50348 ctf-player@saturn.picoctf.net
Welcome to Ubuntu 20.04.5 LTS (GNU/Linux 6.5.0-1023-aws x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

This system has been minimized by removing packages and content that are
not required on a system that users do not log into.

To restore this content, you can run the 'unminimize' command.

The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.

ctf-player@challenge:~$ ls -la
total 4
drwxr-xr-x 1 ctf-player ctf-player 20 Jul 30 08:27 .
drwxr-xr-x 1 root       root       24 Aug  4  2023 ..
drwx------ 2 ctf-player ctf-player 34 Jul 30 08:27 .cache
drwxr-xr-x 2 ctf-player ctf-player 29 Aug  4  2023 .ssh
-rw-r--r-- 1 root       root       28 Aug  4  2023 flag.txt
```
