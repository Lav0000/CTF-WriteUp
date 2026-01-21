Ban đầu ta có file tunn3lv1s10n

Kiểm tra Hex file ta thấy Signature file là 42 4D -> file .bmp

![Image](https://github.com/user-attachments/assets/75c7a3a4-569c-4c2d-82a8-c69b1ac1256e)

Rename file thành tunn3lv1s10n.bmp và thử mở -> fail

Tiến hành kiểm tra mã hex các cấu trúc còn lại trong file BMP biết rằng với một file BMP cơ bản có những điểm cần lưu ý như sau:

![Image](https://github.com/user-attachments/assets/894e6a09-ab52-47f2-918c-62e26ae4771c)

Và đây là cấu trúc của tunn3lv1s10n.bmp:

![Image](https://github.com/user-attachments/assets/b578d604-ad34-4f72-a0f5-6702417e86b0)

Thay đổi DataOffset thành `36 00 00 00` và DIB Header Size thành `28 00 00 00` để giống một file BMP cơ bản.
Sau đó mở lại file bằng phần mềm xem ảnh.

![Image](https://github.com/user-attachments/assets/0a487de1-4341-4c75-b224-c5787fc55c5b)

Đây không phải flag cần tìm. Nhận thấy kích thước Height của ảnh khá nhỏ, giống như bị cắt mất một phần.
Thử tìm đến hex Height, tăng lên.

![Image](https://github.com/user-attachments/assets/550aaf89-1390-4a14-b5f8-9db63849232e)

Mở lại ảnh, ta thành công lấy được flag.

*NGUỒN*
https://www.ece.ualberta.ca/~elliott/ee552/studentAppNotes/2003_w/misc/bmp_file_format/bmp_file_format.htm
https://www.youtube.com/watch?v=d63buMlAUHM

![Image](https://github.com/user-attachments/assets/85589996-1ac2-469b-82ca-f504a81518f1)
