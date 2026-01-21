file: Nininja.flag.png

Sau khi dò bằng các tool cơ bản: file, exiftool, binwalk, strings; ta vẫn không tìm thấy điểm khả nghi.
Tiến hành dò bằng tool `stegsolve` 

![Image](https://github.com/user-attachments/assets/dd24d865-800a-4a00-baa2-c222fd6513e7)

Chọn Data Extract

![Image](https://github.com/user-attachments/assets/e82d6670-30f5-43c2-b110-334358c64285)

Thường thì flag sẽ được giấu trong LSB (Least Significant Bit) tức bit plane 0 để hạn chế gây nhiễu/ảnh hưởng đến hình ảnh hiển thị. Nhưng ở bài MSB (Most Significant Bit) này, ta sẽ check bit plane 7.

![Image](https://github.com/user-attachments/assets/9de60a20-4f4e-4807-ad94-62bb1f40bd72)

Dường như có một văn bản text được đặt ở đây một cách cố ý, ta sẽ Save text lại và dò flag trong đó thử.

![Image](https://github.com/user-attachments/assets/613e4acd-6938-4921-84a3-f27d2dfa87bf)

Tuyệt vời, ta đã tìm được một phần của flag, phần còn lại hãy thử cat ra 5 dòng trên dưới vị trí này xem sao.

![Image](https://github.com/user-attachments/assets/43f8b0b7-9a37-4aa4-bd6d-c8a00574f86d)

You win!

*CHÚ GIẢI:*
- Stegsolve là một công cụ được thiết kế để phân tích và trích xuất dữ liệu ẩn trong hình ảnh bằng kỹ thuật steganography (thuật giấu tin). Công cụ này giúp người dùng kiểm tra từng bit thông tin trong pixel của ảnh, xem các kênh màu riêng lẻ, phát hiện LSB, và nhiều kỹ thuật ẩn dữ liệu khác.
- Mỗi file .png .jpg là tổ hợp của muôn vàn pixel màu, ở trường hợp ảnh màu, mỗi pixel màu chứa 3 bytes màu ở kiểu dữ liệu binary (Red, Green, Blue), mỗi bytes chứa 8 bit (từ 0 -> 7 với bit 0 là LBS, bit 7 là MSB).
- Bit plane là tập hợp tất cả các bit có cùng vị trí của tất cả các bytes trong file. Ví dụ ta có 1 pixel với` RGB(00001000,10000000,00000001) `vậy thì Bit plane 7 của nó sẽ là `RGB(0,1,0)`
