---
title: "Hidden Investigations CTF - Write-ups"
description: "Write-up các challenge mình giải tại Hidden Investigations CTF."
date: 2026-11-02 00:00:00 +0700
lang: vi-VN
categories: [CTF, Hidden Investigations]
tags: [dfir, windows, ransomware, sysmon]
author: koga
toc: true
comments: false
---

## The Miner That Mined the Victim

Một người dùng tải **CoinBoost Pro v3.2**, tưởng là công cụ tối ưu đào coin miễn phí. Sau khi chạy, các file văn bản không còn đọc được và Desktop xuất hiện thư đòi tiền chuộc. Người dùng xóa thư mục chứa tool, hy vọng mọi chuyện sẽ kết thúc ở đó.

Nhưng xóa thư mục không đồng nghĩa với xóa hết dấu vết. Đề cung cấp một **bộ triage ổ C của máy nạn nhân** và yêu cầu dựng lại chuỗi sự kiện qua 14 câu hỏi: tải từ đâu, chạy lúc nào, làm gì với hệ thống và còn khôi phục được những gì.

Mình dùng **KAPE** để thu thập nhanh các artifact cần thiết cho quá trình triage, sau đó đối chiếu dữ liệu giữa các nguồn để dựng lại timeline. Các artifact chính gồm:

| Artifact                       | Thông tin cần tìm                                         |
| :----------------------------- | :-------------------------------------------------------- |
| `ransomware_debug.log`         | Phiên bản OS, thời gian và thông báo từ chương trình      |
| Hive `SYSTEM`                  | Cấu hình múi giờ để đối chiếu timestamp                   |
| Edge `History`                 | URL tải xuống, redirect và thời điểm hoàn tất             |
| Prefetch                       | Dấu vết thực thi của `miner.exe`                          |
| Sysmon                         | Assembly được load, thay đổi registry và hành vi xóa file |
| `$MFT` và metadata Recycle Bin | Nội dung còn lưu, đường dẫn và thông tin xóa              |

### Q1 - Phiên bản OS khi malware chạy

Trong thư mục Temp của người dùng có file log:

```plaintext
C:\Users\milon1\AppData\Local\Temp\ransomware_debug.log
```

Dòng cần tìm là:

```plaintext
OS Version: Microsoft Windows NT 10.0.26200.0
```

Câu hỏi yêu cầu đúng chuỗi phiên bản được ghi nhận khi chương trình chạy, nên mình giữ nguyên giá trị trong log.

**Đáp án:**

```plaintext
Microsoft Windows NT 10.0.26200.0
```

### Q2 - Múi giờ thực tế và ActiveTimeBias

Trước khi ghép timeline, cần thống nhất cách đọc thời gian. Trong hive `SYSTEM`, key sau lưu cấu hình múi giờ:

```plaintext
ControlSet001\Control\TimeZoneInformation
```

Các giá trị đáng chú ý:

```plaintext
TimeZoneKeyName = Pacific Standard Time
Bias = 480
DaylightBias = -60
ActiveTimeBias = 420
```

`ActiveTimeBias = 420` tương ứng giờ địa phương chậm hơn UTC **420 phút**, tức **7 tiếng**. Đối chiếu thêm với log: thời điểm khoảng `07:26` trong malware log khớp với khoảng `14:26` UTC trong Sysmon.

Tên `Pacific Standard Time` không có nghĩa là cứ lấy UTC-8 cho mọi timestamp. Ở đây, giá trị bias đang có hiệu lực và sự khớp giữa các log cùng hỗ trợ **UTC-7**. Từ bước này, mình quy các mốc trong timeline về UTC.

**Đáp án:**

```plaintext
UTC-7, 420
```

### Q3 - URL tải malware, bao gồm fragment

Mở database lịch sử Edge:

```plaintext
C:\Users\milon1\AppData\Local\Microsoft\Edge\User Data\Default\History
```

Trong bảng `urls`, có trang Telegraph quảng cáo công cụ và một đường dẫn LimeWire:

```plaintext
https://telegra.ph/CoinBoost-Pro-v32--Free-Mining-Optimizer-05-12
https://limewire.com/d/Ak55K#Yrx3FgK3du
```

Đề nhấn mạnh **including the fragment**, nên phần sau dấu `#` cũng thuộc đáp án. Nếu chỉ lấy `https://limewire.com/d/Ak55K` thì sẽ thiếu dữ liệu yêu cầu.

**Đáp án:**

```plaintext
https://limewire.com/d/Ak55K#Yrx3FgK3du
```

### Q4 - downloadId trong URL chuyển hướng

URL người dùng truy cập chưa phải toàn bộ câu chuyện tải xuống. Trong **Sysmon Event ID 15**, dữ liệu `Zone.Identifier` của `miner.zip` chứa:

```plaintext
ReferrerUrl=https://limewire.com/d/Ak55K
HostUrl=https://limewire.com/decrypt/download?downloadId=42d377fe-8948-4a32-809f-69a51e6dbcfa
```

Giá trị cần nộp nằm trong tham số `downloadId` của `HostUrl`. Điểm quan trọng là phân biệt **URL ban đầu** với **URL chuyển hướng dùng để phân phối ZIP**; hai câu hỏi đang lấy hai phần khác nhau của cùng chuỗi tải.

**Đáp án:**

```plaintext
42d377fe-8948-4a32-809f-69a51e6dbcfa
```

### Q5 - Thời điểm tải xong

Quay lại Edge `History`, lần này kiểm tra bảng `downloads`. Bản ghi `miner.zip` có:

```plaintext
received_bytes = 77944
total_bytes = 77944
end_time = 13423155936833030
```

Hai trường byte khớp nhau, còn `end_time` cho biết mốc hoàn tất. Timestamp Chromium dùng đơn vị microsecond kể từ `1601-01-01`. Chuyển đổi bằng Python:

```python
from datetime import datetime, timedelta, timezone

chromium_time = 13423155936833030
epoch = datetime(1601, 1, 1, tzinfo=timezone.utc)
finished = epoch + timedelta(microseconds=chromium_time)

print(finished.isoformat())
print(finished.strftime("%Y-%m-%d %H:%M:%S UTC"))
```

Kết quả đầy đủ là `2026-05-13 14:25:36.833030 UTC`. Định dạng câu hỏi chỉ cần đến giây.

**Đáp án:**

```plaintext
2026-05-13 14:25:36 UTC
```

![Nội dung challenge và các câu trả lời về OS, múi giờ, URL tải, downloadId và thời điểm tải xong](/assets/img/posts/hidden-investigations/miner-victim/questions-01-05.png){: width="710" height="842" }
_Bối cảnh challenge và nhóm câu hỏi đầu tiên._

### Q6 - Chương trình có chạy không, chạy lúc nào và bao nhiêu lần?

Thư mục chứa tool đã bị xóa, nhưng Windows vẫn còn Prefetch:

```plaintext
C:\Windows\Prefetch\MINER.EXE-9A2B223D.pf
```

Phân tích file này cho thấy:

```plaintext
Run count: 1
Execution time: 2026-05-13 14:26:55.567595 UTC
```

UserAssist có một mốc gần đó là `14:26:52`, nhưng câu hỏi cần thời điểm thực thi được xác định từ Prefetch. Ở đây, artifact hỗ trợ kết luận **`miner.exe` đã chạy một lần**, với timestamp đến giây là `14:26:55 UTC`.

**Đáp án:**

```plaintext
2026-05-13 14:26:55 UTC, 1
```

### Q7 - Assembly mã hóa được load

Lọc **Sysmon Event ID 7** theo `miner.exe` và từ khóa `Cryptography`, mình tìm được:

```plaintext
ImageLoaded:
C:\Program Files\dotnet\shared\Microsoft.NETCore.App\9.0.16\System.Security.Cryptography.dll

UtcTime:
2026-05-13 14:26:58.931
```

Assembly này được load ngay trước khi các file `.vibed` xuất hiện. Nó giúp nối mốc chạy của executable với giai đoạn mã hóa dữ liệu; riêng tên DLL chưa đủ để xác định thuật toán mã hóa cụ thể.

**Đáp án:**

```plaintext
C:\Program Files\dotnet\shared\Microsoft.NETCore.App\9.0.16\System.Security.Cryptography.dll, 2026-05-13 14:26:58 UTC
```

### Q8 - Registry value nào bị sửa thành công?

Malware log ghi hai kết quả khác nhau:

```plaintext
ERROR in DisableRealtimeProtection:
Requested registry access is not allowed.

SUCCESS: Set DisableAntiSpyware=1
```

Vì câu hỏi yêu cầu thay đổi **thành công**, không thể lấy `DisableRealtimeProtection` chỉ vì nó xuất hiện trong log.

Đối chiếu **Sysmon Event ID 13**, mình thấy:

```plaintext
TargetObject:
HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\DisableAntiSpyware

Details:
DWORD (0x00000001)
```

Đây là registry value cần tìm. Tuy nhiên, **ghi registry thành công không đồng nghĩa Defender đã bị vô hiệu hóa**: Defender còn ghi nhận thay đổi này là `Ignored / Not Applicable`.

**Đáp án:**

```plaintext
HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\DisableAntiSpyware
```

### Q9 - MITRE ATT&CK technique hiện tại

Hành vi sửa cấu hình bảo vệ nhằm làm suy yếu công cụ phòng thủ tương ứng với **Disable or Modify Tools**. Đề hỏi ID hiện tại, nên đối chiếu [MITRE ATT&CK - T1685](https://attack.mitre.org/techniques/T1685/).

Việc ánh xạ ở đây mô tả hành vi quan sát được; nó không thay thế bằng chứng về hiệu quả của thay đổi đối với Defender.

**Đáp án:**

```plaintext
T1685
```

### Q10 - Khôi phục đoạn text quan trọng

Trong Documents có hai tên file đáng chú ý:

```plaintext
vzcbegnag.txt.vibed
vg'f fbzrjurer.txt.vibed
```

Sau khi bỏ hậu tố `.vibed` và áp dụng ROT13 cho **phần tên trước `.txt`**, mình được:

```plaintext
important.txt
it's somewhere.txt
```

Có thể kiểm tra bước đổi tên bằng Python:

```python
import codecs

filenames = ["vzcbegnag.txt.vibed", "vg'f fbzrjurer.txt.vibed"]

for filename in filenames:
    original = filename.removesuffix(".vibed")
    stem, extension = original.rsplit(".", 1)
    print(f"{codecs.decode(stem, 'rot_13')}.{extension}")
```

Mình giữ nguyên `.txt`, vì ROT13 cả phần mở rộng sẽ biến nó thành `.gkg`. Việc đổi tên này chỉ giúp nhận diện file, chưa khôi phục nội dung đã mã hóa.

Tìm tiếp trong **`$MFT`**, một bản ghi có dữ liệu resident còn giữ nguyên đoạn text quan trọng:

```plaintext
hiCTF{finally_u_proved_ur_worthiness}
```

Đây là **đáp án câu 10**, chưa phải flag cuối của challenge.

### Q11 - Thư mục bị xóa và thời điểm xóa

Trong `$MFT`, mình khôi phục được metadata Recycle Bin của file:

```plaintext
$IGDL3PH
```

Metadata `$I` lưu thông tin về mục đã xóa. Dữ liệu đọc được gồm:

```plaintext
Original path:
C:\Users\milon1\Downloads\miner

Deletion time:
2026-05-13 14:27:47.957 UTC
```

Như vậy, có thể xác định cả **đường dẫn gốc** lẫn **thời điểm xóa thư mục**, dù thư mục chứa chương trình không còn ở Downloads.

**Đáp án:**

```plaintext
C:\Users\milon1\Downloads\miner, 2026-05-13 14:27:47 UTC
```

### Q12 - Kích thước thư mục đã xóa

Cũng trong metadata `$I`, trường kích thước có giá trị:

```plaintext
0x2BDA7
```

Đổi sang hệ thập phân:

```python
print(int("2BDA7", 16))  # 179623
```

**Đáp án, tính bằng byte:**

```plaintext
179623
```

### Q13 - Plaintext của bar.txt

File còn lại mang tên:

```plaintext
bar.txt.vibed
```

Nội dung file này đã bị mã hóa. Tuy nhiên, kiểm tra các bản ghi `$MFT` giúp tìm được **một bản sao văn bản trong file cache có tên dạng hash**:

```plaintext
I will always be there for you bro!
```

Mình nộp đúng chuỗi này và nhận kết quả chính xác. Đây là khôi phục nội dung từ bản sao còn lưu, không phải giải mã trực tiếp file `.vibed`.

**Đáp án:**

```plaintext
I will always be there for you bro!
```

![Các câu trả lời được xác nhận đúng từ dấu vết thực thi đến khôi phục nội dung bar.txt](/assets/img/posts/hidden-investigations/miner-victim/questions-06-13.png){: width="1485" height="841" }
_Kết quả đối chiếu cho các câu 6–13; bấm ảnh để xem rõ từng giá trị._

### Q14 - Chuỗi ASCII của shred pattern

Trong **Sysmon Event ID 23**, sự kiện xóa `noting.txt` có:

```plaintext
TargetFilename:
C:\Users\milon1\Documents\noting.txt

Archived:
false - shredded file with pattern 0x706c6568
```

Đề hỏi bốn ký tự ASCII theo thứ tự byte **được lưu trên đĩa**. Với giá trị 32-bit này, đọc theo little-endian:

```plaintext
0x706c6568
    → 68 65 6c 70
    → h  e  l  p
```

Kiểm tra bằng Python:

```python
pattern = 0x706C6568
print(pattern.to_bytes(4, byteorder="little").decode("ascii"))
```

Nếu chỉ đọc các cặp hex từ trái sang phải sẽ ra `pleh`, ngược với thứ tự cần tìm.

**Đáp án:**

```plaintext
help
```

### Ghép lại timeline

| Thời điểm UTC - 2026-05-13 | Dấu vết                                                                                  |
| :------------------------- | :--------------------------------------------------------------------------------------- |
| `14:25:36.833030`          | Edge ghi nhận tải xong `miner.zip`                                                       |
| `14:26:52`                 | Mốc UserAssist gần thời điểm khởi chạy                                                   |
| `14:26:55.567595`          | Prefetch ghi nhận thực thi `miner.exe`, run count `1`                                    |
| `14:26:58.931`             | Sysmon ghi nhận load `System.Security.Cryptography.dll`, trước khi tạo các file `.vibed` |
| `14:27:47.957`             | Metadata Recycle Bin ghi nhận xóa thư mục `Downloads\miner`                              |

Chuỗi sự kiện khớp với bối cảnh: tải công cụ quảng cáo đào coin, thực thi, xuất hiện hành vi mã hóa và cuối cùng xóa thư mục chứa tool. Bên cạnh đó, log và Sysmon cho thấy chương trình đã thử can thiệp cấu hình bảo vệ.

### Flag cuối cùng

Sau khi trả lời đủ **14/14 câu hỏi**, instance trả về:

```plaintext
hiCTF{c4r3ful_4b0ut_cr4ck3d_t001s_b4c108e678}
```

![Câu 14 được xác nhận đúng và instance trả về flag sau khi hoàn tất 14 câu hỏi](/assets/img/posts/hidden-investigations/miner-victim/completed.png){: width="842" height="235" }
_Challenge hoàn tất với toàn bộ câu trả lời chính xác._

Điểm mình thích ở bài này là phải ghép **nhiều artifact cho cùng một sự kiện**. Edge trả lời phần tải xuống, Prefetch hỗ trợ xác nhận thực thi, Sysmon mô tả hành vi và `$MFT` giữ lại những gì tưởng đã mất. Xóa tool thì nhanh; xóa sạch câu chuyện nó để lại lại là chuyện khác.

## Ghost in the Wire

Một nhóm giám sát mạng đã phát hiện được lưu lượng ICMP bất thường. Có dữ liệu được truyền ra ngoài. Nhưng mà nó lại bị hòa lẫn nào nhiễu mạng thông thường bây giờ hãy thu thập và phân tích "Ghost"

### Cách giải

Ở đây tui sẽ thực hiện ở **Wireshark**. Và như hình dưới có rất nhiều gói tin ICMP được gửi từ IP **10.13.37.1** đến **10.13.37.2**

![các gói tin trong 1 file pcap](/assets/img/posts/hidden-investigations/ghost-in-the-wire/Ghost_in_the_wire_1.png){: width="1625" height="927" }
_Danh sách các gói tin._

Tiếp theo đó ta thử xem payload gói tin thử. Khi này ta nhận ra đó là 1 chữ trong kí tự flag và mình tiếp tục xem và ghi lại thì sẽ ra được full flag.

![Điều tra đoạn payload trong gói tin ICMP](/assets/img/posts/hidden-investigations/ghost-in-the-wire/Ghost_in_the_wire_2.png){: width="1627" height="928" }
_Tìm thấy được kí tự h trong cấu trúc flag của hiCTF{}._

### Flag cuối cùng

Sau khi ghép đầy đủ kí tự

```plaintext
hiCTF{1cmp_3xf1l_d3t3ct3d}
```
