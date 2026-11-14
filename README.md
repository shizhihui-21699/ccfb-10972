# EVTX Kerberos 异常检测

纯 Python 直接解析 EVTX 二进制格式（不依赖 Windows / 第三方库），
针对域控安全日志中的 Kerberos 事件（4768 / 4769 / 4771）做基线建模和异常检测。

## 文件

| 文件 | 说明 |
|---|---|
| `evtx.py` | EVTX 解析器：文件头 → 64KB chunk（双 CRC 校验）→ 事件记录 → BinXML（模板实例、模板定义、替换值、字符串表）。**损坏的 chunk 校验失败会跳过并继续**，单条记录解析失败也只跳过该记录，全部警告收集在 `EvtxFile.warnings` |
| `make_sample_evtx.py` | 按真实格式造样例 EVTX（含一周正常基线 + 4 类埋入异常 + 1 个故意损坏的 chunk）。生成文件已通过参考实现（Rust `evtx` crate, PyPI `evtx` 0.15）逐字段比对验证：515/515 记录、0 字段差异 |
| `kerb_hunt.py` | 检测器：建账户/服务基线，输出 `timeline.csv`、`baseline.json`、`alerts.json`、`alerts.md`（告警说明 + 攻击时间线） |

## 用法

```bash
# 造样例（--corrupt-chunk -1 可关掉故意损坏）
python3 make_sample_evtx.py --out samples/security_sample.evtx

# 分析
python3 kerb_hunt.py samples/security_sample.evtx -o hunt_out

# 也可以只 dump XML 验证解析器
python3 evtx.py samples/security_sample.evtx | less
```

阈值可调（都有默认值）：

```
--rc4-burst 20        每账户每窗口 RC4 票据请求数阈值
--rc4-window 600      RC4 突发窗口（秒）
--max-tgt-hours 12    TGT 连续使用时长上限（小时）
--max-gap-hours 3     判定"同一 TGT 会话"允许的最大请求间隔（小时）
--spray-accounts 10   每源 IP 每窗口失败的不同账户数
--spray-window 300    喷洒窗口（秒）
--established-hours 24  账户存在多久才算"老账户"（新主机检测）
--new-ip-hours 24     IP 首次出现后多久内算"新地址"
--min-history 5       账户至少有多少历史事件才启用新主机检测
```

## 检测项与阈值依据

1. **RC4 突发（Kerberoasting）**：4769 中 `TicketEncryptionType=0x17`(RC4-HMAC)，
   按账户聚类（相邻请求间隔 ≤10 分钟），一簇 ≥20 张报警。
   依据：正常用户一天就几张 TGS，而 Rubeus/Impacket 会对所有 SPN 账户
   一次性请求 RC4 票据（几十张/几分钟）。另附"该账户此前全 AES"的降级备注。
2. **TGT 有效期异常**：对每个 4768（TGT 签发），链式跟踪该账户后续 4769
   （间隔 ≤3h 算同一会话），连续使用 >12h 报警。
   依据：域默认 `MaxTicketAge=10h`；链式规则同时避免日志缺块
   （如被跳过的损坏 chunk）把正常数据拉成误报。
3. **新主机突访高权限服务**：老账户（建档 >24h）从新 IP（首次出现 <24h）
   请求敏感服务——DC 上的 cifs/ldap/host/rpc 等，或任何主机的
   wsman/termsrv/rpc 等远程管理类。IP 全日志从未出现过 → high，
   否则 medium。用"首次出现时间"判定而不是运行集合，避免新主机的 4768
   把 IP 先洗白。
4. **口令喷洒**：4771（状态 0x18/0x17/0x06）按源 IP 聚类，
   5 分钟内 ≥10 个不同账户失败报警。

## 格式要点（解析器/生成器都按此实现）

- 文件头 4096 字节（`ElfFile\0`），随后 64KB chunk（`ElfChnk\0`）。
- chunk 头 512 字节：两个 CRC（头部 CRC @120、事件数据 CRC @52）、
  64 项字符串偏移表（@128）、32 项模板偏移表（@384）。
- 事件记录：`2A2A0000` + size + record id + FILETIME + BinXML + size。
- BinXML：片段头 `0F 01 01 00`；模板实例 `0C 01 <id> <offset>`，
  模板定义可内联（offset 指向自身之后）或引用 chunk 内先前的定义；
  替换值区 = 数量 + 描述符（size u16, type u8, 保留 u8）+ 原始值。
- 名称走 chunk 字符串表（`next u32 + hash u16 + count u16 + UTF-16 + NUL`），
  也兼容内联名称。hash 算法：`h = h*0x1003F + c`（UTF-16 码元）。
- 替换值类型：string/ansi/int/uint/real/bool/binary/GUID/SizeT/
  FILETIME/SYSTIME/SID/HexInt32/HexInt64/数组（0x80 标记）。

参考：libevtx 格式文档、MS-EVEN6、omerbenamram/evtx (Rust) 源码。

## 样例里埋的异常（2026-11-09）

- 09:31 alice@10.0.0.66：4 分钟内 60 张 RC4 TGS（60 个 SPN）→ Kerberoasting
- 11-08 01:00 起 svc_backup 的 TGT 连续使用 26 小时 → 长效票据
- 22:15 dave@10.0.9.99（陌生地址）请求 CIFS/LDAP/DC01 → 新主机高权限访问
- 03:12 10.0.9.100 对 30 个账户 4771 预认证失败 → 口令喷洒
- chunk 1 数据区被故意翻转 64 字节（CRC 校验失败）→ 验证跳过逻辑
