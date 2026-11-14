# Kerberos 安全检测报告

- 日志文件：`samples/security_sample.evtx`
- 解析到 Kerberos 事件（4768/4769/4771）：348 条
- 时间范围：2026-11-02T01:04:44Z ~ 2026-11-09T22:16:01Z
- 阈值：RC4 突发 ≥20 次/600 秒；TGT 使用 >12.0 小时；喷洒 ≥10 账户/300 秒

## 解析警告（已跳过，未中断）

- chunk 1 (file offset 0x11000): event data CRC mismatch (stored 0xE9D5454C, computed 0xCFD7022C) — chunk skipped

## 告警（4 条）

### 1. [HIGH] 疑似口令喷洒：10.0.9.100 对 30 个账户预认证失败

2026-11-09T03:12:00Z ~ 2026-11-09T03:13:27Z 内，来源 10.0.9.100 对 30 个不同账户产生 30 条 Kerberos 预认证失败（4771，状态 KDC_ERR_PREAUTH_FAILED (wrong password)）。典型口令喷洒特征。

**处置建议**：封禁/限速来源地址；检查喷射窗口之后是否有任一目标账户登录成功（4768 成功或 4624）；强制受影响账户改密。

证据（前 12 条，共 30 条）：

```
2026-11-09T03:12:00Z  4771  user00        krbtgt                                    10.0.9.100       enc=-    st=0x18
2026-11-09T03:12:03Z  4771  user01        krbtgt                                    10.0.9.100       enc=-    st=0x18
2026-11-09T03:12:06Z  4771  user02        krbtgt                                    10.0.9.100       enc=-    st=0x18
2026-11-09T03:12:09Z  4771  user03        krbtgt                                    10.0.9.100       enc=-    st=0x18
2026-11-09T03:12:12Z  4771  user04        krbtgt                                    10.0.9.100       enc=-    st=0x18
2026-11-09T03:12:15Z  4771  user05        krbtgt                                    10.0.9.100       enc=-    st=0x18
2026-11-09T03:12:18Z  4771  user06        krbtgt                                    10.0.9.100       enc=-    st=0x18
2026-11-09T03:12:21Z  4771  user07        krbtgt                                    10.0.9.100       enc=-    st=0x18
2026-11-09T03:12:24Z  4771  user08        krbtgt                                    10.0.9.100       enc=-    st=0x18
2026-11-09T03:12:27Z  4771  user09        krbtgt                                    10.0.9.100       enc=-    st=0x18
2026-11-09T03:12:30Z  4771  user10        krbtgt                                    10.0.9.100       enc=-    st=0x18
2026-11-09T03:12:33Z  4771  user11        krbtgt                                    10.0.9.100       enc=-    st=0x18
... 其余 18 条略
```

### 2. [HIGH] 疑似 Kerberoasting：账户 alice 短时大量 RC4 票据请求

2026-11-09T09:31:00Z ~ 2026-11-09T09:34:56Z（236 秒）内账户 alice 从 10.0.0.66 请求了 60 张 RC4-HMAC (0x17) 加密的服务票据，涉及 60 个不同 SPN。该账户此前从未使用 RC4（全部 AES），疑似加密降级。

**处置建议**：排查来源主机是否运行 Rubeus/Impacket 等工具；重置该账户口令；检查被请求 SPN 对应服务账户的口令强度（RC4 票据可离线爆破）。

证据（前 12 条，共 60 条）：

```
2026-11-09T09:31:00Z  4769  alice         MSSQLSvc/sql01.corp.local:1433            10.0.0.66        enc=0x17 st=0x0
2026-11-09T09:31:04Z  4769  alice         MSSQLSvc/sql02.corp.local:1433            10.0.0.66        enc=0x17 st=0x0
2026-11-09T09:31:08Z  4769  alice         MSSQLSvc/sql03.corp.local:1433            10.0.0.66        enc=0x17 st=0x0
2026-11-09T09:31:12Z  4769  alice         MSSQLSvc/sql04.corp.local:1433            10.0.0.66        enc=0x17 st=0x0
2026-11-09T09:31:16Z  4769  alice         MSSQLSvc/sql05.corp.local:1433            10.0.0.66        enc=0x17 st=0x0
2026-11-09T09:31:20Z  4769  alice         MSSQLSvc/sql06.corp.local:1433            10.0.0.66        enc=0x17 st=0x0
2026-11-09T09:31:24Z  4769  alice         MSSQLSvc/sql07.corp.local:1433            10.0.0.66        enc=0x17 st=0x0
2026-11-09T09:31:28Z  4769  alice         MSSQLSvc/sql08.corp.local:1433            10.0.0.66        enc=0x17 st=0x0
2026-11-09T09:31:32Z  4769  alice         MSSQLSvc/sql09.corp.local:1433            10.0.0.66        enc=0x17 st=0x0
2026-11-09T09:31:36Z  4769  alice         MSSQLSvc/sql10.corp.local:1433            10.0.0.66        enc=0x17 st=0x0
2026-11-09T09:31:40Z  4769  alice         MSSQLSvc/sql11.corp.local:1433            10.0.0.66        enc=0x17 st=0x0
2026-11-09T09:31:44Z  4769  alice         MSSQLSvc/sql12.corp.local:1433            10.0.0.66        enc=0x17 st=0x0
... 其余 48 条略
```

### 3. [HIGH] 新主机突访高权限服务：账户 dave 来自陌生地址 10.0.9.99

账户 dave 的历史来源地址为 10.0.0.14，2026-11-09T22:15:03Z 起突然从陌生地址 10.0.9.99 请求高权限服务：CIFS/DC01.corp.local, LDAP/DC01.corp.local, cifs/DC01.corp.local。该地址在整个日志中从未出现过。

**处置建议**：核实该来源主机归属；检查账户凭据是否被盗用（Pass-the-Hash / 被窃票据重放）；必要时强制改密。

证据（前 12 条，共 3 条）：

```
2026-11-09T22:15:03Z  4769  dave          CIFS/DC01.corp.local                      10.0.9.99        enc=0x12 st=0x0
2026-11-09T22:15:20Z  4769  dave          LDAP/DC01.corp.local                      10.0.9.99        enc=0x12 st=0x0
2026-11-09T22:16:01Z  4769  dave          cifs/DC01.corp.local                      10.0.9.99        enc=0x12 st=0x0
```

### 4. [MEDIUM] 票据有效期异常：账户 svc_backup 的 TGT 被持续使用 26.0 小时

账户 svc_backup 于 2026-11-08T01:00:00Z 从 10.0.0.31 获取 TGT 后，直到 2026-11-09T03:00:00Z 仍在使用该 TGT 请求服务票据（连续活动跨度 26.0 小时，域默认上限 10 小时），期间未重新认证。疑似伪造/窃取的长期票据（如 Golden Ticket）。

**处置建议**：检查该账户 TGT 的加密类型与来源主机；若确认伪造票据，需两次重置 krbtgt 账户口令。

证据（前 12 条，共 27 条）：

```
2026-11-08T01:00:00Z  4768  svc_backup    krbtgt                                    10.0.0.31        enc=0x12 st=0x0
2026-11-08T02:00:00Z  4769  svc_backup    cifs/backup01.corp.local                  10.0.0.31        enc=0x12 st=0x0
2026-11-08T03:00:00Z  4769  svc_backup    cifs/backup01.corp.local                  10.0.0.31        enc=0x12 st=0x0
2026-11-08T04:00:00Z  4769  svc_backup    cifs/backup01.corp.local                  10.0.0.31        enc=0x12 st=0x0
2026-11-08T05:00:00Z  4769  svc_backup    cifs/backup01.corp.local                  10.0.0.31        enc=0x12 st=0x0
2026-11-08T06:00:00Z  4769  svc_backup    cifs/backup01.corp.local                  10.0.0.31        enc=0x12 st=0x0
2026-11-08T07:00:00Z  4769  svc_backup    cifs/backup01.corp.local                  10.0.0.31        enc=0x12 st=0x0
2026-11-08T08:00:00Z  4769  svc_backup    cifs/backup01.corp.local                  10.0.0.31        enc=0x12 st=0x0
2026-11-08T09:00:00Z  4769  svc_backup    cifs/backup01.corp.local                  10.0.0.31        enc=0x12 st=0x0
2026-11-08T10:00:00Z  4769  svc_backup    cifs/backup01.corp.local                  10.0.0.31        enc=0x12 st=0x0
2026-11-08T11:00:00Z  4769  svc_backup    cifs/backup01.corp.local                  10.0.0.31        enc=0x12 st=0x0
2026-11-08T12:00:00Z  4769  svc_backup    cifs/backup01.corp.local                  10.0.0.31        enc=0x12 st=0x0
... 其余 15 条略
```

## 攻击时间线（告警涉及事件，按时间排序）

```
2026-11-08T01:00:00Z  4768  svc_backup    krbtgt                                    10.0.0.31        enc=0x12 st=0x0  [long_tgt]
2026-11-08T02:00:00Z  4769  svc_backup    cifs/backup01.corp.local                  10.0.0.31        enc=0x12 st=0x0  [long_tgt]
2026-11-08T03:00:00Z  4769  svc_backup    cifs/backup01.corp.local                  10.0.0.31        enc=0x12 st=0x0  [long_tgt]
2026-11-08T04:00:00Z  4769  svc_backup    cifs/backup01.corp.local                  10.0.0.31        enc=0x12 st=0x0  [long_tgt]
2026-11-08T05:00:00Z  4769  svc_backup    cifs/backup01.corp.local                  10.0.0.31        enc=0x12 st=0x0  [long_tgt]
2026-11-08T06:00:00Z  4769  svc_backup    cifs/backup01.corp.local                  10.0.0.31        enc=0x12 st=0x0  [long_tgt]
2026-11-08T07:00:00Z  4769  svc_backup    cifs/backup01.corp.local                  10.0.0.31        enc=0x12 st=0x0  [long_tgt]
2026-11-08T08:00:00Z  4769  svc_backup    cifs/backup01.corp.local                  10.0.0.31        enc=0x12 st=0x0  [long_tgt]
2026-11-08T09:00:00Z  4769  svc_backup    cifs/backup01.corp.local                  10.0.0.31        enc=0x12 st=0x0  [long_tgt]
2026-11-08T10:00:00Z  4769  svc_backup    cifs/backup01.corp.local                  10.0.0.31        enc=0x12 st=0x0  [long_tgt]
2026-11-08T11:00:00Z  4769  svc_backup    cifs/backup01.corp.local                  10.0.0.31        enc=0x12 st=0x0  [long_tgt]
2026-11-08T12:00:00Z  4769  svc_backup    cifs/backup01.corp.local                  10.0.0.31        enc=0x12 st=0x0  [long_tgt]
2026-11-08T13:00:00Z  4769  svc_backup    cifs/backup01.corp.local                  10.0.0.31        enc=0x12 st=0x0  [long_tgt]
2026-11-08T14:00:00Z  4769  svc_backup    cifs/backup01.corp.local                  10.0.0.31        enc=0x12 st=0x0  [long_tgt]
2026-11-08T15:00:00Z  4769  svc_backup    cifs/backup01.corp.local                  10.0.0.31        enc=0x12 st=0x0  [long_tgt]
2026-11-08T16:00:00Z  4769  svc_backup    cifs/backup01.corp.local                  10.0.0.31        enc=0x12 st=0x0  [long_tgt]
2026-11-08T17:00:00Z  4769  svc_backup    cifs/backup01.corp.local                  10.0.0.31        enc=0x12 st=0x0  [long_tgt]
2026-11-08T18:00:00Z  4769  svc_backup    cifs/backup01.corp.local                  10.0.0.31        enc=0x12 st=0x0  [long_tgt]
2026-11-08T19:00:00Z  4769  svc_backup    cifs/backup01.corp.local                  10.0.0.31        enc=0x12 st=0x0  [long_tgt]
2026-11-08T20:00:00Z  4769  svc_backup    cifs/backup01.corp.local                  10.0.0.31        enc=0x12 st=0x0  [long_tgt]
2026-11-08T21:00:00Z  4769  svc_backup    cifs/backup01.corp.local                  10.0.0.31        enc=0x12 st=0x0  [long_tgt]
2026-11-08T22:00:00Z  4769  svc_backup    cifs/backup01.corp.local                  10.0.0.31        enc=0x12 st=0x0  [long_tgt]
2026-11-08T23:00:00Z  4769  svc_backup    cifs/backup01.corp.local                  10.0.0.31        enc=0x12 st=0x0  [long_tgt]
2026-11-09T00:00:00Z  4769  svc_backup    cifs/backup01.corp.local                  10.0.0.31        enc=0x12 st=0x0  [long_tgt]
2026-11-09T01:00:00Z  4769  svc_backup    cifs/backup01.corp.local                  10.0.0.31        enc=0x12 st=0x0  [long_tgt]
2026-11-09T02:00:00Z  4769  svc_backup    cifs/backup01.corp.local                  10.0.0.31        enc=0x12 st=0x0  [long_tgt]
2026-11-09T03:00:00Z  4769  svc_backup    cifs/backup01.corp.local                  10.0.0.31        enc=0x12 st=0x0  [long_tgt]
2026-11-09T03:12:00Z  4771  user00        krbtgt                                    10.0.9.100       enc=-    st=0x18  [password_spray]
2026-11-09T03:12:03Z  4771  user01        krbtgt                                    10.0.9.100       enc=-    st=0x18  [password_spray]
2026-11-09T03:12:06Z  4771  user02        krbtgt                                    10.0.9.100       enc=-    st=0x18  [password_spray]
2026-11-09T03:12:09Z  4771  user03        krbtgt                                    10.0.9.100       enc=-    st=0x18  [password_spray]
2026-11-09T03:12:12Z  4771  user04        krbtgt                                    10.0.9.100       enc=-    st=0x18  [password_spray]
2026-11-09T03:12:15Z  4771  user05        krbtgt                                    10.0.9.100       enc=-    st=0x18  [password_spray]
2026-11-09T03:12:18Z  4771  user06        krbtgt                                    10.0.9.100       enc=-    st=0x18  [password_spray]
2026-11-09T03:12:21Z  4771  user07        krbtgt                                    10.0.9.100       enc=-    st=0x18  [password_spray]
2026-11-09T03:12:24Z  4771  user08        krbtgt                                    10.0.9.100       enc=-    st=0x18  [password_spray]
2026-11-09T03:12:27Z  4771  user09        krbtgt                                    10.0.9.100       enc=-    st=0x18  [password_spray]
2026-11-09T03:12:30Z  4771  user10        krbtgt                                    10.0.9.100       enc=-    st=0x18  [password_spray]
2026-11-09T03:12:33Z  4771  user11        krbtgt                                    10.0.9.100       enc=-    st=0x18  [password_spray]
2026-11-09T03:12:36Z  4771  user12        krbtgt                                    10.0.9.100       enc=-    st=0x18  [password_spray]
2026-11-09T03:12:39Z  4771  user13        krbtgt                                    10.0.9.100       enc=-    st=0x18  [password_spray]
2026-11-09T03:12:42Z  4771  user14        krbtgt                                    10.0.9.100       enc=-    st=0x18  [password_spray]
2026-11-09T03:12:45Z  4771  user15        krbtgt                                    10.0.9.100       enc=-    st=0x18  [password_spray]
2026-11-09T03:12:48Z  4771  user16        krbtgt                                    10.0.9.100       enc=-    st=0x18  [password_spray]
2026-11-09T03:12:51Z  4771  user17        krbtgt                                    10.0.9.100       enc=-    st=0x18  [password_spray]
2026-11-09T03:12:54Z  4771  user18        krbtgt                                    10.0.9.100       enc=-    st=0x18  [password_spray]
2026-11-09T03:12:57Z  4771  user19        krbtgt                                    10.0.9.100       enc=-    st=0x18  [password_spray]
2026-11-09T03:13:00Z  4771  user20        krbtgt                                    10.0.9.100       enc=-    st=0x18  [password_spray]
2026-11-09T03:13:03Z  4771  user21        krbtgt                                    10.0.9.100       enc=-    st=0x18  [password_spray]
2026-11-09T03:13:06Z  4771  user22        krbtgt                                    10.0.9.100       enc=-    st=0x18  [password_spray]
2026-11-09T03:13:09Z  4771  user23        krbtgt                                    10.0.9.100       enc=-    st=0x18  [password_spray]
2026-11-09T03:13:12Z  4771  user24        krbtgt                                    10.0.9.100       enc=-    st=0x18  [password_spray]
2026-11-09T03:13:15Z  4771  user25        krbtgt                                    10.0.9.100       enc=-    st=0x18  [password_spray]
2026-11-09T03:13:18Z  4771  user26        krbtgt                                    10.0.9.100       enc=-    st=0x18  [password_spray]
2026-11-09T03:13:21Z  4771  user27        krbtgt                                    10.0.9.100       enc=-    st=0x18  [password_spray]
2026-11-09T03:13:24Z  4771  user28        krbtgt                                    10.0.9.100       enc=-    st=0x18  [password_spray]
2026-11-09T03:13:27Z  4771  user29        krbtgt                                    10.0.9.100       enc=-    st=0x18  [password_spray]
2026-11-09T09:31:00Z  4769  alice         MSSQLSvc/sql01.corp.local:1433            10.0.0.66        enc=0x17 st=0x0  [rc4_burst]
2026-11-09T09:31:04Z  4769  alice         MSSQLSvc/sql02.corp.local:1433            10.0.0.66        enc=0x17 st=0x0  [rc4_burst]
2026-11-09T09:31:08Z  4769  alice         MSSQLSvc/sql03.corp.local:1433            10.0.0.66        enc=0x17 st=0x0  [rc4_burst]
2026-11-09T09:31:12Z  4769  alice         MSSQLSvc/sql04.corp.local:1433            10.0.0.66        enc=0x17 st=0x0  [rc4_burst]
2026-11-09T09:31:16Z  4769  alice         MSSQLSvc/sql05.corp.local:1433            10.0.0.66        enc=0x17 st=0x0  [rc4_burst]
2026-11-09T09:31:20Z  4769  alice         MSSQLSvc/sql06.corp.local:1433            10.0.0.66        enc=0x17 st=0x0  [rc4_burst]
2026-11-09T09:31:24Z  4769  alice         MSSQLSvc/sql07.corp.local:1433            10.0.0.66        enc=0x17 st=0x0  [rc4_burst]
2026-11-09T09:31:28Z  4769  alice         MSSQLSvc/sql08.corp.local:1433            10.0.0.66        enc=0x17 st=0x0  [rc4_burst]
2026-11-09T09:31:32Z  4769  alice         MSSQLSvc/sql09.corp.local:1433            10.0.0.66        enc=0x17 st=0x0  [rc4_burst]
2026-11-09T09:31:36Z  4769  alice         MSSQLSvc/sql10.corp.local:1433            10.0.0.66        enc=0x17 st=0x0  [rc4_burst]
2026-11-09T09:31:40Z  4769  alice         MSSQLSvc/sql11.corp.local:1433            10.0.0.66        enc=0x17 st=0x0  [rc4_burst]
2026-11-09T09:31:44Z  4769  alice         MSSQLSvc/sql12.corp.local:1433            10.0.0.66        enc=0x17 st=0x0  [rc4_burst]
2026-11-09T09:31:48Z  4769  alice         MSSQLSvc/sql13.corp.local:1433            10.0.0.66        enc=0x17 st=0x0  [rc4_burst]
2026-11-09T09:31:52Z  4769  alice         MSSQLSvc/sql14.corp.local:1433            10.0.0.66        enc=0x17 st=0x0  [rc4_burst]
2026-11-09T09:31:56Z  4769  alice         MSSQLSvc/sql15.corp.local:1433            10.0.0.66        enc=0x17 st=0x0  [rc4_burst]
2026-11-09T09:32:00Z  4769  alice         MSSQLSvc/sql16.corp.local:1433            10.0.0.66        enc=0x17 st=0x0  [rc4_burst]
2026-11-09T09:32:04Z  4769  alice         MSSQLSvc/sql17.corp.local:1433            10.0.0.66        enc=0x17 st=0x0  [rc4_burst]
2026-11-09T09:32:08Z  4769  alice         MSSQLSvc/sql18.corp.local:1433            10.0.0.66        enc=0x17 st=0x0  [rc4_burst]
2026-11-09T09:32:12Z  4769  alice         MSSQLSvc/sql19.corp.local:1433            10.0.0.66        enc=0x17 st=0x0  [rc4_burst]
2026-11-09T09:32:16Z  4769  alice         MSSQLSvc/sql20.corp.local:1433            10.0.0.66        enc=0x17 st=0x0  [rc4_burst]
2026-11-09T09:32:20Z  4769  alice         HTTP/web01.corp.local                     10.0.0.66        enc=0x17 st=0x0  [rc4_burst]
2026-11-09T09:32:24Z  4769  alice         HTTP/web02.corp.local                     10.0.0.66        enc=0x17 st=0x0  [rc4_burst]
2026-11-09T09:32:28Z  4769  alice         HTTP/web03.corp.local                     10.0.0.66        enc=0x17 st=0x0  [rc4_burst]
2026-11-09T09:32:32Z  4769  alice         HTTP/web04.corp.local                     10.0.0.66        enc=0x17 st=0x0  [rc4_burst]
2026-11-09T09:32:36Z  4769  alice         HTTP/web05.corp.local                     10.0.0.66        enc=0x17 st=0x0  [rc4_burst]
2026-11-09T09:32:40Z  4769  alice         HTTP/web06.corp.local                     10.0.0.66        enc=0x17 st=0x0  [rc4_burst]
2026-11-09T09:32:44Z  4769  alice         HTTP/web07.corp.local                     10.0.0.66        enc=0x17 st=0x0  [rc4_burst]
2026-11-09T09:32:48Z  4769  alice         HTTP/web08.corp.local                     10.0.0.66        enc=0x17 st=0x0  [rc4_burst]
2026-11-09T09:32:52Z  4769  alice         HTTP/web09.corp.local                     10.0.0.66        enc=0x17 st=0x0  [rc4_burst]
2026-11-09T09:32:56Z  4769  alice         HTTP/web10.corp.local                     10.0.0.66        enc=0x17 st=0x0  [rc4_burst]
2026-11-09T09:33:00Z  4769  alice         HTTP/web11.corp.local                     10.0.0.66        enc=0x17 st=0x0  [rc4_burst]
2026-11-09T09:33:04Z  4769  alice         HTTP/web12.corp.local                     10.0.0.66        enc=0x17 st=0x0  [rc4_burst]
2026-11-09T09:33:08Z  4769  alice         HTTP/web13.corp.local                     10.0.0.66        enc=0x17 st=0x0  [rc4_burst]
2026-11-09T09:33:12Z  4769  alice         HTTP/web14.corp.local                     10.0.0.66        enc=0x17 st=0x0  [rc4_burst]
2026-11-09T09:33:16Z  4769  alice         HTTP/web15.corp.local                     10.0.0.66        enc=0x17 st=0x0  [rc4_burst]
2026-11-09T09:33:20Z  4769  alice         HTTP/web16.corp.local                     10.0.0.66        enc=0x17 st=0x0  [rc4_burst]
2026-11-09T09:33:24Z  4769  alice         HTTP/web17.corp.local                     10.0.0.66        enc=0x17 st=0x0  [rc4_burst]
2026-11-09T09:33:28Z  4769  alice         HTTP/web18.corp.local                     10.0.0.66        enc=0x17 st=0x0  [rc4_burst]
2026-11-09T09:33:32Z  4769  alice         HTTP/web19.corp.local                     10.0.0.66        enc=0x17 st=0x0  [rc4_burst]
2026-11-09T09:33:36Z  4769  alice         HTTP/web20.corp.local                     10.0.0.66        enc=0x17 st=0x0  [rc4_burst]
2026-11-09T09:33:40Z  4769  alice         svc_app01/app01.corp.local                10.0.0.66        enc=0x17 st=0x0  [rc4_burst]
2026-11-09T09:33:44Z  4769  alice         svc_app02/app02.corp.local                10.0.0.66        enc=0x17 st=0x0  [rc4_burst]
2026-11-09T09:33:48Z  4769  alice         svc_app03/app03.corp.local                10.0.0.66        enc=0x17 st=0x0  [rc4_burst]
2026-11-09T09:33:52Z  4769  alice         svc_app04/app04.corp.local                10.0.0.66        enc=0x17 st=0x0  [rc4_burst]
2026-11-09T09:33:56Z  4769  alice         svc_app05/app05.corp.local                10.0.0.66        enc=0x17 st=0x0  [rc4_burst]
2026-11-09T09:34:00Z  4769  alice         svc_app06/app06.corp.local                10.0.0.66        enc=0x17 st=0x0  [rc4_burst]
2026-11-09T09:34:04Z  4769  alice         svc_app07/app07.corp.local                10.0.0.66        enc=0x17 st=0x0  [rc4_burst]
2026-11-09T09:34:08Z  4769  alice         svc_app08/app08.corp.local                10.0.0.66        enc=0x17 st=0x0  [rc4_burst]
2026-11-09T09:34:12Z  4769  alice         svc_app09/app09.corp.local                10.0.0.66        enc=0x17 st=0x0  [rc4_burst]
2026-11-09T09:34:16Z  4769  alice         svc_app10/app10.corp.local                10.0.0.66        enc=0x17 st=0x0  [rc4_burst]
2026-11-09T09:34:20Z  4769  alice         svc_app11/app11.corp.local                10.0.0.66        enc=0x17 st=0x0  [rc4_burst]
2026-11-09T09:34:24Z  4769  alice         svc_app12/app12.corp.local                10.0.0.66        enc=0x17 st=0x0  [rc4_burst]
2026-11-09T09:34:28Z  4769  alice         svc_app13/app13.corp.local                10.0.0.66        enc=0x17 st=0x0  [rc4_burst]
2026-11-09T09:34:32Z  4769  alice         svc_app14/app14.corp.local                10.0.0.66        enc=0x17 st=0x0  [rc4_burst]
2026-11-09T09:34:36Z  4769  alice         svc_app15/app15.corp.local                10.0.0.66        enc=0x17 st=0x0  [rc4_burst]
2026-11-09T09:34:40Z  4769  alice         svc_app16/app16.corp.local                10.0.0.66        enc=0x17 st=0x0  [rc4_burst]
2026-11-09T09:34:44Z  4769  alice         svc_app17/app17.corp.local                10.0.0.66        enc=0x17 st=0x0  [rc4_burst]
2026-11-09T09:34:48Z  4769  alice         svc_app18/app18.corp.local                10.0.0.66        enc=0x17 st=0x0  [rc4_burst]
2026-11-09T09:34:52Z  4769  alice         svc_app19/app19.corp.local                10.0.0.66        enc=0x17 st=0x0  [rc4_burst]
2026-11-09T09:34:56Z  4769  alice         svc_app20/app20.corp.local                10.0.0.66        enc=0x17 st=0x0  [rc4_burst]
2026-11-09T22:15:03Z  4769  dave          CIFS/DC01.corp.local                      10.0.9.99        enc=0x12 st=0x0  [new_host_highpriv]
2026-11-09T22:15:20Z  4769  dave          LDAP/DC01.corp.local                      10.0.9.99        enc=0x12 st=0x0  [new_host_highpriv]
2026-11-09T22:16:01Z  4769  dave          cifs/DC01.corp.local                      10.0.9.99        enc=0x12 st=0x0  [new_host_highpriv]
```
