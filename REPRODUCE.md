# SmartPGP 卡片个人化复现指南（单文件版）

> **本文档自包含**：从零复现「安全修复编译 → 安装 applet → 生成 3 组 RSA-2048
> 密钥＋自签证书 → 导入卡片 → 恢复出厂救援通道验证」全流程。
> 补丁与全部脚本已完整内嵌，只需上游源码仓＋本文档即可复现。

---

## 0. 产出物与参考值

| 项目 | 值 |
|---|---|
| CAP 文件 | `SmartPGPApplet.cap`（约 118 KB，bytecode verifier 通过） |
| CAP sha256（参考） | `43e7308687f185f871519f23d21e68dac7926484b7d1abaa201ab2c73b62a8aa` |
| Applet AID | `D276000124010304AFAF000000000000`（OpenPGP card 3.4） |
| 密钥 | 3 × RSA-2048（SIG / DEC / AUT），私钥卡内＋本地加密备份 |
| 证书 | 3 × X.509 自签 DER（812 / 814 / 822 字节，卡片上限 1152） |
| 本地备份 | `keys/`（加密 PEM＋`BACKUP_PASSPHRASE.txt`＋`MANIFEST.txt`） |

> ⚠️ 本文中的**指纹、证书哈希是本机示例值**，你复现时会不同（密钥是随机生成的）。
> 只有流程、APDU 结构、SW 回应码应当一致。

---

## 1. 硬件与环境

| 类别 | 要求 |
|---|---|
| 读卡器 | 任意 PC/SC 读卡器（本文实测 ACS ACR1281U，读卡器索引 1） |
| 卡片 | JavaCard 3.0.4+，GP 2.3 / SCP02，RAM ≥2 KB、NVM ≥33 KB（实测 JCOP4 J3R180/J3R200） |
| 主机 | Linux ＋ `pcscd` 运行中 |

### 1.1 软件依赖

```bash
sudo apt-get install -y openjdk-8-jdk-headless ant git pcscd libpcsclite-dev \
    python3-pyscard openssl gnupg
pip3 install cryptography            # 或 apt python3-cryptography

# JavaCard SDK 3.0.4
git clone https://github.com/martinpaljak/oracle_javacard_sdks /tmp/jcsdk
export JC_HOME=/tmp/jcsdk/jc304_kit

# GlobalPlatformPro（下载 gp.jar 到 /tmp/gp.jar）
curl -L -o /tmp/gp.jar \
    https://github.com/martinpaljak/GlobalPlatformPro/releases/latest/download/gp.jar
```

**JDK 版本是硬性要求**：ant-javacard 对 JavaCard 3.0.4 只接受 **JDK 8/11**。
JDK 17 报 `Can't use JDK 17 with JavaCard kit 3.0.4 (use JDK 11)`；
JDK >17 报 `JDK 17 is the latest supported JDK`。

### 1.2 确认卡片在位

```bash
pcsc_scan &                # 或 gpg --card-status
```

---

## 2. 获取源码并应用安全修复

```bash
git clone https://github.com/ANSSI-FR/SmartPGP   # 或 github-af/SmartPGP
cd SmartPGP
git checkout 2a06700                              # 本文基线 commit
```

把本文内嵌补丁存为 `repro.patch`（完整内容见 2.2），然后：

```bash
git apply repro.patch
echo "keys/" >> .gitignore
```

### 2.1 修复摘要（6 文件，+123/-44）

| # | 文件 | 修复内容 | 级别 |
|---|---|---|---|
| 1 | `SmartPGPApplet.java` | 命令分发 `try` 覆盖 `prepareChainingInput`/`receiveData`/SM 解密，`catch RuntimeException`＋`abortTransaction`，SM 路径的运行时异常不再逃逸 `process()` | 中 |
| 2 | `SmartPGPApplet.java` | `receiveData` 长度检查改 `lc > 0x500 - off` 并拒绝负 lc（原 `off + lc` 加法可短溢位绕过；ExtendedLength 的 Lc>0x7FFF 时 `getIncomingLength()` 为负） | 中 |
| 3 | `SmartPGPApplet.java` | AES PSO ENCIPHER/DECIPHER 输出缓冲区边界检查（`2*lc±1 ≤ 0x500`） | 中 |
| 4 | `Common.java` | `readLength` 拒绝负长度（`0x82` 长度字段高位绕过）——根因修复 | 中 |
| 5 | `PGPKey.java` | RSA/EC 密钥导入长度检查改为溢位安全写法＋负值防护 | 中 |
| 6 | `PGPKey.java` | RSA sign/decipher 输出缓冲区边界检查 | 中 |
| 7 | `SecureMessaging.java` | `verifyAndDecryptCommand`/`encryptAndSign` 尾部写（MAC/填充块位于 `buf[dataLen..+16)`）边界检查：`dataLen ≤ 0x4F0`，超出回 `6581` 而非 AIOOBE（lc∈[0x4F1,0x4F9] 时原本溢出 1–9 字节） | 中 |
| 8 | `PGPKey.java` | RSA 模长白名单 `{2048,3072,4096}`（原仅查 ≥2048，可设硬件不支持的 0x7FFF 等；与 `writeAlgorithmInformation` 广播集一致） | 中 |
| 9 | `PGPKey.java` | 凭证清除顺序错误（先归零长度导致旧凭证残留 EEPROM）＋加事务 | 低 |
| 10 | `SmartPGPApplet.java` | `minlen` byte 溢位绕过 PIN 长度检查（3 处）＋ `key_derivation_function_length` 截断 | 低 |
| 11 | `SmartPGPApplet.java` | PUT DATA `0xF9` 写入前校验 KDF-DO：拒绝「`keyDerivationIsActive()` 为真（len≥3、`[0]==0x81`、`[2]≠0`）但 `keyDerivationSize()==0`（len<6 或 `[5]∉{0x08,0x0A}`）」的畸形 DO——否则所有 PIN 验证恒失败，只能恢复出厂（#10 截断修复把可达长度域扩到 128..255 后暴露；旧代码 6..127 亦可触发，属既有问题一并闭合） | 低 |
| 12 | `SecureMessaging.java` | `clearSession` 检查错对象（`senc`→`sreceiptmac`）；新增越界守卫与相邻失败路径一致地 `clearSession` | 低 |
| 13 | `Persistent.java` | 建构子 typo（`do_0102_length`）＋ `user_puk_length` 赋值类型风格 | 卫生 |

**行为等价性**（已在代码复核中确认）：

- `try` 内抛出的 `ISOException`（链接错误 `6883`、SM 校验失败 `6982` 等）经 `sw` 记录后在方法末尾
  `throwIt(sw)` 重抛，响应码与原先直接逃逸一致；`secureMessagingOk` 仅在 SM 校验成功后置位，
  失败路径仍跳过响应加密；`try` 内无可达 `return`（`throwIt` 后的 `return` 不可达）。
- SM 命令上限由隐含的 `lc ≤ 0x4F9` 精确收紧到 `lc ≤ 0x4F0`（MAC 需完整 16 字节尾块），超出回 `6581`。
- GET_RESPONSE、命令链接续包分支逻辑未变；续包分支的 `receiveData` 负 lc 路径已由 #2 一并闭合。

**保留规格行为（有意不修）**：admin PIN 锁死后 `TERMINATE DF` 免认证＋
`ACTIVATE FILE` 恢复出厂。这是 OpenPGP 规格的救援通道（见第 8 节实测），
代价是任何人可借「锁死 admin PIN → TERMINATE → ACTIVATE」抹卡（只能销毁、无法提取私钥）。

### 2.2 完整补丁（`repro.patch`）

```diff
diff --git a/.gitignore b/.gitignore
index 97f838b..4e2744b 100644
--- a/.gitignore
+++ b/.gitignore
@@ -1,3 +1,4 @@
 ant-javacard.jar
 build
 SmartPGPApplet.cap
+keys/
diff --git a/src/fr/anssi/smartpgp/Common.java b/src/fr/anssi/smartpgp/Common.java
index ef18752..4b82916 100644
--- a/src/fr/anssi/smartpgp/Common.java
+++ b/src/fr/anssi/smartpgp/Common.java
@@ -138,12 +138,19 @@ public final class Common {
             }
             return Util.makeShort((byte)0, buf[(short)(off + 1)]);
 
-        case (byte)0x82:
+        case (byte)0x82: {
             if(len < 3) {
                 ISOException.throwIt(ISO7816.SW_WRONG_DATA);
                 return (short)0;
             }
-            return Util.getShort(buf, (short)(off + 1));
+            final short v = Util.getShort(buf, (short)(off + 1));
+            /* Reject negative lengths: the 16-bit length is signed in Java */
+            if(v < 0) {
+                ISOException.throwIt(ISO7816.SW_WRONG_DATA);
+                return (short)0;
+            }
+            return v;
+        }
 
         default:
             ISOException.throwIt(ISO7816.SW_WRONG_DATA);
diff --git a/src/fr/anssi/smartpgp/PGPKey.java b/src/fr/anssi/smartpgp/PGPKey.java
index c291995..2dd0ae9 100644
--- a/src/fr/anssi/smartpgp/PGPKey.java
+++ b/src/fr/anssi/smartpgp/PGPKey.java
@@ -74,8 +74,10 @@ public final class PGPKey {
         }
 
         if(certificate_length > 0) {
-            certificate_length = (short)0;
+            Common.beginTransaction(isRegistering);
             Util.arrayFillNonAtomic(certificate, (short)0, certificate_length, (byte)0);
+            certificate_length = (short)0;
+            Common.commitTransaction(isRegistering);
         }
 
         if(!is_secure_messaging_key) {
@@ -164,7 +166,8 @@ public final class PGPKey {
                 ISOException.throwIt(ISO7816.SW_WRONG_DATA);
                 return;
             }
-            if((Util.getShort(buf, (short)(off + 1)) < 2048) ||
+            final short modbits = Util.getShort(buf, (short)(off + 1));
+            if(((modbits != (short)2048) && (modbits != (short)3072) && (modbits != (short)4096)) ||
                (Util.getShort(buf, (short)(off + 3)) != 0x11) ||
                (buf[(short)(off + 5)] < 0) || (buf[(short)(off + 5)] > 3)) {
                 ISOException.throwIt(ISO7816.SW_WRONG_DATA);
@@ -313,7 +316,7 @@ public final class PGPKey {
         byte i = 0;
         while(i < tag_count) {
 
-            if((short)((short)(off - boff) + tag_len[i]) > len) {
+            if((tag_len[i] < 0) || ((short)(off - boff) > (short)(len - tag_len[i]))) {
                 ISOException.throwIt(ISO7816.SW_WRONG_DATA);
                 return null;
             }
@@ -407,7 +410,7 @@ public final class PGPKey {
         byte i = 0;
         while(i < tag_count) {
 
-            if((short)((short)(off - boff) + tag_len[i]) > len) {
+            if((tag_len[i] < 0) || ((short)(off - boff) > (short)(len - tag_len[i]))) {
                 ISOException.throwIt(ISO7816.SW_WRONG_DATA);
                 return null;
             }
@@ -636,6 +639,12 @@ public final class PGPKey {
                 return 0;
             }
 
+            /* The signature is written at buf[lc]: make sure it fits */
+            if((short)(lc + Common.bitsToBytes(rsaModulusBitSize())) > Constants.INTERNAL_BUFFER_MAX_LENGTH) {
+                ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
+                return 0;
+            }
+
             common.cipher_rsa_pkcs1.init(priv, Cipher.MODE_ENCRYPT);
 
             off = common.cipher_rsa_pkcs1.doFinal(buf, (short)0, lc,
@@ -753,6 +762,12 @@ public final class PGPKey {
                 return 0;
             }
 
+            /* The plaintext is written at buf[lc]: make sure it fits */
+            if((short)(lc + modulus_size) > Constants.INTERNAL_BUFFER_MAX_LENGTH) {
+                ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
+                return 0;
+            }
+
             if(buf[0] != (byte)0) {
                 ISOException.throwIt(ISO7816.SW_WRONG_DATA);
                 return 0;
diff --git a/src/fr/anssi/smartpgp/Persistent.java b/src/fr/anssi/smartpgp/Persistent.java
index 175d6a5..f06b149 100644
--- a/src/fr/anssi/smartpgp/Persistent.java
+++ b/src/fr/anssi/smartpgp/Persistent.java
@@ -112,7 +112,7 @@ public final class Persistent {
         do_0101_length = 0;
 
         do_0102 = new byte[Constants.specialDoMaxLength()];
-        do_0101_length = 0;
+        do_0102_length = 0;
 
         do_0103 = new byte[Constants.specialDoMaxLength()];
         do_0103_length = 0;
@@ -240,7 +240,7 @@ public final class Persistent {
         user_pin.resetAndUnblock();
 
         Common.beginTransaction(isRegistering);
-        user_puk_length = (short)0;
+        user_puk_length = (byte)0;
         /* Ensures any previously defined PUK code is blocked at factory reset */
         byte[] emptyPin = new byte[1];
         while(user_puk.getTriesRemaining() > 0) {
diff --git a/src/fr/anssi/smartpgp/SecureMessaging.java b/src/fr/anssi/smartpgp/SecureMessaging.java
index da1d29f..01bb394 100644
--- a/src/fr/anssi/smartpgp/SecureMessaging.java
+++ b/src/fr/anssi/smartpgp/SecureMessaging.java
@@ -89,7 +89,7 @@ public final class SecureMessaging {
 
         macer.clear();
         Util.arrayFillNonAtomic(mac_chaining, (short)0, (short)mac_chaining.length, (byte)0);
-        if((sreceiptmac != null) && senc.isInitialized()) {
+        if((sreceiptmac != null) && sreceiptmac.isInitialized()) {
             sreceiptmac.clearKey();
         }
         if((smac != null) && smac.isInitialized()) {
@@ -335,6 +335,14 @@ public final class SecureMessaging {
             return 0;
         }
 
+        /* The computed MAC and the MAC chaining value are written at
+         * buf[dataLen]: make sure a full block fits there. */
+        if(dataLen > (short)(Constants.INTERNAL_BUFFER_MAX_LENGTH - Constants.AES_BLOCK_SIZE)) {
+            clearSession(transients);
+            ISOException.throwIt(Constants.SW_MEMORY_FAILURE);
+            return 0;
+        }
+
         final byte[] buf = transients.buffer;
 
         macer.init(smac);
@@ -420,6 +428,14 @@ public final class SecureMessaging {
             return 0;
         }
 
+        /* The padding block and the MAC are written at buf[dataLen]:
+         * make sure a full block fits there. */
+        if((dataLen < 0) ||
+           (dataLen > (short)(Constants.INTERNAL_BUFFER_MAX_LENGTH - Constants.AES_BLOCK_SIZE))) {
+            ISOException.throwIt(Constants.SW_MEMORY_FAILURE);
+            return 0;
+        }
+
         final byte[] buf = transients.buffer;
 
         if(dataLen > 0) {
diff --git a/src/fr/anssi/smartpgp/SmartPGPApplet.java b/src/fr/anssi/smartpgp/SmartPGPApplet.java
index 33e703d..02bca0e 100644
--- a/src/fr/anssi/smartpgp/SmartPGPApplet.java
+++ b/src/fr/anssi/smartpgp/SmartPGPApplet.java
@@ -111,7 +111,9 @@ public final class SmartPGPApplet extends Applet implements ExtendedLength {
 
         short off = transients.chainingInputLength();
 
-        if((short)(off + lc) > Constants.INTERNAL_BUFFER_MAX_LENGTH) {
+        /* lc is signed: ExtendedLength Lc above 0x7FFF would come out
+         * negative and bypass the bound check below */
+        if((lc < 0) || (lc > (short)(Constants.INTERNAL_BUFFER_MAX_LENGTH - off))) {
             transients.setChainingInput(false);
             transients.setChainingInputLength((short)0);
             ISOException.throwIt(Constants.SW_MEMORY_FAILURE);
@@ -656,7 +658,7 @@ public final class SmartPGPApplet extends Applet implements ExtendedLength {
         sensitiveData();
 
         byte off;
-        byte minlen;
+        short minlen;
 
         if(p1 != 0) {
             ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
@@ -682,7 +684,7 @@ public final class SmartPGPApplet extends Applet implements ExtendedLength {
                 ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
                 return;
             }
-            minlen = (byte)(lc - off);
+            minlen = (short)(lc - off);
             if(data.keyDerivationIsActive()) {
                 if(data.keyDerivationSize() != minlen) {
                     ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
@@ -696,7 +698,7 @@ public final class SmartPGPApplet extends Applet implements ExtendedLength {
                 }
             }
             JCSystem.beginTransaction();
-            data.user_pin_length = minlen;
+            data.user_pin_length = (byte)minlen;
             data.user_pin.update(transients.buffer, off, data.user_pin_length);
             JCSystem.commitTransaction();
             data.user_pin.resetAndUnblock();
@@ -718,7 +720,7 @@ public final class SmartPGPApplet extends Applet implements ExtendedLength {
                 ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
                 return;
             }
-            minlen = (byte)(lc - off);
+            minlen = (short)(lc - off);
             if(data.keyDerivationIsActive()) {
                 if(data.keyDerivationSize() != minlen) {
                     ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
@@ -732,7 +734,7 @@ public final class SmartPGPApplet extends Applet implements ExtendedLength {
                 }
             }
             JCSystem.beginTransaction();
-            data.admin_pin_length = minlen;
+            data.admin_pin_length = (byte)minlen;
             data.admin_pin.update(transients.buffer, off, data.admin_pin_length);
             JCSystem.commitTransaction();
             data.admin_pin.resetAndUnblock();
@@ -751,7 +753,7 @@ public final class SmartPGPApplet extends Applet implements ExtendedLength {
         sensitiveData();
 
         byte off = 0;
-        byte minlen;
+        short minlen;
 
         if(p2 != (byte)0x81) {
             ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
@@ -777,7 +779,7 @@ public final class SmartPGPApplet extends Applet implements ExtendedLength {
                 ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
                 return;
             }
-            minlen = (byte)(lc - off);
+            minlen = (short)(lc - off);
             if(data.keyDerivationIsActive()) {
                 if(data.keyDerivationSize() != minlen) {
                     ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
@@ -791,7 +793,7 @@ public final class SmartPGPApplet extends Applet implements ExtendedLength {
                 }
             }
             JCSystem.beginTransaction();
-            data.user_pin_length = minlen;
+            data.user_pin_length = (byte)minlen;
             data.user_pin.update(transients.buffer, off, data.user_pin_length);
             JCSystem.commitTransaction();
             data.user_pin.resetAndUnblock();
@@ -1217,12 +1219,25 @@ public final class SmartPGPApplet extends Applet implements ExtendedLength {
                     ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
                     return;
                 }
+                /* Reject DOs that would leave keyDerivationIsActive()
+                 * true while keyDerivationSize() returns 0: an active
+                 * KDF-DO (len>=3, tag 0x81, [2]!=0) needs len>=6 with a
+                 * supported hash id at [5]; anything else makes every
+                 * PIN verification fail until factory reset. */
+                if((lc >= 3) &&
+                   (buf[0] == (byte)0x81) &&
+                   (buf[2] != (byte)0) &&
+                   ((lc < 6) ||
+                    ((buf[5] != (byte)0x08) && (buf[5] != (byte)0x0A)))) {
+                    ISOException.throwIt(ISO7816.SW_WRONG_DATA);
+                    return;
+                }
                 JCSystem.beginTransaction();
                 if(data.key_derivation_function_length > 0) {
                     Util.arrayFillNonAtomic(data.key_derivation_function, (short)0, data.key_derivation_function_length, (byte)0);
                 }
                 Util.arrayCopyNonAtomic(buf, (short)0, data.key_derivation_function, (short)0, lc);
-                data.key_derivation_function_length = (byte)lc;
+                data.key_derivation_function_length = lc;
                 JCSystem.commitTransaction();
                 break;
 
@@ -1372,6 +1387,12 @@ public final class SmartPGPApplet extends Applet implements ExtendedLength {
                     return 0;
                 }
 
+                /* The plaintext is written at buf[lc]: make sure it fits */
+                if((short)((short)(2 * lc) - 1) > Constants.INTERNAL_BUFFER_MAX_LENGTH) {
+                    ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
+                    return 0;
+                }
+
                 if((data.aes_key == null) || !data.aes_key.isInitialized()) {
                     ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
                     return 0;
@@ -1403,6 +1424,12 @@ public final class SmartPGPApplet extends Applet implements ExtendedLength {
                 return 0;
             }
 
+            /* The ciphertext is written at buf[lc + 1]: make sure it fits */
+            if((short)((short)(2 * lc) + 1) > Constants.INTERNAL_BUFFER_MAX_LENGTH) {
+                ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
+                return 0;
+            }
+
             if((data.aes_key == null) || !data.aes_key.isInitialized()) {
                 ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
                 return 0;
@@ -1478,6 +1505,10 @@ public final class SmartPGPApplet extends Applet implements ExtendedLength {
             return;
         }
 
+        /* OpenPGP spec behaviour: when the admin PIN is blocked, allow
+         * TERMINATE DF without authentication so ACTIVATE FILE can restore
+         * the card. This is the intended recovery path (deliberate
+         * trade-off: anyone can wipe a card by blocking the admin PIN). */
         if(data.admin_pin.getTriesRemaining() <= 0) {
             data.isTerminated = true;
             return;
@@ -1582,40 +1613,40 @@ public final class SmartPGPApplet extends Applet implements ExtendedLength {
 
         } else {
 
-            prepareChainingInput(apdubuf);
-            receiveData(apdu);
+            try {
 
-            short lc = transients.chainingInputLength();
+                prepareChainingInput(apdubuf);
+                receiveData(apdu);
 
-            if((apdubuf[ISO7816.OFFSET_CLA] & Constants.CLA_MASK_SECURE_MESSAGING) == Constants.CLA_MASK_SECURE_MESSAGING) {
-                short off = lc;
+                short lc = transients.chainingInputLength();
 
-                if((short)(off + 1 + 1 + 1 + 1 + 3) > Constants.INTERNAL_BUFFER_MAX_LENGTH) {
-                    ISOException.throwIt(Constants.SW_MEMORY_FAILURE);
-                    return;
-                }
+                if((apdubuf[ISO7816.OFFSET_CLA] & Constants.CLA_MASK_SECURE_MESSAGING) == Constants.CLA_MASK_SECURE_MESSAGING) {
+                    short off = lc;
 
-                transients.buffer[off++] = apdubuf[ISO7816.OFFSET_CLA];
-                transients.buffer[off++] = apdubuf[ISO7816.OFFSET_INS];
-                transients.buffer[off++] = p1;
-                transients.buffer[off++] = p2;
-                if(lc > (short)0xff) {
-                    transients.buffer[off++] = (byte)0;
-                    transients.buffer[off++] = (byte)((lc >> 8) & (byte)0xff);
-                }
-                transients.buffer[off++] = (byte)(lc & (byte)0xff);
+                    if((short)(off + 1 + 1 + 1 + 1 + 3) > Constants.INTERNAL_BUFFER_MAX_LENGTH) {
+                        ISOException.throwIt(Constants.SW_MEMORY_FAILURE);
+                        return;
+                    }
 
-                transients.setChainingInputLength((short)0);
+                    transients.buffer[off++] = apdubuf[ISO7816.OFFSET_CLA];
+                    transients.buffer[off++] = apdubuf[ISO7816.OFFSET_INS];
+                    transients.buffer[off++] = p1;
+                    transients.buffer[off++] = p2;
+                    if(lc > (short)0xff) {
+                        transients.buffer[off++] = (byte)0;
+                        transients.buffer[off++] = (byte)((lc >> 8) & (byte)0xff);
+                    }
+                    transients.buffer[off++] = (byte)(lc & (byte)0xff);
 
-                lc = sm.verifyAndDecryptCommand(transients, lc, off);
+                    transients.setChainingInputLength((short)0);
 
-                transients.setSecureMessagingOk(true);
+                    lc = sm.verifyAndDecryptCommand(transients, lc, off);
 
-            } else if(sm.isSessionAvailable()) {
-                clearConnection();
-            }
+                    transients.setSecureMessagingOk(true);
 
-            try {
+                } else if(sm.isSessionAvailable()) {
+                    clearConnection();
+                }
 
                 switch(apdubuf[ISO7816.OFFSET_INS]) {
                 case Constants.INS_SELECT_DATA:
@@ -1681,6 +1712,15 @@ public final class SmartPGPApplet extends Applet implements ExtendedLength {
 
             } catch (ISOException e) {
                 sw = e.getReason();
+            } catch (RuntimeException e) {
+                /* Do not let unexpected runtime exceptions (CryptoException,
+                 * ArrayIndexOutOfBoundsException, ...) escape to the JCRE:
+                 * abort any open transaction and return a generic error. */
+                try {
+                    JCSystem.abortTransaction();
+                } catch (TransactionException ignored) {
+                }
+                sw = ISO7816.SW_UNKNOWN;
             }
 
             if(transients.secureMessagingOk()) {
```
## 3. 编译 CAP

```bash
export JC_HOME=/tmp/jcsdk/jc304_kit
export JAVA_HOME=/usr/lib/jvm/java-8-openjdk-amd64
ant
```

预期尾部输出：

```
[verify] Verification of .../fr/anssi/smartpgp/javacard/smartpgp.cap passed
[c] CAP saved to .../SmartPGPApplet.cap
BUILD SUCCESSFUL
```

`ant` 会自动下载 `ant-javacard.jar`（需联网）。产物 `SmartPGPApplet.cap` 即为待安装 applet。

---

## 4. 安装 applet 到卡片

> **注意**：安装会清除卡上所有数据（含旧密钥，无法恢复）。若卡上有需要的密钥请先确认备份。

卖家公开的 GP 默认传输密钥（TK 值，SCP02，**公开值，装完建议更换**）：

```
Kenc = bd4dc7cad88ae968fe5bc814d88d10a0
Kmac = a060b868d75e7afcacd4d9186d8509cc
Kdek = 562825306ede1b80b757a1e5ece54005
```

```bash
GPARGS='-r "ACS ACR1281U 00 01" --key-enc bd4dc7cad88ae968fe5bc814d88d10a0
        --key-mac a060b868d75e7afcacd4d9186d8509cc
        --key-dek 562825306ede1b80b757a1e5ece54005'

# 删除旧 applet 与包（ISD 的 --delete 对 AID 操作；-uninstall 只接受 cap 文件）
java -jar /tmp/gp.jar $GPARGS --delete D276000124010304AFAF000000000000
java -jar /tmp/gp.jar $GPARGS --delete D27600012401

# 安装
java -jar /tmp/gp.jar $GPARGS -install SmartPGPApplet.cap
# 预期输出: .../SmartPGPApplet.cap loaded: fr.anssi.smartpgp D27600012401
```

若读卡器名带空格导致 `Invalid non-option arguments`，把 `-r "ACS ACR1281U 00 01"` 直接写进每条命令（不要放变量里展开）。

**验证安装**（出厂默认：user PIN `123456`／admin PIN `12345678`，各 3 次机会）：

```bash
gpgconf --kill scdaemon && gpg --card-status
# 期望: Version 3.4 / Key attributes rsa2048 rsa2048 rsa2048
#       PIN retry counter 3 0 3 / 三个 key 指纹为空（尚未生成）
```

---

## 5. 本地生成密钥与自签证书

私钥在主机生成后导入卡片（这样本地可留存备份；卡上生成的私钥无法导出）。
**私钥内容不要出现在任何命令行输出/日志中**，全程静默写文件。

```bash
K=keys
mkdir -p $K && chmod 700 $K

# 备份密码（随机生成，只写入文件；请另行安全备份此文件！）
openssl rand -base64 32 > $K/BACKUP_PASSPHRASE.txt && chmod 400 $K/BACKUP_PASSPHRASE.txt

for role in sig dec aut; do
  case $role in
    sig) CN="SmartPGP Signature";      KU="digitalSignature,nonRepudiation";;
    dec) CN="SmartPGP Decryption";     KU="keyEncipherment,dataEncipherment";;
    aut) CN="SmartPGP Authentication"; KU="digitalSignature";;
  esac
  openssl genrsa -aes256 -passout file:$K/BACKUP_PASSPHRASE.txt \
      -out $K/$role.key.pem 2048 2>/dev/null
  openssl req -new -x509 -key $K/$role.key.pem -passin file:$K/BACKUP_PASSPHRASE.txt \
      -sha256 -days 3650 -subj "/CN=$CN" \
      -addext "basicConstraints=critical,CA:FALSE" \
      -addext "keyUsage=critical,$KU" \
      -out $K/$role.cert.pem 2>/dev/null
  openssl x509 -in $K/$role.cert.pem -outform DER -out $K/$role.cert.der
done
chmod 400 $K/*
ls -la $K        # 只看文件名/大小，不打印内容
```

自签证书 DER 应约 800～830 字节（卡片凭据上限 `0x480`=1152，见 `Constants.EXTENDED_CAPABILITIES`）。

---

## 6. 密钥导入卡片

### 6.1 APDU 结构（脚本实现依据）

| 数据对象 | APDU | 说明 |
|---|---|---|
| 私钥 | `00/10 DB 3F FF`＋`4D…` | CRT：`B6`(SIG)/`B8`(DEC)/`A4`(AUT)＋`7F48` 模板＋`5F48` 数据；RSA 分量 `91`e(3B)/`92`p/`93`q/`94`PQ/`95`DP1/`96`DQ1(各128B)/`97`n(256B)；>255B 用 CLA `10` 命令链接力 |
| 指纹 | `00 DA 00 C7/C8/C9` | 20 字节 OpenPGP v4 指纹（SHA-1） |
| 生成日期 | `00 DA 00 CE/CF/D0` | 4 字节 UTC 时间戳（取证书 notBefore） |
| 证书 | `00 A5 occ 04`＋`7F21` 选择 → `00/10 DA 7F 21` | occ：SIG=02、DEC=01、AUT=00 |

指纹算法：`SHA1(0x99 || len || 0x04 || created(4B) || 0x01 || MPI(n) || MPI(e))`。

### 6.2 导入脚本（完整代码，存为 `bin/import-local-keys.py`）

```python
#!/usr/bin/env python3
# SmartPGP : import locally generated RSA keys and certificates into the card.
# Reads key material from a local directory (never prints it) and imports:
#   - private keys (PUT DATA 3FFF, CRT format: e/p/q/PQ/DP1/DQ1/n)
#   - PGP v4 fingerprints and generation dates
#   - X.509 certificates (cardholder certificate DO 7F21)
#
# Usage: ./import-local-keys.py --keys ../keys [--reader 1] [--verify]
# PIN source: environment variable SMARTPGP_ADMIN_PIN, or the applet default.

import argparse
import hashlib
import os
import sys

from smartcard.System import readers
from cryptography import x509
from cryptography.hazmat.primitives import serialization

DEFAULT_ADMIN_PIN = "12345678"  # applet factory default (see Constants.java)

ROLES = {
    # role: (CRT tag for key import, fingerprint DO, generation date DO,
    #        SELECT DATA occurrence for certificate DO)
    'sig': (0xB6, 0x00C7, 0x00CE, 0x02),
    'dec': (0xB8, 0x00C8, 0x00CF, 0x01),
    'aut': (0xA4, 0x00C9, 0x00D0, 0x00),
}

SELECT_APPLET = [0x00, 0xA4, 0x04, 0x00, 0x06, 0xD2, 0x76, 0x00, 0x01, 0x24, 0x01, 0x00]
SELECT_DATA_CERT = [0x60, 0x04, 0x5C, 0x02, 0x7F, 0x21]


class CardError(Exception):
    pass


def transmit(conn, apdu, what):
    data, sw1, sw2 = conn.transmit(list(apdu))
    if (sw1, sw2) != (0x90, 0x00):
        raise CardError("%s failed: %02X %02X" % (what, sw1, sw2))
    return data


def get_data(conn, p1, p2):
    data, sw1, sw2 = conn.transmit([0x00, 0xCA, p1, p2, 0x00])
    while sw1 == 0x61:
        more, sw1, sw2 = conn.transmit([0x00, 0xC0, 0x00, 0x00, sw2])
        data = data + more
    if (sw1, sw2) != (0x90, 0x00):
        raise CardError("GET DATA %02X%02X failed: %02X %02X" % (p1, p2, sw1, sw2))
    return data


def put_data(conn, ins, p1, p2, data, what):
    """PUT DATA with command chaining (255-byte chunks)."""
    data = list(data)
    off = 0
    total = len(data)
    while off < total:
        chunk = data[off:off + 255]
        off += 255
        cla = 0x10 if off < total else 0x00
        apdu = [cla, ins, p1, p2, len(chunk)] + chunk
        transmit(conn, apdu, "%s (chunk)" % what)


def der_len(n):
    if n > 0xFF:
        return bytes([0x82, (n >> 8) & 0xFF, n & 0xFF])
    if n > 0x7F:
        return bytes([0x81, n & 0xFF])
    return bytes([n & 0xFF])


def pad_int(v, ln):
    return v.to_bytes((v.bit_length() + 7) // 8, 'big').rjust(ln, b'\x00')


def build_key_blob(priv, crt_tag):
    """OpenPGP key import DO (4D) with RSA CRT components."""
    pn = priv.private_numbers()
    n = pn.public_numbers.n
    e = pn.public_numbers.e
    e_b = pad_int(e, 3)      # attributes require a 17-bit (3-byte) exponent
    p = pad_int(pn.p, 128)
    q = pad_int(pn.q, 128)
    pq = pad_int(pn.iqmp, 128)    # 1/q mod p  -> setPQ
    dp1 = pad_int(pn.dmp1, 128)   # d mod (p-1) -> setDP1
    dq1 = pad_int(pn.dmq1, 128)   # d mod (q-1) -> setDQ1
    n_b = pad_int(n, 256)
    parts = [(0x91, e_b), (0x92, p), (0x93, q), (0x94, pq),
             (0x95, dp1), (0x96, dq1), (0x97, n_b)]
    tmpl = b''.join(bytes([t]) + der_len(len(v)) for t, v in parts)
    blob = b''.join(v for _, v in parts)
    body = (bytes([crt_tag, 0x00]) +
            b'\x7f\x48' + der_len(len(tmpl)) + tmpl +
            b'\x5f\x48' + der_len(len(blob)) + blob)
    return b'\x4d' + der_len(len(body)) + body


def pgp_fingerprint(n, e, created):
    """OpenPGP v4 fingerprint: SHA-1 over 0x99 || len || pubkey packet body."""
    def mpi(v):
        bl = v.bit_length()
        return bl.to_bytes(2, 'big') + v.to_bytes((bl + 7) // 8, 'big')
    body = (b'\x04' + int(created).to_bytes(4, 'big') + b'\x01' +
            mpi(n) + mpi(e))
    return hashlib.sha1(b'\x99' + len(body).to_bytes(2, 'big') + body).digest()


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--keys', required=True, help='directory with <role>.key.pem / <role>.cert.der')
    ap.add_argument('--reader', type=int, default=1, help='PC/SC reader index (default 1)')
    ap.add_argument('--verify', action='store_true', help='read certificates back and compare')
    args = ap.parse_args()

    kdir = args.keys
    passfile = os.path.join(kdir, 'BACKUP_PASSPHRASE.txt')
    with open(passfile, 'rb') as f:
        passphrase = f.read().strip()
    admin_pin = os.environ.get('SMARTPGP_ADMIN_PIN', DEFAULT_ADMIN_PIN).encode()

    conn = readers()[args.reader].createConnection()
    conn.connect()
    transmit(conn, SELECT_APPLET, 'SELECT applet')
    transmit(conn, [0x00, 0x20, 0x00, 0x83, len(admin_pin)] + list(admin_pin),
             'VERIFY admin PIN')
    print('Connected to reader %d, admin PIN verified.' % args.reader)

    manifest = ['# SmartPGP local key backup manifest (public information only)']

    for role, (crt_tag, fp_tag, date_tag, occ) in ROLES.items():
        with open(os.path.join(kdir, '%s.key.pem' % role), 'rb') as f:
            priv = serialization.load_pem_private_key(f.read(), password=passphrase)
        with open(os.path.join(kdir, '%s.cert.der' % role), 'rb') as f:
            cert_der = f.read()
        cert = x509.load_der_x509_certificate(cert_der)

        pn = priv.private_numbers()
        if pn.public_numbers.n.bit_length() != 2048 or pn.public_numbers.e != 65537:
            raise SystemExit('%s: key is not RSA-2048 with e=65537' % role)

        nb = getattr(cert, 'not_valid_before_utc', None) or cert.not_valid_before
        created = int(nb.timestamp())

        # 1. private key
        blob = build_key_blob(priv, crt_tag)
        put_data(conn, 0xDB, 0x3F, 0xFF, blob, 'import %s key' % role)

        # 2. fingerprint + generation date
        fp = pgp_fingerprint(pn.public_numbers.n, pn.public_numbers.e, created)
        put_data(conn, 0xDA, (fp_tag >> 8) & 0xFF, fp_tag & 0xFF, fp, '%s fingerprint' % role)
        put_data(conn, 0xDA, (date_tag >> 8) & 0xFF, date_tag & 0xFF,
                 int(created).to_bytes(4, 'big'), '%s generation date' % role)

        # 3. certificate
        transmit(conn, [0x00, 0xA5, occ, 0x04, len(SELECT_DATA_CERT)] + SELECT_DATA_CERT,
                 'SELECT DATA %s cert' % role)
        put_data(conn, 0xDA, 0x7F, 0x21, cert_der, '%s certificate' % role)

        fp_hex = fp.hex().upper()
        fp_pretty = ' '.join(fp_hex[i:i + 4] for i in range(0, 40, 4))
        cert_sha = hashlib.sha256(cert_der).hexdigest()
        print('%s: key+cert imported, %d bytes cert, fingerprint %s'
              % (role.upper(), len(cert_der), fp_pretty))

        manifest += [
            '',
            '[%s]' % role,
            'subject       : %s' % cert.subject.rfc4514_string(),
            'serial        : %s' % cert.serial_number,
            'validity       : %s .. %s' % (nb.isoformat(),
                                          (getattr(cert, 'not_valid_after_utc', None) or
                                           cert.not_valid_after).isoformat()),
            'cert sha256   : %s' % cert_sha,
            'pgp fingerprint: %s' % fp_hex,
        ]

        if args.verify:
            transmit(conn, [0x00, 0xA5, occ, 0x04, len(SELECT_DATA_CERT)] + SELECT_DATA_CERT,
                     'SELECT DATA %s cert' % role)
            oncard = bytes(get_data(conn, 0x7F, 0x21))
            status = 'OK' if oncard == cert_der else 'MISMATCH'
            print('    read-back certificate: %s (%d bytes, sha256 %s)'
                  % (status, len(oncard), hashlib.sha256(oncard).hexdigest()))

    mpath = os.path.join(kdir, 'MANIFEST.txt')
    if os.path.exists(mpath):
        os.chmod(mpath, 0o600)
    with open(mpath, 'w') as f:
        f.write('\n'.join(manifest) + '\n')
    os.chmod(mpath, 0o400)
    print('Manifest written to %s' % mpath)


if __name__ == '__main__':
    main()
```

### 6.3 执行导入

```bash
python3 bin/import-local-keys.py --keys keys --reader 1 --verify
```

预期输出（指纹为示例值，你的会不同）：

```
Connected to reader 1, admin PIN verified.
SIG: key+cert imported, 812 bytes cert, fingerprint 9B0E 1D9C ...
    read-back certificate: OK (812 bytes, sha256 ...)
DEC: key+cert imported, 814 bytes cert, fingerprint D32C E8D3 ...
    read-back certificate: OK (814 bytes, sha256 ...)
AUT: key+cert imported, 822 bytes cert, fingerprint 18C8 76C7 ...
    read-back certificate: OK (822 bytes, sha256 ...)
Manifest written to keys/MANIFEST.txt
```

`read-back ... OK` 表示从卡片读回的证书与本地文件逐字节一致。
`keys/MANIFEST.txt` 记录公开信息（指纹、证书哈希、效期），不含秘密。

---

## 7. 验证

```bash
gpgconf --kill scdaemon && gpg --card-status
```

期望（示例值）：

```
Application ID ...: D276000124010304AFAF000000000000
Version ..........: 3.4
Key attributes ...: rsa2048 rsa2048 rsa2048
PIN retry counter : 3 0 3
Signature key ....: 9B0E 1D9C A696 5D96 BDFE  F4A3 3ED0 67A5 A400 FC26
      created ....: 2026-10-16 17:53:20
Encryption key....: D32C E8D3 8E00 AFEF D0D7  F71C F146 ED31 E566 508C
Authentication key: 18C8 76C7 0A2D EE93 FFCE  6887 2E36 56FB 381D FF61
```

三个指纹应与 6.3 输出一致；`General key info [none]` 属正常（公钥未进本机 keyring）。

---

## 8. 恢复出厂救援通道实测（⚠️ 会清卡，测完需重跑第 6 节）

验证规格行为：**admin PIN 锁死 → 免认证 TERMINATE DF → ACTIVATE FILE 恢复出厂**。
以下脚本存为 `recovery-test.py` 执行（Python＋pyscard，勿用 opensc-tool，见 10 节）：

```python
#!/usr/bin/env python3
# SmartPGP 恢复出厂救援通道验证（会清除卡片数据！）
from smartcard.System import readers

conn = readers()[1].createConnection()
conn.connect()

def t(apdu, what):
    d, s1, s2 = conn.transmit(apdu)
    print("%-42s -> %02X %02X" % (what, s1, s2))
    return s1, s2

SELECT = [0x00, 0xA4, 0x04, 0x00, 0x06, 0xD2, 0x76, 0x00, 0x01, 0x24, 0x01, 0x00]
t(SELECT, "SELECT")
t([0x00, 0xE6, 0x00, 0x00], "(1) 未锁 PIN 时免认证 TERMINATE（应拒 6982）")

print("--- 故意锁死 admin PIN ---")
for i in range(3):
    t([0x00, 0x20, 0x00, 0x83, 0x08] + list(b"00000000"), "   错误 PIN #%d" % (i + 1))

s1, s2 = t([0x00, 0xE6, 0x00, 0x00], "(2) 锁死后免认证 TERMINATE（应 9000）")
assert (s1, s2) == (0x90, 0x00), "TERMINATE 失败！"
t(SELECT, "(3) SELECT（应 6285 已终止）")
t([0x00, 0x44, 0x00, 0x00], "(4) ACTIVATE FILE（应 9000）")
t(SELECT, "(5) SELECT（应恢复 9000）")
d, s1, s2 = conn.transmit([0x00, 0xCA, 0x00, 0xC4, 0x07])
print("%-42s -> %02X %02X  %s" % ("(6) PIN 计数（应回 3 0 3）", s1, s2, bytes(d).hex()))
print("\n*** 恢复出厂救援通道验证成功 ***")
```

预期输出：

```
SELECT                                     -> 90 00
(1) 未锁 PIN 时免认证 TERMINATE（应拒 6982）      -> 69 82
--- 故意锁死 admin PIN ---
   错误 PIN #1                              -> 69 82
   错误 PIN #2                              -> 69 82
   错误 PIN #3                              -> 69 82
(2) 锁死后免认证 TERMINATE（应 9000）            -> 90 00
(3) SELECT（应 6285 已终止）                    -> 62 85
(4) ACTIVATE FILE（应 9000）                  -> 90 00
(5) SELECT（应恢复 9000）                      -> 90 00
(6) PIN 计数（应回 3 0 3）                     -> 90 00  007f7f7f030003
```

> `007f7f7f030003` = PIN/PUK 最大长度 127/127/127 ＋ 重试计数 3/0/3（出厂默认）。
> 测试清卡后重跑 6.3 即可恢复密钥（指纹不变，实测已验证备份→还原闭环）。

---


## 9. 安全须知

1. **PIN 重试次数：user / admin / PUK 各 3 次**（`Constants.java:36/50/46`）。
   输错递减（回应 `63Cx`，x=剩余次数），验证成功才回满；重新选卡不会重置。
2. **PIN 遗忘的后果**：
   - user PIN 锁死 → 用 admin PIN 解锁（`RESET RETRY COUNTER` P1=02）；
     建议再设 PUK 留后路：`./bin/smartpgp-cli -r 1 -p 12345678 set-resetting-code`
   - admin PIN 锁死 → 走第 8 节救援通道恢复出厂（**密钥会被销毁**）；
     若不想保留此通道，删除 `processTerminateDf` 中 `getTriesRemaining() <= 0`
     的代码块重新编译（即上游 `patches/remove_factory_reset.patch` 的效果）。
3. **出厂默认 PIN 请尽快更换**（`123456` / `12345678` 是公开值）：
   `CHANGE REFERENCE DATA`（INS 24）或 smartpgp-cli。
4. **GP TK 密钥是卖家公开默认值**，任何人可管理同款卡片，建议用
   `gp ... -lock` 轮换并妥善保存新密钥。
5. **备份**：`keys/BACKUP_PASSPHRASE.txt` 必须与密钥分开保存（如密码管理器）；
   私钥加密（AES-256）＋文件权限 400/700；`keys/` 已加入 `.gitignore` 防误提交。
6. 私钥只在「主机文件 ↔ 卡片」间流动，**不要让其进入命令行参数、日志或聊天窗口**。

---

## 10. 故障排查

| 症状 | 原因与解决 |
|---|---|
| `opensc-tool` 对卡片回 `6D00`/`6A86` 等怪码，但 pyscard/gpg 正常 | 卡片被 OpenSC 识别为 PIV，driver 在背后干扰会话。**改用 pyscard 或本文脚本**，勿用 opensc-tool 的结果做判断 |
| `gpg --card-status` 报「没有可用的 OpenPGP 卡片 / 不良的个人识别码 / 一般错误」 | scdaemon 持卡状态过期或与其他工具抢读卡器：`gpgconf --kill scdaemon` 后重试；避免 gpg 与脚本同时操作卡片 |
| ant 报 `Can't use JDK 17 with JavaCard kit 3.0.4 (use JDK 11)` | 换 JDK 8/11：`JAVA_HOME=/usr/lib/jvm/java-8-openjdk-amd64` |
| ant 报 `JDK 17 is the latest supported JDK` | JDK 版本 >17，换 8/11 |
| gp 报 `Invalid argument: Could not read CAP: <AID>` | 删除 AID 要用 `--delete <AID>`；`-uninstall` 只收 cap 文件 |
| gp 报 `Invalid non-option arguments: ACR1281U 00 01` | 读卡器名含空格时不要放进 shell 变量，直接写在命令里 |
| 密钥导入回 `6A88`（Reference data not found） | INS 用错了：密钥是 `0xDB`（odd PUT DATA），指纹/日期/证书才是 `0xDA` |
| 脚本报 `PermissionError: MANIFEST.txt` | 旧 MANIFEST 权限 400 不可覆写，新版脚本已自动 `chmod 600` |
| 证书导入后读回 `MISMATCH` | 证书超过 1152 字节或未先 `SELECT DATA` 选择 occurrence；核对 DER 大小 |
| 安装后 gpg 显示指纹为空 | 属正常（尚未生成/导入密钥），完成第 5–6 节后出现 |

---

## 附：流程速查（TL;DR）

```bash
# ① 修复＋编译
git checkout 2a06700 && git apply repro.patch
export JC_HOME=/tmp/jcsdk/jc304_kit JAVA_HOME=/usr/lib/jvm/java-8-openjdk-amd64
ant

# ② 安装（清除旧数据）
java -jar /tmp/gp.jar -r "ACS ACR1281U 00 01" --key-enc bd4dc7cad88ae968fe5bc814d88d10a0 \
  --key-mac a060b868d75e7afcacd4d9186d8509cc --key-dek 562825306ede1b80b757a1e5ece54005 \
  --delete D276000124010304AFAF000000000000
java -jar /tmp/gp.jar -r "ACS ACR1281U 00 01" --key-enc bd4dc7cad88ae968fe5bc814d88d10a0 \
  --key-mac a060b868d75e7afcacd4d9186d8509cc --key-dek 562825306ede1b80b757a1e5ece54005 \
  --delete D27600012401
java -jar /tmp/gp.jar -r "ACS ACR1281U 00 01" --key-enc bd4dc7cad88ae968fe5bc814d88d10a0 \
  --key-mac a060b868d75e7afcacd4d9186d8509cc --key-dek 562825306ede1b80b757a1e5ece54005 \
  -install SmartPGPApplet.cap

# ③ 生成密钥/证书（第 5 节）→ ④ 导入
python3 bin/import-local-keys.py --keys keys --reader 1 --verify

# ⑤ 验证
gpgconf --kill scdaemon && gpg --card-status
```

> **交付物即本文档一个文件**：内含补丁 diff、导入脚本、恢复出厂测试脚本，
> 配合上游仓库即可完整复现本会话的全部结果。
