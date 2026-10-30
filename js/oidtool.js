// ============================================================
// OID 查询页（page-oid）—— PKI / 密码常用 OID 内置库
// 功能：
//   1) 查询：点分 OID（精确命中信息卡 / 未命中给顶层分支提示）、
//      DER Hex（自动识别并剥离 06 LL 长度头后解码）、名称关键字（库内模糊搜索）
//   2) 互转：点分 OID ↔ DER Hex（base-128 自实现，双向一致：
//      oidDotToHex(oidHexToDot(x)) 规范化后恒等于 x）
//   3) 内置库浏览表：分类单选 + 搜索框实时过滤，点击行回填查询
// 依赖（须先于本文件加载）：js/app.js → showNotification /
//   copyTextToClipboard（onclick 运行时均已可用）
// 数据口径：只收录有把握的标准 OID（国密 GM/T、RSA/PKCS、ECC/NIST、
//   X.509/DN、EKU/AIA），一条不编造；未收录 OID 查询时按已知顶层分支给提示
// ============================================================

// ---------- 内置 OID 库 ----------
// 每条 { oid, name, nameEn, cat, source, desc }：
//   oid 点分串 / name 中文名 / nameEn 英文标识 / cat 分类 /
//   source 出处标准 / desc 简要说明
var OID_DB = [
    // ---- 国密（1.2.156.10197 分支，GM/T 0006-2012 密码应用标识规范）----
    { oid: '1.2.156.10197', name: '中国商用密码算法分支', nameEn: 'SM Cryptography Algorithms', cat: '国密', source: 'GM/T 0006-2012（密码应用标识规范）', desc: '1.2.156.10197 为中国商用密码国家主管机关分配的密码算法 OID 分支，SM2/SM3/SM4 等算法标识均定义于其下' },
    { oid: '1.2.156.10197.1.301', name: 'SM2 椭圆曲线', nameEn: 'SM2 Elliptic Curve', cat: '国密', source: 'GM/T 0006-2012（密码应用标识规范）', desc: 'SM2 椭圆曲线公钥密码算法推荐 256 位曲线参数（GM/T 0003-2012 / GB/T 32918.5-2016）' },
    { oid: '1.2.156.10197.1.301.1', name: 'SM2-1 数字签名算法', nameEn: 'SM2-1 Digital Signature', cat: '国密', source: 'GM/T 0006-2012（密码应用标识规范）', desc: 'SM2 数字签名算法（GM/T 0003.2-2012 / GB/T 32918.2-2016）' },
    { oid: '1.2.156.10197.1.301.2', name: 'SM2-2 密钥交换协议', nameEn: 'SM2-2 Key Exchange', cat: '国密', source: 'GM/T 0006-2012（密码应用标识规范）', desc: 'SM2 密钥交换协议（GM/T 0003.3-2012 / GB/T 32918.3-2016）' },
    { oid: '1.2.156.10197.1.301.3', name: 'SM2-3 公钥加密算法', nameEn: 'SM2-3 Public Key Encryption', cat: '国密', source: 'GM/T 0006-2012（密码应用标识规范）', desc: 'SM2 公钥加密（加密/解密）算法（GM/T 0003.4-2012 / GB/T 32918.4-2016）' },
    { oid: '1.2.156.10197.1.104', name: 'SM4 分组密码算法', nameEn: 'SM4 Block Cipher', cat: '国密', source: 'GM/T 0006-2012（密码应用标识规范）', desc: 'SM4 分组密码算法，分组与密钥均为 128 位（GM/T 0002-2012 / GB/T 32907-2016）' },
    { oid: '1.2.156.10197.1.401', name: 'SM3 密码杂凑算法', nameEn: 'SM3 Hash', cat: '国密', source: 'GM/T 0006-2012（密码应用标识规范）', desc: 'SM3 密码杂凑算法，输出 256 位（GM/T 0004-2012 / GB/T 32905-2016）' },
    { oid: '1.2.156.10197.1.501', name: 'SM2 数字签名算法（with SM3）', nameEn: 'SM3withSM2', cat: '国密', source: 'GM/T 0006-2012（密码应用标识规范）', desc: 'SM2 签名 + SM3 摘要的组合签名标识，用于 SM2 证书 signature 算法字段（GM/T 0009-2012 SM2 密码算法使用规范）' },
    // ---- RSA 与 PKCS（1.2.840.113549 RSADSI 分支）----
    { oid: '1.2.840.113549.1.1.1', name: 'rsaEncryption', nameEn: 'rsaEncryption', cat: 'RSA与PKCS', source: 'PKCS#1 / RFC 8017', desc: 'RSA 公钥算法标识，证书 / PKCS#8 公钥的 algorithm 字段' },
    { oid: '1.2.840.113549.1.1.4', name: 'md5WithRSAEncryption', nameEn: 'md5WithRSAEncryption', cat: 'RSA与PKCS', source: 'RFC 3279', desc: 'MD5 摘要 + RSA（PKCS#1 v1.5）签名算法（已不推荐）' },
    { oid: '1.2.840.113549.1.1.5', name: 'sha1WithRSAEncryption', nameEn: 'sha1WithRSAEncryption', cat: 'RSA与PKCS', source: 'RFC 3279', desc: 'SHA-1 摘要 + RSA（PKCS#1 v1.5）签名算法（已不推荐）' },
    { oid: '1.2.840.113549.1.1.10', name: 'RSASSA-PSS', nameEn: 'RSASSA-PSS', cat: 'RSA与PKCS', source: 'RFC 4055', desc: 'RSASSA-PSS 概率签名方案（配合 SHA-2 与 MGF1 参数使用）' },
    { oid: '1.2.840.113549.1.1.11', name: 'sha256WithRSAEncryption', nameEn: 'sha256WithRSAEncryption', cat: 'RSA与PKCS', source: 'RFC 4055', desc: 'SHA-256 + RSA（PKCS#1 v1.5）签名，当前最常用的 RSA 签名算法' },
    { oid: '1.2.840.113549.1.1.12', name: 'sha384WithRSAEncryption', nameEn: 'sha384WithRSAEncryption', cat: 'RSA与PKCS', source: 'RFC 4055', desc: 'SHA-384 + RSA（PKCS#1 v1.5）签名算法' },
    { oid: '1.2.840.113549.1.1.13', name: 'sha512WithRSAEncryption', nameEn: 'sha512WithRSAEncryption', cat: 'RSA与PKCS', source: 'RFC 4055', desc: 'SHA-512 + RSA（PKCS#1 v1.5）签名算法' },
    { oid: '1.2.840.113549.1.1.14', name: 'sha224WithRSAEncryption', nameEn: 'sha224WithRSAEncryption', cat: 'RSA与PKCS', source: 'RFC 4055', desc: 'SHA-224 + RSA（PKCS#1 v1.5）签名算法' },
    { oid: '1.2.840.113549.2.5', name: 'md5', nameEn: 'md5', cat: 'RSA与PKCS', source: 'RFC 1321', desc: 'MD5 消息摘要算法，PKCS 系列沿用的摘要标识（RFC 1321 沿革）' },
    { oid: '1.2.840.113549.2.9', name: 'hmacWithSHA256', nameEn: 'hmacWithSHA256', cat: 'RSA与PKCS', source: 'RFC 4231', desc: '以 SHA-256 为底层杂凑的 HMAC 算法标识' },
    { oid: '1.2.840.113549.1.7.1', name: 'pkcs7-data', nameEn: 'id-data', cat: 'RSA与PKCS', source: 'RFC 5652', desc: 'PKCS#7/CMS ContentInfo 的 data 内容类型' },
    { oid: '1.2.840.113549.1.7.2', name: 'pkcs7-signedData', nameEn: 'id-signedData', cat: 'RSA与PKCS', source: 'RFC 5652', desc: '签名数据：携带签名与证书的常用 PKCS#7/CMS 类型' },
    { oid: '1.2.840.113549.1.7.3', name: 'pkcs7-envelopedData', nameEn: 'id-envelopedData', cat: 'RSA与PKCS', source: 'RFC 5652', desc: '数字信封：内容密钥用接收方公钥加密包裹' },
    { oid: '1.2.840.113549.1.7.6', name: 'pkcs7-encryptedData', nameEn: 'id-encryptedData', cat: 'RSA与PKCS', source: 'RFC 5652', desc: '加密数据：仅对称加密的内容，不含接收方公钥信息' },
    { oid: '1.2.840.113549.1.9.1', name: 'emailAddress', nameEn: 'emailAddress', cat: 'RSA与PKCS', source: 'RFC 5280', desc: 'PKCS#9 定义的 DN 邮箱属性（IA5String，RFC 5280 DN 属性）' },
    { oid: '1.2.840.113549.1.9.3', name: 'contentType', nameEn: 'contentType', cat: 'RSA与PKCS', source: 'RFC 5652', desc: 'PKCS#9 签名属性：被签名内容的类型' },
    { oid: '1.2.840.113549.1.9.4', name: 'messageDigest', nameEn: 'messageDigest', cat: 'RSA与PKCS', source: 'RFC 5652', desc: 'PKCS#9 签名属性：被签名内容的摘要值' },
    { oid: '1.2.840.113549.1.9.5', name: 'signingTime', nameEn: 'signingTime', cat: 'RSA与PKCS', source: 'RFC 5652', desc: 'PKCS#9 签名属性：签名时间' },
    // ---- ECC 与 NIST（SEC / NIST 算法分支）----
    { oid: '1.2.840.10045.2.1', name: 'id-ecPublicKey', nameEn: 'id-ecPublicKey', cat: 'ECC与NIST', source: 'RFC 5480', desc: 'ECC 公钥算法标识（X9.62），证书 SubjectPublicKeyInfo 的 algorithm 字段' },
    { oid: '1.2.840.10045.3.1.7', name: 'prime256v1（P-256）', nameEn: 'prime256v1 (P-256)', cat: 'ECC与NIST', source: 'SECG SEC 2', desc: 'NIST P-256 曲线（secp256r1），TLS / 证书中最常用的 ECC 曲线' },
    { oid: '1.2.840.10045.4.1', name: 'ecdsa-with-SHA1', nameEn: 'ecdsa-with-SHA1', cat: 'ECC与NIST', source: 'RFC 3279', desc: 'ECDSA with SHA-1 签名算法（已不推荐）' },
    { oid: '1.2.840.10045.4.3.2', name: 'ecdsa-with-SHA256', nameEn: 'ecdsa-with-SHA256', cat: 'ECC与NIST', source: 'RFC 5758', desc: 'ECDSA with SHA-256 签名算法' },
    { oid: '1.2.840.10045.4.3.3', name: 'ecdsa-with-SHA384', nameEn: 'ecdsa-with-SHA384', cat: 'ECC与NIST', source: 'RFC 5758', desc: 'ECDSA with SHA-384 签名算法' },
    { oid: '1.2.840.10045.4.3.4', name: 'ecdsa-with-SHA512', nameEn: 'ecdsa-with-SHA512', cat: 'ECC与NIST', source: 'RFC 5758', desc: 'ECDSA with SHA-512 签名算法' },
    { oid: '1.3.132.0.34', name: 'secp384r1（P-384）', nameEn: 'secp384r1 (P-384)', cat: 'ECC与NIST', source: 'SECG SEC 2', desc: 'NIST P-384 曲线' },
    { oid: '1.3.132.0.35', name: 'secp521r1（P-521）', nameEn: 'secp521r1 (P-521)', cat: 'ECC与NIST', source: 'SECG SEC 2', desc: 'NIST P-521 曲线' },
    // SHA-2 族（nistAlgorithm hashalgs）：2.1=SHA-256、2.2=SHA-384、2.3=SHA-512、2.4=SHA-224
    { oid: '2.16.840.1.101.3.4.2.1', name: 'SHA-256', nameEn: 'SHA-256', cat: 'ECC与NIST', source: 'NIST FIPS 180-4 / RFC 5754', desc: 'NIST SHA-256 杂凑算法（nistAlgorithm hashalgs 第 1 项）' },
    { oid: '2.16.840.1.101.3.4.2.2', name: 'SHA-384', nameEn: 'SHA-384', cat: 'ECC与NIST', source: 'NIST FIPS 180-4 / RFC 5754', desc: 'NIST SHA-384 杂凑算法（nistAlgorithm hashalgs 第 2 项）' },
    { oid: '2.16.840.1.101.3.4.2.3', name: 'SHA-512', nameEn: 'SHA-512', cat: 'ECC与NIST', source: 'NIST FIPS 180-4 / RFC 5754', desc: 'NIST SHA-512 杂凑算法（nistAlgorithm hashalgs 第 3 项）' },
    { oid: '2.16.840.1.101.3.4.2.4', name: 'SHA-224', nameEn: 'SHA-224', cat: 'ECC与NIST', source: 'NIST FIPS 180-4 / RFC 5754', desc: 'NIST SHA-224 杂凑算法（nistAlgorithm hashalgs 第 4 项）' },
    // AES 族（nistAlgorithm aes）：.2=aes128-CBC、.42=aes256-CBC、.46=aes256-GCM
    { oid: '2.16.840.1.101.3.4.1.2', name: 'id-aes128-CBC', nameEn: 'id-aes128-CBC', cat: 'ECC与NIST', source: 'NIST SP 800-38A / RFC 3565', desc: 'AES-128-CBC 加密算法（nistAlgorithm aes 分支）' },
    { oid: '2.16.840.1.101.3.4.1.42', name: 'id-aes256-CBC', nameEn: 'id-aes256-CBC', cat: 'ECC与NIST', source: 'NIST SP 800-38A / RFC 3565', desc: 'AES-256-CBC 加密算法（注意：aes 分支 .42 是 256 位 CBC；aes128-GCM 为 .6）' },
    { oid: '2.16.840.1.101.3.4.1.46', name: 'id-aes256-GCM', nameEn: 'id-aes256-GCM', cat: 'ECC与NIST', source: 'NIST SP 800-38D / RFC 5084', desc: 'AES-256-GCM 认证加密算法' },
    // ---- X.509 与 DN（2.5 X.500 目录属性 / 2.5.29 证书扩展）----
    { oid: '2.5.4.3', name: 'CN (Common Name)', nameEn: 'commonName', cat: 'X.509与DN', source: 'ITU-T X.509 / RFC 5280', desc: '主题通用名称（X.520 属性），HTTPS 证书中通常填域名' },
    { oid: '2.5.4.4', name: 'SN (Surname)', nameEn: 'surname', cat: 'X.509与DN', source: 'ITU-T X.509 / RFC 5280', desc: '姓氏（X.520 属性）' },
    { oid: '2.5.4.5', name: 'serialNumber', nameEn: 'serialNumber', cat: 'X.509与DN', source: 'ITU-T X.509 / RFC 5280', desc: '主体序列号属性（设备序列号等常用）' },
    { oid: '2.5.4.6', name: 'C (Country)', nameEn: 'countryName', cat: 'X.509与DN', source: 'ITU-T X.509 / RFC 5280', desc: '国家代码（两位 ISO 3166-1 字母）' },
    { oid: '2.5.4.7', name: 'L (Locality)', nameEn: 'localityName', cat: 'X.509与DN', source: 'ITU-T X.509 / RFC 5280', desc: '城市 / 地区名（X.520 属性）' },
    { oid: '2.5.4.8', name: 'ST (State)', nameEn: 'stateOrProvinceName', cat: 'X.509与DN', source: 'ITU-T X.509 / RFC 5280', desc: '州 / 省份名（X.520 属性）' },
    { oid: '2.5.4.10', name: 'O (Organization)', nameEn: 'organizationName', cat: 'X.509与DN', source: 'ITU-T X.509 / RFC 5280', desc: '组织 / 机构名称（X.520 属性）' },
    { oid: '2.5.4.11', name: 'OU (Organizational Unit)', nameEn: 'organizationalUnitName', cat: 'X.509与DN', source: 'ITU-T X.509 / RFC 5280', desc: '组织部门名称（X.520 属性）' },
    { oid: '2.5.29.14', name: 'subjectKeyIdentifier', nameEn: 'subjectKeyIdentifier', cat: 'X.509与DN', source: 'ITU-T X.509 / RFC 5280', desc: '主体公钥标识（SKI）扩展，证书链构建与吊销匹配用' },
    { oid: '2.5.29.15', name: 'keyUsage', nameEn: 'keyUsage', cat: 'X.509与DN', source: 'ITU-T X.509 / RFC 5280', desc: '密钥用法位串扩展（digitalSignature / keyEncipherment / keyCertSign 等）' },
    { oid: '2.5.29.17', name: 'subjectAltName', nameEn: 'subjectAltName', cat: 'X.509与DN', source: 'ITU-T X.509 / RFC 5280', desc: '主体备用名扩展（DNS / IP / URI / email 等多形态名称）' },
    { oid: '2.5.29.19', name: 'basicConstraints', nameEn: 'basicConstraints', cat: 'X.509与DN', source: 'ITU-T X.509 / RFC 5280', desc: '基本约束扩展（CA 标志与签发路径深度限制）' },
    { oid: '2.5.29.31', name: 'cRLDistributionPoints', nameEn: 'cRLDistributionPoints', cat: 'X.509与DN', source: 'ITU-T X.509 / RFC 5280', desc: 'CRL 分发点扩展（吊销列表下载地址）' },
    { oid: '2.5.29.32', name: 'certificatePolicies', nameEn: 'certificatePolicies', cat: 'X.509与DN', source: 'ITU-T X.509 / RFC 5280', desc: '证书策略扩展（策略 OID 列表）' },
    { oid: '2.5.29.35', name: 'authorityKeyIdentifier', nameEn: 'authorityKeyIdentifier', cat: 'X.509与DN', source: 'ITU-T X.509 / RFC 5280', desc: '颁发者公钥标识（AKI）扩展，与签发者证书的 SKI 匹配' },
    { oid: '2.5.29.37', name: 'extKeyUsage', nameEn: 'extKeyUsage', cat: 'X.509与DN', source: 'ITU-T X.509 / RFC 5280', desc: '扩展密钥用法（EKU）扩展，取值见 EKU 与 AIA 分类' },
    // ---- EKU 与 AIA（PKIX id-kp / id-pe / id-ad 分支）----
    { oid: '2.5.29.37.0', name: 'anyExtendedKeyUsage', nameEn: 'anyExtendedKeyUsage', cat: 'EKU与AIA', source: 'RFC 5280', desc: '任意扩展密钥用法（仅可出现在 EKU 扩展自身中）' },
    { oid: '1.3.6.1.5.5.7.3.1', name: 'serverAuth (TLS 服务端认证)', nameEn: 'id-kp-serverAuth', cat: 'EKU与AIA', source: 'RFC 5280', desc: 'TLS 服务端证书用途' },
    { oid: '1.3.6.1.5.5.7.3.2', name: 'clientAuth (TLS 客户端认证)', nameEn: 'id-kp-clientAuth', cat: 'EKU与AIA', source: 'RFC 5280', desc: 'TLS 客户端证书用途（双向认证）' },
    { oid: '1.3.6.1.5.5.7.3.3', name: 'codeSigning', nameEn: 'id-kp-codeSigning', cat: 'EKU与AIA', source: 'RFC 5280', desc: '代码签名用途' },
    { oid: '1.3.6.1.5.5.7.3.4', name: 'emailProtection', nameEn: 'id-kp-emailProtection', cat: 'EKU与AIA', source: 'RFC 5280', desc: '邮件保护用途（S/MIME）' },
    { oid: '1.3.6.1.5.5.7.3.8', name: 'timeStamping', nameEn: 'id-kp-timeStamping', cat: 'EKU与AIA', source: 'RFC 5280', desc: '时间戳服务签名用途' },
    { oid: '1.3.6.1.5.5.7.3.9', name: 'OCSPSigning', nameEn: 'id-kp-OCSPSigning', cat: 'EKU与AIA', source: 'RFC 5280', desc: 'OCSP 响应签名用途' },
    { oid: '1.3.6.1.5.5.7.1.1', name: 'authorityInfoAccess (AIA)', nameEn: 'id-pe-authorityInfoAccess', cat: 'EKU与AIA', source: 'RFC 5280', desc: '颁发者信息访问扩展：携带 OCSP / caIssuers 访问方式与地址' },
    { oid: '1.3.6.1.5.5.7.48.1', name: 'OCSP', nameEn: 'id-ad-ocsp', cat: 'EKU与AIA', source: 'RFC 6960', desc: 'AIA AccessDescription 中的 OCSP 查询地址' },
    { oid: '1.3.6.1.5.5.7.48.2', name: 'caIssuers', nameEn: 'id-ad-caIssuers', cat: 'EKU与AIA', source: 'RFC 5280', desc: 'AIA AccessDescription 中的签发证书下载地址' }
];

// 顶层分支提示表：库中未收录的 OID 按最长前缀匹配给出归属提示
var OID_BRANCHES = [
    { prefix: '1.2.156.10197', tip: '国密分支（GM/T 0006）' },
    { prefix: '1.2.840.113549', tip: 'RSA/PKCS（RSADSI）' },
    { prefix: '1.2.840.10045', tip: 'SEC ECC' },
    { prefix: '2.5', tip: 'X.500 目录（ITU-T）' },
    { prefix: '1.3.6.1', tip: 'OID.INTERNET（IANA）' }
];

// ---------- 纯转换函数（不触碰 DOM，Node 可直接打桩测试） ----------

// HTML 转义（结果卡 innerHTML 渲染前统一过一遍，防用户输入注入）
function oidEsc(s) {
    return String(s == null ? '' : s)
        .replace(/&/g, '&amp;').replace(/</g, '&lt;')
        .replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

// Hex 字符串清洗：去掉全部空白（支持空格 / 换行分隔的 Hex）
function oidCleanHex(s) {
    return String(s == null ? '' : s).replace(/\s+/g, '');
}

// 紧凑 Hex 串 → 字节数组；含非法字符或长度为奇数抛中文错误
function oidHexToBytes(hex) {
    var s = oidCleanHex(hex);
    if (s === '') {
        throw new Error('Hex 输入为空');
    }
    if (!/^[0-9a-fA-F]+$/.test(s)) {
        throw new Error('不是合法的 Hex 字符串（含非十六进制字符）');
    }
    if (s.length % 2 !== 0) {
        throw new Error('Hex 长度为奇数，应每两个字符表示一个字节');
    }
    var out = new Array(s.length / 2);
    for (var i = 0; i < s.length; i += 2) {
        out[i / 2] = parseInt(s.substr(i, 2), 16);
    }
    return out;
}

// 识别并剥离 OID 的 `06 LL` TLV 头：首字节为 0x06 且第二字节（短格式长度）
// 恰好等于剩余字节数时剥离；返回 { bytes, stripped }
function oidStripTlvHeader(bytes) {
    if (bytes.length >= 2 && bytes[0] === 0x06 && bytes[1] < 0x80 &&
        bytes[1] === bytes.length - 2) {
        return { bytes: bytes.slice(2), stripped: true };
    }
    return { bytes: bytes, stripped: false };
}

// 单个数值 → base-128 字节序列（≥128 时多字节 0x80 续位，末字节高位为 0）
function oidEncodeBase128(v) {
    if (v < 0 || Math.floor(v) !== v) {
        throw new Error('base-128 编码遇到非法数值');
    }
    var parts = [v % 128];
    v = Math.floor(v / 128);
    while (v > 0) {
        parts.unshift((v % 128) + 0x80);
        v = Math.floor(v / 128);
    }
    return parts;
}

// OID 内容字节 → 点分串：
//   先按 base-128 切出全部子标识符（首个子标识符可能是多字节，如 2.999），
//   再把首个子标识符按 40*a+b 拆成前两节点；
//   空输入 / 末尾截断在续位中 / 数值超出安全范围返回 null
function oidDecodeOidBytes(bytes) {
    if (!bytes || bytes.length === 0) {
        return null;
    }
    var subs = [];
    var val = 0;
    var pending = false; // 是否正处于多字节续位中
    for (var i = 0; i < bytes.length; i++) {
        val = val * 128 + (bytes[i] & 0x7F);
        if (val > 0xFFFFFFFFFFFF) {
            return null; // 数值超出安全范围
        }
        if (bytes[i] & 0x80) {
            pending = true;
        } else {
            subs.push(val);
            val = 0;
            pending = false;
        }
    }
    if (pending) {
        return null; // 末尾截断在续位中
    }
    // 首个子标识符 V → 40*a+b：V<40 → [0,V]；V<80 → [1,V-40]；否则 [2,V-80]
    var v0 = subs[0];
    var first = v0 < 40 ? [0, v0] : (v0 < 80 ? [1, v0 - 40] : [2, v0 - 80]);
    return first.concat(subs.slice(1)).join('.');
}

// 点分 OID 字符串 → 弧值数组（顺带规范化前导零）：
//   校验规则（X.660）：至少 2 个节点、全为数字、首节点 a ∈ {0,1,2}、
//   a 为 0/1 时第二节点 b < 40（如 1.40.x 越界报错；a=2 时 b 不限，
//   2.1000 合法）；单节点数值上限 0xFFFFFFFFFFFF（2^48-1，防浮点失真）
function oidDotToArcs(dot) {
    var s = String(dot == null ? '' : dot).trim();
    if (!/^\d+(\.\d+)+$/.test(s)) {
        throw new Error('不是合法的点分 OID（应形如 1.2.156.10197.1.301）');
    }
    var parts = s.split('.');
    if (parts.length < 2) {
        throw new Error('点分 OID 至少需要 2 个节点');
    }
    var arcs = [];
    for (var i = 0; i < parts.length; i++) {
        var v = Number(parts[i]);
        if (v > 0xFFFFFFFFFFFF) {
            throw new Error('第 ' + (i + 1) + ' 个节点数值过大');
        }
        arcs.push(v);
    }
    if (arcs[0] > 2) {
        throw new Error('首节点只能是 0 / 1 / 2（X.660 根节点规则）');
    }
    if (arcs[0] <= 1 && arcs[1] >= 40) {
        throw new Error('首节点为 ' + arcs[0] + ' 时第二节点必须小于 40（X.660 规则）');
    }
    return arcs;
}

// 弧值数组 → OID 内容字节数组（首两节点合并为 40*a+b 后逐节点 base-128）
function oidArcsToBytes(arcs) {
    if (!arcs || arcs.length < 2) {
        throw new Error('点分 OID 至少需要 2 个节点');
    }
    var bytes = oidEncodeBase128(arcs[0] * 40 + arcs[1]);
    for (var i = 2; i < arcs.length; i++) {
        bytes = bytes.concat(oidEncodeBase128(arcs[i]));
    }
    return bytes;
}

// 字节数组 → 大写紧凑 Hex（无分隔）
function oidBytesToHex(bytes) {
    var out = '';
    for (var i = 0; i < bytes.length; i++) {
        out += (bytes[i] < 16 ? '0' : '') + bytes[i].toString(16).toUpperCase();
    }
    return out;
}

// 紧凑 Hex → 每 2 字符空格分组的展示串（便于阅读）
function oidFormatHex(compact) {
    return String(compact).replace(/([0-9A-Fa-f]{2})/g, '$1 ').replace(/\s+$/, '');
}

// 内容字节数组 → `06 LL` 前缀串（内容 <128 字节用短格式，否则 06 81 LL）
function oidTlvPrefix(contentLen) {
    if (contentLen < 0x80) {
        return '06 ' + (contentLen < 16 ? '0' : '') + contentLen.toString(16).toUpperCase();
    }
    return '06 81 ' + (contentLen < 16 ? '0' : '') + contentLen.toString(16).toUpperCase();
}

// 点分 OID → 大写紧凑内容 Hex（不含 06 头）；非法点分串抛中文错误
function oidDotToHex(dot) {
    return oidBytesToHex(oidArcsToBytes(oidDotToArcs(dot)));
}

// Hex（可带 06 LL 头，自动识别剥离）→ 点分 OID；非法抛中文错误
function oidHexToDot(hex) {
    var st = oidStripTlvHeader(oidHexToBytes(hex));
    var dotted = oidDecodeOidBytes(st.bytes);
    if (dotted === null) {
        throw new Error('按 base-128 解码失败：内容为空、末尾截断或数值过大');
    }
    return dotted;
}

// 点分 OID 规范化（去前导零）：合法返回规范化串，非法返回 null
function oidNormalizeOid(dot) {
    try {
        return oidDotToArcs(dot).join('.');
    } catch (e) {
        return null;
    }
}

// 库内精确查找（先规范化再比对）；未命中返回 null
function oidFindEntry(dot) {
    var norm = oidNormalizeOid(dot);
    if (norm === null) {
        return null;
    }
    for (var i = 0; i < OID_DB.length; i++) {
        if (OID_DB[i].oid === norm) {
            return OID_DB[i];
        }
    }
    return null;
}

// 顶层分支提示（最长前缀匹配；无匹配返回空串）
function oidBranchTip(dot) {
    var norm = oidNormalizeOid(dot);
    if (norm === null) {
        return '';
    }
    var best = '';
    var bestLen = -1;
    for (var i = 0; i < OID_BRANCHES.length; i++) {
        var p = OID_BRANCHES[i].prefix;
        if ((norm === p || norm.indexOf(p + '.') === 0) && p.length > bestLen) {
            best = OID_BRANCHES[i].tip;
            bestLen = p.length;
        }
    }
    return best;
}

// ---------- 结果渲染 ----------

// 信息卡单行（键值行）
function oidCardRow(k, v, mono) {
    return '<div class="oid-card-row"><span class="oid-k">' + oidEsc(k) +
        '</span><span class="oid-v' + (mono ? ' oid-mono' : '') + '">' + oidEsc(v) + '</span></div>';
}

// 查询结果信息卡：命中 / 未收录共用（entry 为 null 时展示分支提示）
// note 为来源说明（如"由 Hex 解码，已剥离 06 长度头"）
function oidRenderCard(out, dotted, entry, note) {
    var html = '<div class="oid-card">';
    if (entry) {
        html += '<div class="oid-card-title">✅ ' + oidEsc(entry.name) +
            '<span class="oid-card-en">' + oidEsc(entry.nameEn) + '</span></div>' +
            oidCardRow('OID', dotted, true) +
            oidCardRow('分类', entry.cat) +
            oidCardRow('出处', entry.source) +
            oidCardRow('说明', entry.desc);
    } else {
        var tip = oidBranchTip(dotted);
        html += '<div class="oid-card-title">⚠️ 库中未收录：' + oidEsc(dotted) + '</div>' +
            oidCardRow('分支提示', tip === '' ? '—（未知分支）' : tip);
    }
    // 实时 DER 编码：内容 Hex + 完整 TLV（06 头）双版本展示
    var content = oidDotToHex(dotted);
    var grouped = oidFormatHex(content);
    html += oidCardRow('DER 编码', grouped + '（含头：' + oidFormatHex(oidTlvPrefix(content.length / 2).replace(/ /g, '') + content) + '）', true);
    if (note) {
        html += '<div class="oid-card-note">' + oidEsc(note) + '</div>';
    }
    html += '</div>';
    out.innerHTML = html;
}

// 表格行 HTML：点击行回填查询（data-oid 由事件委托读取）
function oidRowHtml(entry) {
    return '<tr data-oid="' + oidEsc(entry.oid) + '"><td>' + oidEsc(entry.oid) + '</td><td>' +
        oidEsc(entry.name) + ' <span class="oid-en">' + oidEsc(entry.nameEn) + '</span></td><td>' +
        oidEsc(entry.cat) + '</td><td>' + oidEsc(entry.source) + '</td></tr>';
}

// 关键字搜索结果列表（count + 表格，静态数据 + 转义后 innerHTML 拼接）
function oidRenderList(out, hits, keyword) {
    if (hits.length === 0) {
        out.innerHTML = '<div class="oid-card-note">未找到匹配 “' + oidEsc(keyword) +
            '” 的条目（可试试 SM2 / keyUsage / RFC 4055 等关键字，或直接输入点分 OID / Hex）</div>';
        return;
    }
    var html = '<div class="oid-card-note">关键字 “' + oidEsc(keyword) + '” 命中 ' + hits.length + ' 条（点击行查看详情）</div>' +
        '<div class="httpref-wrap"><table class="query-table">' +
        '<thead><tr><th style="width:200px;">OID</th><th>名称</th><th style="width:110px;">分类</th><th style="width:200px;">出处标准</th></tr></thead><tbody>';
    for (var i = 0; i < hits.length; i++) {
        html += oidRowHtml(hits[i]);
    }
    html += '</tbody></table></div>';
    out.innerHTML = html;
}

// 错误信息卡
function oidRenderError(out, msg) {
    out.innerHTML = '<span class="oid-error">❌ ' + oidEsc(msg) + '</span>';
}

// ---------- 页面动作 ----------

// "查询"按钮：识别输入类型（点分 OID / Hex / 关键字）分派处理
function oidRun() {
    var inputEl = document.getElementById('oid-input');
    var out = document.getElementById('oid-result');
    if (!inputEl || !out) {
        return;
    }
    var raw = inputEl.value.trim();
    if (raw === '') {
        showNotification('请先输入点分 OID、DER Hex 或名称关键字');
        return;
    }
    try {
        if (/^\d+(\.\d+)+$/.test(raw)) {
            // 1) 点分 OID：校验（1.40.x 之类越界在此报错）→ 查库 → 信息卡
            var dotted = oidDotToArcs(raw).join('.');
            oidRenderCard(out, dotted, oidFindEntry(dotted), '');
            return;
        }
        var cleaned = oidCleanHex(raw);
        if (/^[0-9a-fA-F]+$/.test(cleaned) && cleaned.length % 2 === 0 && cleaned.length >= 2) {
            // 2) Hex：识别并剥离 06 LL 头 → base-128 解码 → 查库
            var st = oidStripTlvHeader(oidHexToBytes(cleaned));
            var decoded = oidDecodeOidBytes(st.bytes);
            if (decoded === null) {
                throw new Error('Hex 按 base-128 解码失败：内容为空、末尾截断或数值过大');
            }
            oidRenderCard(out, decoded, oidFindEntry(decoded),
                '由 Hex 解码' + (st.stripped ? '（已自动剥离 06 长度头，内容 ' + st.bytes.length + ' 字节）' : '（输入未带 06 头，按内容字节处理）'));
            return;
        }
        // 3) 关键字：库内模糊搜索（OID / 名称 / 出处，跨字段 contains，大小写不敏感）
        var q = raw.toLowerCase();
        var hits = [];
        for (var i = 0; i < OID_DB.length; i++) {
            var e = OID_DB[i];
            if (e.oid.toLowerCase().indexOf(q) !== -1 ||
                e.name.toLowerCase().indexOf(q) !== -1 ||
                e.nameEn.toLowerCase().indexOf(q) !== -1 ||
                e.source.toLowerCase().indexOf(q) !== -1) {
                hits.push(e);
            }
        }
        if (hits.length === 0 && /^[0-9a-fA-F]+$/.test(cleaned)) {
            out.innerHTML = '<span class="oid-error">❌ Hex 长度为奇数，无法按字节解码；若想按关键字搜索请换个词</span>';
            return;
        }
        oidRenderList(out, hits, raw);
    } catch (e) {
        oidRenderError(out, e.message);
        showNotification('查询失败：' + e.message);
    }
}

// 互转结果当前可复制的紧凑文本（显示带空格版 / 复制紧凑版）
var OID_CONVERT_TEXT = '';

// 写互转结果区：displayed 为展示内容，compact 为复制用紧凑串
function oidSetConvert(displayed, compact) {
    var el = document.getElementById('oid-convert');
    if (!el) {
        return;
    }
    if (displayed === null) {
        el.innerHTML = '';
        OID_CONVERT_TEXT = '';
        return;
    }
    if (compact === undefined || compact === null) {
        compact = displayed;
    }
    el.textContent = displayed;
    el.title = compact; // 悬浮提示给紧凑版
    OID_CONVERT_TEXT = compact;
}

// "Hex → OID"按钮：支持空格分隔 Hex，自动识别并剥离 06 LL 头
function oidHexToOid() {
    var inputEl = document.getElementById('oid-input');
    if (!inputEl) {
        return;
    }
    if (inputEl.value.trim() === '') {
        showNotification('请先在输入框中填写 Hex');
        return;
    }
    try {
        oidSetConvert(oidHexToDot(inputEl.value));
    } catch (e) {
        oidSetConvert('❌ ' + e.message, ''); // 紧凑串置空，禁止复制错误文案
        showNotification('Hex → OID 失败：' + e.message);
    }
}

// "OID → Hex"按钮：校验点分串后 base-128 编码，展示空格分组大写 Hex
function oidOidToHex() {
    var inputEl = document.getElementById('oid-input');
    if (!inputEl) {
        return;
    }
    if (inputEl.value.trim() === '') {
        showNotification('请先在输入框中填写点分 OID');
        return;
    }
    try {
        var compact = oidDotToHex(inputEl.value);
        // 展示带空格版本；title 与复制均为无空格紧凑串
        oidSetConvert(oidFormatHex(compact), compact);
    } catch (e) {
        oidSetConvert('❌ ' + e.message, ''); // 紧凑串置空，禁止复制错误文案
        showNotification('OID → Hex 失败：' + e.message);
    }
}

// 互转结果"复制"按钮：复制紧凑串（非显示文本）
function oidCopyConvert() {
    if (!OID_CONVERT_TEXT) {
        showNotification('暂无可复制的互转结果');
        return;
    }
    copyTextToClipboard(OID_CONVERT_TEXT);
}

// "清空"按钮
function oidClear() {
    var inputEl = document.getElementById('oid-input');
    var out = document.getElementById('oid-result');
    if (inputEl) { inputEl.value = ''; }
    if (out) { out.innerHTML = ''; }
    oidSetConvert(null);
}

// ---------- 内置库浏览表 ----------

// 按分类单选 + 搜索框过滤渲染浏览表（静态数据转义后 innerHTML 一次性拼接）
function oidRenderTable() {
    var container = document.getElementById('oid-table-container');
    if (!container) {
        return;
    }
    // 当前分类：all 或五类之一（与 OID_DB 的 cat 字段取值一致）
    var cat = 'all';
    var checked = document.querySelector('input[name="oid-cat"]:checked');
    if (checked) {
        cat = checked.value;
    }
    var searchEl = document.getElementById('oid-search');
    var q = searchEl && searchEl.value ? searchEl.value.trim().toLowerCase() : '';

    var rows = [];
    for (var i = 0; i < OID_DB.length; i++) {
        var e = OID_DB[i];
        if (cat !== 'all' && e.cat !== cat) {
            continue;
        }
        if (q &&
            e.oid.toLowerCase().indexOf(q) === -1 &&
            e.name.toLowerCase().indexOf(q) === -1 &&
            e.nameEn.toLowerCase().indexOf(q) === -1 &&
            e.source.toLowerCase().indexOf(q) === -1) {
            continue;
        }
        rows.push(e);
    }

    var html = '<p class="httpref-count">共 ' + rows.length + ' 条</p>' +
        '<div class="httpref-wrap"><table class="query-table">' +
        '<thead><tr><th style="width:200px;">OID</th><th>名称</th><th style="width:110px;">分类</th><th style="width:200px;">出处标准</th></tr></thead><tbody>';
    for (var r = 0; r < rows.length; r++) {
        html += oidRowHtml(rows[r]);
    }
    html += '</tbody></table></div>';
    container.innerHTML = html;
}

// ---------- 初始化 ----------

// 绑定搜索输入（input 实时过滤）、分类单选与表格行点击（事件委托，重渲染后依然有效）
function oidInit() {
    var searchEl = document.getElementById('oid-search');
    if (searchEl) {
        searchEl.addEventListener('input', oidRenderTable);
    }
    var radios = document.getElementsByName('oid-cat');
    for (var i = 0; i < radios.length; i++) {
        radios[i].addEventListener('change', oidRenderTable);
    }
    // 浏览表与查询结果列表的行点击：回填输入框并执行查询（事件委托）
    var containers = [document.getElementById('oid-table-container'), document.getElementById('oid-result')];
    for (var c = 0; c < containers.length; c++) {
        if (!containers[c]) {
            continue;
        }
        containers[c].addEventListener('click', function (event) {
            var tr = event.target && event.target.closest ? event.target.closest('tr[data-oid]') : null;
            if (!tr) {
                return;
            }
            var inputEl = document.getElementById('oid-input');
            if (inputEl) {
                inputEl.value = tr.getAttribute('data-oid');
            }
            oidRun();
        });
    }
    oidRenderTable();
}

// 本文件在 body 尾加载，正常情况下元素已就绪可直接初始化；
// readyState 判断用于兜底：若未来被改为提前加载，则等待 DOM 就绪后再初始化；
// 无 document 的环境（Node 打桩测试纯转换函数）直接跳过
if (typeof document === 'undefined') {
    // Node 环境：不初始化页面，仅暴露纯函数供测试
} else if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', oidInit);
} else {
    oidInit();
}

// Node 环境导出纯数据与纯函数（浏览器中 module 未定义，此块自动跳过，便于对拍自测）
if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
        OID_DB: OID_DB,
        OID_BRANCHES: OID_BRANCHES,
        oidCleanHex: oidCleanHex,
        oidHexToBytes: oidHexToBytes,
        oidStripTlvHeader: oidStripTlvHeader,
        oidEncodeBase128: oidEncodeBase128,
        oidDecodeOidBytes: oidDecodeOidBytes,
        oidDotToArcs: oidDotToArcs,
        oidArcsToBytes: oidArcsToBytes,
        oidBytesToHex: oidBytesToHex,
        oidDotToHex: oidDotToHex,
        oidHexToDot: oidHexToDot,
        oidFormatHex: oidFormatHex,
        oidNormalizeOid: oidNormalizeOid,
        oidFindEntry: oidFindEntry,
        oidBranchTip: oidBranchTip
    };
}
