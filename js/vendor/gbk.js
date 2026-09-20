// GBK 编解码库（自旧单文件版 HTML 提取，IIFE 挂载 window.gbk）

        // 完整的GBK编码/解码库（支持23940个GBK字符）
        (function(window) {
            'use strict';
            
            let encodeTable;  // Unicode -> GBK 编码表
            let decodeTable;  // GBK -> Unicode 解码表

            function initGbkTables() {
                // 初始化编码表（基于GBK标准区位码范围）
                // https://en.wikipedia.org/wiki/GBK_(character_encoding)#Encoding
                const ranges = [
                    [0xA1, 0xA9,  0xA1, 0xFE],
                    [0xB0, 0xF7,  0xA1, 0xFE],
                    [0x81, 0xA0,  0x40, 0xFE],
                    [0xAA, 0xFE,  0x40, 0xA0],
                    [0xA8, 0xA9,  0x40, 0xA0],
                    [0xAA, 0xAF,  0xA1, 0xFE],
                    [0xF8, 0xFE,  0xA1, 0xFE],
                    [0xA1, 0xA7,  0x40, 0xA0],
                ];
                
                const codes = new Uint16Array(23940);
                let i = 0;

                for (const [b1Begin, b1End, b2Begin, b2End] of ranges) {
                    for (let b2 = b2Begin; b2 <= b2End; b2++) {
                        if (b2 !== 0x7F) {
                            for (let b1 = b1Begin; b1 <= b1End; b1++) {
                                codes[i++] = b2 << 8 | b1;
                            }
                        }
                    }
                }
                
                // 创建编码表
                encodeTable = new Uint16Array(65536);
                encodeTable.fill(0xFFFF);

                // 使用浏览器原生TextDecoder生成字符串
                const str = new TextDecoder('gbk').decode(codes);
                
                // 创建解码表（GBK -> Unicode）
                decodeTable = new Map();
                
                for (let i = 0; i < str.length; i++) {
                    const unicode = str.charCodeAt(i);
                    const gbkCode = codes[i];
                    
                    // Unicode -> GBK (编码)
                    encodeTable[unicode] = gbkCode;
                    
                    // GBK -> Unicode (解码)
                    decodeTable.set(gbkCode, unicode);
                }
                
                console.log(`✓ GBK表已初始化: ${decodeTable.size} 个字符映射`);
            }

            // 编码：字符串 -> GBK字节数组
            function str2gbk(str, opt = {}) {
                if (!encodeTable) {
                    initGbkTables();
                }
                
                const onAlloc = opt.onAlloc || ((len) => new Uint8Array(len));
                const onError = opt.onError || (() => 63);  // '?'

                const buf = onAlloc(str.length * 2);
                let n = 0;

                for (let i = 0; i < str.length; i++) {
                    const code = str.charCodeAt(i);
                    
                    // ASCII字符直接输出
                    if (code < 0x80) {
                        buf[n++] = code;
                        continue;
                    }
                    
                    const gbk = encodeTable[code];

                    if (gbk !== 0xFFFF) {
                        buf[n++] = gbk & 0xFF;        // 低字节
                        buf[n++] = (gbk >> 8) & 0xFF; // 高字节
                    } else if (code === 8364) {
                        // 8364 == '€'.charCodeAt(0)
                        // Code Page 936 has a single-byte euro sign at 0x80
                        buf[n++] = 0x80;
                    } else {
                        const ret = onError(i, str);
                        if (ret === -1) {
                            break;
                        }
                        if (ret > 0xFF) {
                            buf[n++] = ret & 0xFF;
                            buf[n++] = (ret >> 8) & 0xFF;
                        } else {
                            buf[n++] = ret;
                        }
                    }
                }
                return buf.subarray(0, n);
            }

            // 解码：GBK字节数组 -> 字符串
            function gbk2str(bytes) {
                if (!decodeTable) {
                    initGbkTables();
                }
                
                const result = [];
                let i = 0;
                
                while (i < bytes.length) {
                    const byte1 = bytes[i];
                    
                    // ASCII字符
                    if (byte1 < 0x80) {
                        result.push(String.fromCharCode(byte1));
                        i++;
                        continue;
                    }
                    
                    // 特殊处理：欧元符号
                    if (byte1 === 0x80) {
                        result.push('€');
                        i++;
                        continue;
                    }
                    
                    // GBK双字节字符
                    if (i + 1 < bytes.length) {
                        const byte2 = bytes[i + 1];
                        const gbkCode = (byte2 << 8) | byte1;
                        
                        const unicode = decodeTable.get(gbkCode);
                        if (unicode !== undefined) {
                            result.push(String.fromCharCode(unicode));
                            i += 2;
                            continue;
                        }
                    }
                    
                    // 无法解码的字符
                    result.push('?');
                    i++;
                }
                
                return result.join('');
            }

            // 暴露到全局（兼容原有代码）
            window.gbk = {
                encode: str2gbk,
                decode: gbk2str,
                str2gbk: str2gbk,
                gbk2str: gbk2str
            };
            
        })(window);
