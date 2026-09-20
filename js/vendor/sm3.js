// SM3 国密哈希实现（自旧单文件版 HTML 提取，IIFE 挂载 window.sm3Hash）

        // 嵌入式 SM3 实现（基于 sm3-1.0.js），适用于浏览器单文件
        (function(window){
            // --- 辅助函数 ---
            function arrayCopy(src, srcPos, dest, destPos, length) {
                for (var i = 0; i < length; i++) {
                    dest[destPos + i] = src[srcPos + i];
                }
                return length;
            }

            function byteArrayToIntArray(bytes) {
                var n = bytes.length / 4;
                var ints = new Array(n);
                for (var i = 0; i < n; i++) {
                    var idx = i * 4;
                    ints[i] = ((bytes[idx] & 0xff) << 24) | ((bytes[idx + 1] & 0xff) << 16) | ((bytes[idx + 2] & 0xff) << 8) | (bytes[idx + 3] & 0xff);
                }
                return ints;
            }

            function intArrayToByteArray(ints) {
                var bytes = new Array(ints.length * 4);
                for (var i = 0; i < ints.length; i++) {
                    var v = ints[i];
                    bytes[i*4] = (v >>> 24) & 0xff;
                    bytes[i*4+1] = (v >>> 16) & 0xff;
                    bytes[i*4+2] = (v >>> 8) & 0xff;
                    bytes[i*4+3] = v & 0xff;
                }
                return bytes;
            }

            function longToByte(len) {
                // len is a number (may be >32 bits)
                var out = new Array(8);
                var high = Math.floor(len / Math.pow(2, 32));
                var low = len >>> 0;
                out[0] = (high >>> 24) & 0xff;
                out[1] = (high >>> 16) & 0xff;
                out[2] = (high >>> 8) & 0xff;
                out[3] = high & 0xff;
                out[4] = (low >>> 24) & 0xff;
                out[5] = (low >>> 16) & 0xff;
                out[6] = (low >>> 8) & 0xff;
                out[7] = low & 0xff;
                return out;
            }

            function toHex(bytes) {
                return Array.prototype.map.call(bytes, function(n){
                    return (n < 16 ? '0' : '') + n.toString(16);
                }).join('');
            }

            function normalizeInputToByteArray(input) {
                if (input instanceof Uint8Array) return Array.prototype.slice.call(input);
                if (input instanceof ArrayBuffer) return Array.prototype.slice.call(new Uint8Array(input));
                if (Array.isArray(input)) return input.slice();
                if (typeof input === 'string') {
                    var bytes = [];
                    for (var i = 0; i < input.length; i++) {
                        var c = input.charCodeAt(i);
                        if (c < 128) bytes.push(c);
                        else if (c < 2048) {
                            bytes.push(192 + (c >> 6));
                            bytes.push(128 + (c & 63));
                        } else if (c < 65536) {
                            bytes.push(224 + (c >> 12));
                            bytes.push(128 + ((c >> 6) & 63));
                            bytes.push(128 + (c & 63));
                        } else {
                            bytes.push(240 + (c >> 18));
                            bytes.push(128 + ((c >> 12) & 63));
                            bytes.push(128 + ((c >> 6) & 63));
                            bytes.push(128 + (c & 63));
                        }
                    }
                    return bytes;
                }
                throw new Error('Invalid input type for SM3');
            }

            // --- 下面为 sm3-1.0.js 的核心实现（已做少量适配） ---
            function SM3Digest(){

                this.ivByte = new Array( 0x73,  0x80, 0x16, 0x6f, 0x49,
                    0x14,  0xb2, 0xb9, 0x17, 0x24, 0x42, 0xd7,
                    0xda,  0x8a, 0x06, 0x00, 0xa9, 0x6f, 0x30,
                    0xbc,  0x16, 0x31, 0x38, 0xaa, 0xe3,
                    0x8d,  0xee, 0x4d, 0xb0, 0xfb, 0x0e,
                    0x4e );
                this.iv = byteArrayToIntArray(
                            this.ivByte
                        );
                this.tj = new Array(64);
                this.BLOCK_BYTE_LEN = 64;
                
                this.vbuf = new Array(8);
                //数据缓冲区
                this.dataBuf = new Array(64);
                //缓冲区长度
                this.dataBufLen = 0;
                //缓冲区总长度
                this.totalLen = 0;//使用数字表示字节长度
                
                for(var i = 0;i<64;i++) {
                    if(i<=15) {
                        this.tj[i] = 0x79cc4519;
                    }else {
                        this.tj[i] = 0x7a879d8a;
                    }
                }
                arrayCopy(this.iv, 0, this.vbuf, 0, this.vbuf.length);
            }

            SM3Digest.prototype = {
                ffj:function(x,y,z,i){
                    var tmp;
                    if(i<=15) {
                        tmp = x^y^z;
                    }else{
                        tmp = (x&y)|(x&z)|(y&z);
                    }
                    return tmp;
                },
                ggj:function(x,y,z,i){
                    var tmp = 0;
                    if(i<=15) {
                        tmp = x^y^z;
                    }else {
                        tmp = (x&y)|(~x&z);
                    }
                    return tmp;
                },
                p0:function(x) {
                    return x^(x<<9|(x>>>(32-9)))^(x<<17|(x>>>(32-17)));
                },
                p1:function(x) {
                    return x^(x<<15|(x>>>(32-15)))^(x<<23|(x>>>(32-23)));
                },
                cycleLeft:function(x,moveLen) {
                    return x<<moveLen|(x>>>(32-moveLen));
                },
                padding:function(data) {
                    var k = 0;
                    var len = data.length;
                    var padding;
                    k = 64 - (len + 1 + 8)%64;
                    if(k>=64) { k = 0; }
                    padding = new Array(k+1+len+8);
                    padding[len] = 1<<7;
                    arrayCopy(data, 0, padding, 0, len);
                    arrayCopy(longToByte(this.totalLen<<3), 0, padding, len+k+1, 8);
                    return padding;
                },
                iterate:function(message) {
                    var len = message.length;
                    var n = parseInt(len/16);
                    var v,b;
                    var ep;
                    v = this.vbuf;
                    b = new Array(16);
                    for(var i = 0;i<n;i++) {
                        arrayCopy(message, i*16, b, 0, b.length);
                        ep = this.expand(b);
                        v = this.cf(v, ep[0], ep[1]);
                    }
                    arrayCopy(v, 0, this.vbuf, 0, v.length);
                },
                expand:function(b) {
                    var w1 = new Array(68);
                    var w2 = new Array(64);
                    arrayCopy(b, 0, w1, 0, b.length);
                    for(var i = 16;i<w1.length;i++) {
                        w1[i] = this.p1(w1[i-16]^w1[i-9]^this.cycleLeft(w1[i-3], 15))^this.cycleLeft(w1[i-13],7)^w1[i-6];
                    }
                    for(var i = 0;i<w2.length;i++) {
                        w2[i] = w1[i]^w1[i+4];
                    }
                    return new Array(w1,w2);
                },
                cf:function(v,w1,w2) {
                    var result;
                    var a,b,c,d,e,f,g,h,ss1,ss2,tt1,tt2;
                    a = v[0]; b = v[1]; c = v[2]; d = v[3]; e = v[4]; f = v[5]; g = v[6]; h = v[7];
                    for(var i = 0;i<64;i++) {
                        ss1 = this.cycleLeft(this.cycleLeft(a, 12)+e+this.cycleLeft(this.tj[i], i),7);
                        ss2 = ss1^this.cycleLeft(a, 12);
                        tt1 = this.ffj(a, b, c,i)+d+ss2+w2[i];
                        tt2 = this.ggj(e,f,g,i)+h+ss1+w1[i];
                        d = c; c = this.cycleLeft(b, 9); b = a; a = tt1; h = g; g = this.cycleLeft(f, 19); f = e; e = this.p0(tt2);
                    }
                    result = new Array(8);
                    result[0] = a^v[0]; result[1] = b^v[1]; result[2] = c^v[2]; result[3] = d^v[3]; result[4] = e^v[4]; result[5] = f^v[5]; result[6] = g^v[6]; result[7] = h^v[7];
                    return result;
                },
                digest:function(data) {
                    var paddingArr = this.padding(data);
                    var paddingInt = byteArrayToIntArray(paddingArr);
                    this.iterate(paddingInt);
                    var macInt = this.vbuf;
                    var mac = intArrayToByteArray(macInt);
                    return mac;
                },
                update:function(data,pos,len) {
                    var loop = parseInt((len+this.dataBufLen)/64);
                    this.totalLen += len;
                    if(len+this.dataBufLen<this.BLOCK_BYTE_LEN) {
                        arrayCopy(data, 0, this.dataBuf, this.dataBufLen, len);
                        this.dataBufLen = len+this.dataBufLen;
                    }else {
                        var dataInt;
                        arrayCopy(data, 0 , this.dataBuf, this.dataBufLen, this.BLOCK_BYTE_LEN-this.dataBufLen);
                        dataInt = byteArrayToIntArray(this.dataBuf);
                        this.iterate(dataInt);
                        for(var i = 1;i<loop;i++) {
                            arrayCopy(data, i*this.BLOCK_BYTE_LEN-this.dataBufLen, this.dataBuf, 0, this.BLOCK_BYTE_LEN);
                            dataInt = byteArrayToIntArray(this.dataBuf);
                            this.iterate(dataInt);
                        }
                        arrayCopy(data, loop*this.BLOCK_BYTE_LEN-this.dataBufLen , this.dataBuf, 0, len-(loop*this.BLOCK_BYTE_LEN-this.dataBufLen));
                        this.dataBufLen = len-(loop*this.BLOCK_BYTE_LEN-this.dataBufLen);
                    }
                },
                doFinal:function() {
                    var finalData = new Array(this.dataBufLen);
                    arrayCopy(this.dataBuf, 0, finalData, 0, this.dataBufLen);
                    var paddingArr = this.padding(finalData);
                    var paddingInt = byteArrayToIntArray(paddingArr);
                    this.iterate(paddingInt);
                    var macInt = this.vbuf;
                    var mac = intArrayToByteArray(macInt);
                    return mac;
                }
            };

            // --- 对外暴露简单函数 ---
            window.sm3Hash = function(input) {
                var bytes = normalizeInputToByteArray(input);
                var d = new SM3Digest();
                d.update(bytes, 0, bytes.length);
                var mac = d.doFinal();
                return toHex(mac);
            };
        })(window);
