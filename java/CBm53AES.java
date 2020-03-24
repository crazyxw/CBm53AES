

public class CBm53AES {
    char[] Sbox = new char[256];
    char[] InvSbox = new char[256];
    char[][][] w = new char[11][4][4];

    public CBm53AES(char[] key) {
        char sBox[] =
                { /* 0 1 2 3 4 5 6 7 8 9 a b c d e f */
                        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76, /*0*/
                        0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, /*1*/
                        0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15, /*2*/
                        0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75, /*3*/
                        0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84, /*4*/
                        0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf, /*5*/
                        0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8, /*6*/
                        0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, /*7*/
                        0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73, /*8*/
                        0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb, /*9*/
                        0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, /*a*/
                        0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08, /*b*/
                        0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a, /*c*/
                        0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, /*d*/
                        0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf, /*e*/
                        0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16 /*f*/
                };
        char invsBox[] =
                { /* 0 1 2 3 4 5 6 7 8 9 a b c d e f */
                        0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb, /*0*/
                        0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb, /*1*/
                        0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e, /*2*/
                        0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25, /*3*/
                        0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92, /*4*/
                        0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84, /*5*/
                        0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06, /*6*/
                        0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b, /*7*/
                        0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73, /*8*/
                        0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e, /*9*/
                        0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b, /*a*/
                        0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4, /*b*/
                        0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f, /*c*/
                        0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef, /*d*/
                        0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61, /*e*/
                        0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d /*f*/
                };

        System.arraycopy(sBox, 0, Sbox, 0, 256);

        System.arraycopy(invsBox, 0, InvSbox, 0, 256);
        KeyExpansion(key, w);
    }


    void Cipher(char[] input, char[] output) {
        char uch_input[] = new char[1024];
        strToUChar(input, uch_input);
        Cipher(uch_input);
        ucharToHex(uch_input, output, 16);
    }

    /*********************************************
     * 函数名：  CipherStr
     * 描述：    整段文档加密
     *
     * @参数： char[] input
     * @参数： char[] output
     * @返回值： void
     *********************************************/
    void CipherStr(char[] input, char[] output) {
        int nLen = input.length;
        char[] newAlock = new char[input.length + (16 - nLen % 16) + 1];
        System.arraycopy(input, 0, newAlock, 0, input.length);
        for (int n = 0; n < (16 - nLen % 16); n++) {
            newAlock[nLen + n] = (char) (16 - nLen % 16);
        }
        newAlock[nLen + (16 - nLen % 16)] = 0;
        int i = 0, j = 0;
        char block[] = new char[17];
        for (i = 0; i < 17; i++) {
            block[i] = 0;
        }
        char e_block[] = new char[33];
        for (i = 0; i < 33; i++) {
            e_block[i] = 0;
        }
        i = 0;
        while (newAlock[i] != '\0') {
            System.arraycopy(newAlock, i, block, 0, 16);
            Cipher(block, e_block);
            System.arraycopy(e_block, 0, output, j, 32);
            i += 16;
            j += 32;
        }
        output[j] = '\0';
    }

    void InvCipher(char[] input, char[] output) {
        char[] uch_input = new char[1024];
        hexToUChar(input, uch_input);
        InvCipher(uch_input);
        ucharToStr(uch_input, output, 16);
    }

    /*********************************************
     * 函数名：  InvCipherStr
     * 描述：    对整段文字解密
     *
     * @参数： char[] input 16进制密文
     * @参数： char[] output 原文
     * @返回值： void
     *********************************************/
    void InvCipherStr(char[] input, char[] output) {
        char[] uch_input = new char[input.length / 2];
        char[] uch_output = new char[output.length];
        hexToUChar(input, uch_input);
        int nBuf = 0;
        char ublock[] = new char[16];
        int n = strlen(input);
        while (nBuf < (int) (strlen(input) / 2)) {
            System.arraycopy(uch_input, nBuf, ublock, 0, 16);
            InvCipher(ublock);
            System.arraycopy(ublock, 0, uch_output, nBuf, 16);
            nBuf += 16;
        }
        ucharToStr(uch_output, output, nBuf);
        //剔除用于补充16字节的字符
        int nLen = strlen(output);
        for (n = nLen - 1; n >= nLen - 16; n--) {
            if (1 <= output[n] && 16 >= output[n]) {
                output[n] = 0;
            } else {
                break;
            }
        }
    }

    char[] Cipher(char[] input) {
        char[][] state = new char[4][4];
        int i, r, c;
        for (r = 0; r < 4; r++) {
            for (c = 0; c < 4; c++) {
                state[r][c] = input[c * 4 + r];
            }
        }
        AddRoundKey(state, w[0]);
        for (i = 1; i <= 10; i++) {
            SubBytes(state);
            ShiftRows(state);
            if (i != 10) MixColumns(state);
            AddRoundKey(state, w[i]);
        }

        for (r = 0; r < 4; r++) {
            for (c = 0; c < 4; c++) {
                input[c * 4 + r] = state[r][c];
            }
        }

        return input;
    }

    char[] InvCipher(char[] input) {
        char[][] state = new char[4][4];
        int i, r, c;
        for (r = 0; r < 4; r++) {
            for (c = 0; c < 4; c++) {
                state[r][c] = input[c * 4 + r];
            }
        }
        AddRoundKey(state, w[10]);
        for (i = 9; i >= 0; i--) {
            InvShiftRows(state);
            InvSubBytes(state);
            AddRoundKey(state, w[i]);
            if (i > 0) {
                InvMixColumns(state);
            }
        }
        for (r = 0; r < 4; r++) {
            for (c = 0; c < 4; c++) {
                input[c * 4 + r] = state[r][c];
            }
        }
        return input;
    }


    void KeyExpansion(char[] key, char w[][][]) {
        int i, j, r, c;
        char rc[] = {0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36};
        for (r = 0; r < 4; r++) {
            for (c = 0; c < 4; c++) {
                if (r + c * 4 >= key.length) {
                    w[0][r][c] = 0;
                } else {
                    w[0][r][c] = key[r + c * 4];
                }
            }
        }
        for (i = 1; i <= 10; i++) {
            for (j = 0; j < 4; j++) {
                char[] t = new char[4];
                for (r = 0; r < 4; r++) {
                    if (j !=0){
                        t[r] = w[i][r][j - 1];
                    }else{
                        t[r] = w[i - 1][r][3];
                    }
//                    t[r] = j != 0 ? w[i][r][j - 1] : w[i - 1][r][3];
                }
                if (j == 0) {
                    char temp = t[0];
                    for (r = 0; r < 3; r++) {
                        t[r] = Sbox[t[(r + 1) % 4]];
                    }
                    t[3] = Sbox[temp];
                    t[0] ^= rc[i - 1];
                }
                for (r = 0; r < 4; r++) {
                    w[i][r][j] = (char) (w[i - 1][r][j] ^ t[r]);
                }
            }
        }
    }

    char FFmul(char a, char b) {
        char[] bw = new char[4];
        char res = 0;
        int i;
        bw[0] = b;
        for (i = 1; i < 4; i++) {
            bw[i] = (char) (bw[i - 1] << 1);
            if ((bw[i - 1] & 0x80) > 0) {
                bw[i] ^= 0x1b;
            }
        }
        for (i = 0; i < 4; i++) {
            if (((a >> i) & 0x01) > 0) {
                res ^= bw[i];
            }
        }
        return (char) (res % 256);
    }

    void SubBytes(char state[][]) {
        int r, c;
        for (r = 0; r < 4; r++) {
            for (c = 0; c < 4; c++) {
                state[r][c] = Sbox[state[r][c]];
            }
        }
    }

    void ShiftRows(char state[][]) {
        char[] t = new char[4];
        int r, c;
        for (r = 1; r < 4; r++) {
            for (c = 0; c < 4; c++) {
                t[c] = state[r][(c + r) % 4];
            }
            for (c = 0; c < 4; c++) {
                state[r][c] = t[c];
            }
        }
    }

    void MixColumns(char state[][]) {
        char[] t = new char[4];
        int r, c;
        for (c = 0; c < 4; c++) {
            for (r = 0; r < 4; r++) {
                t[r] = state[r][c];
            }
            for (r = 0; r < 4; r++) {
                state[r][c] = (char) (FFmul((char) 0x02, t[r])
                        ^ FFmul((char) 0x03, t[(r + 1) % 4])
                        ^ FFmul((char) 0x01, t[(r + 2) % 4])
                        ^ FFmul((char) 0x01, t[(r + 3) % 4]));
                state[r][c] = (char) (state[r][c] % 256);
            }
        }
    }

    void AddRoundKey(char state[][], char k[][]) {
        int r, c;
        for (c = 0; c < 4; c++) {
            for (r = 0; r < 4; r++) {
                state[r][c] ^= k[r][c];
            }
        }
    }

    void InvSubBytes(char state[][]) {
        int r, c;
        for (r = 0; r < 4; r++) {
            for (c = 0; c < 4; c++) {
                state[r][c] = InvSbox[state[r][c]];
            }
        }
    }

    void InvShiftRows(char state[][]) {
        char[] t = new char[4];
        int r, c;
        for (r = 1; r < 4; r++) {
            for (c = 0; c < 4; c++) {
                t[c] = state[r][(c - r + 4) % 4];
            }
            for (c = 0; c < 4; c++) {
                state[r][c] = t[c];
            }
        }
    }

    void InvMixColumns(char state[][]) {
        char[] t = new char[4];
        int r, c;
        for (c = 0; c < 4; c++) {
            for (r = 0; r < 4; r++) {
                t[r] = state[r][c];
            }
            for (r = 0; r < 4; r++) {
                state[r][c] = (char) (FFmul((char) 0x0e, t[r])
                        ^ FFmul((char) 0x0b, t[(r + 1) % 4])
                        ^ FFmul((char) 0x0d, t[(r + 2) % 4])
                        ^ FFmul((char) 0x09, t[(r + 3) % 4]));
            }
        }
    }

    int getUCharLen(char[] uch) {
        int len = 0;
        int i = 0;
        while (uch[i++] > 0)
            ++len;

        return len;
    }

    int ucharToHex(char[] uch, char[] hex, int nLen) {
        int high, low;
        int tmp = 0;
        if (uch == null || hex == null) {
            return -1;
        }
        if (getUCharLen(uch) == 0) {
            return -2;
        }
        int n = 0;
        int hexI = 0;
        int uchI = 0;
        while (n < nLen) {
            tmp = (int) uch[uchI];
            high = tmp >> 4;
            low = tmp & 15;
            hex[hexI++] = valueToHexCh(high); //先写高字节
            hex[hexI++] = valueToHexCh(low); //其次写低字节
            uchI++;
            n++;
        }
        hex[hexI] = '\0';
        return 0;
    }

    int hexToUChar(char[] hex, char[] uch) {
        int high, low;
        int tmp = 0;
        if (hex == null || uch == null) {
            return -1;
        }

        if (hex.length % 2 == 1) {
            return -2;
        }

        int hexI = 0;
        int uchI = 0;
        while (hex[hexI] > 0) {
            high = ascillToValue(hex[hexI]);
            if (high < 0) {
                uch[uchI] = '\0';
                return -3;
            }
            hexI++; //指针移动到下一个字符上
            low = ascillToValue(hex[hexI]);
            if (low < 0) {
                uch[uchI] = '\0';
                return -3;
            }
            tmp = (high << 4) + low;
            uch[uchI++] = (char) tmp;
            hexI++;
        }
        uch[uchI] = (int) '\0';
        return 0;
    }

    int strToUChar(char[] ch, char[] uch) {
        int tmp = 0;
        if (ch == null || uch == null)
            return -1;
        if (ch.length == 0)
            return -2;

        int uchI = 0;
        int chI = 0;
        while (ch[chI] > 0) {
            tmp = (int) ch[chI];
            uch[uchI++] = (char) tmp;
            chI++;
        }
        uch[uchI] = 0x00;
        return 0;
    }

    int ucharToStr(char[] uch, char[] ch, int nlen) {
        int tmp = 0;
        if (uch == null || ch == null)
            return -1;
        int n = 0;
        int chI = 0;
        int uchI = 0;
        while (n < nlen) {
            tmp = (int) uch[uchI];
            ch[chI++] = (char) tmp;
            uchI++;
            n++;
        }
        ch[chI] = '\0';
        return 0;
    }

    int strToHex(char[] ch, char[] hex) {
        int high, low;
        int tmp = 0;
        if (ch == null || hex == null) {
            return -1;
        }

        if (ch.length == 0) {
            return -2;
        }

        int chI = 0;
        int hexI = 0;
        while (ch[chI] > 0) {
            tmp = (int) ch[chI];
            high = tmp >> 4;
            low = tmp & 15;
            hex[hexI++] = valueToHexCh(high); //先写高字节
            hex[hexI++] = valueToHexCh(low); //其次写低字节
            chI++;
        }
        hex[hexI] = '\0';
        return 0;
    }

    int hexToStr(char[] hex, char[] ch) {
        int high, low;
        int tmp = 0;
        if (hex == null || ch == null) {
            return -1;
        }

        if (hex.length % 2 == 1) {
            return -2;
        }

        int hexI = 0;
        int chI = 0;
        while (hex[hexI] > 0) {
            high = ascillToValue(hex[hexI]);
            if (high < 0) {
                ch[chI] = '\0';
                return -3;
            }
            hexI++; //指针移动到下一个字符上
            low = ascillToValue(hex[hexI]);
            if (low < 0) {
                ch[chI] = '\0';
                return -3;
            }
            tmp = (high << 4) + low;
            ch[chI++] = (char) tmp;
            hexI++;
        }
        ch[chI] = '\0';
        return 0;
    }

    int ascillToValue(char ch) {
        int result = 0;
        //获取16进制的高字节位数据
        if (ch >= '0' && ch <= '9') {
            result = (int) (ch - '0');
        } else if (ch >= 'a' && ch <= 'z') {
            result = (int) (ch - 'a') + 10;
        } else if (ch >= 'A' && ch <= 'Z') {
            result = (int) (ch - 'A') + 10;
        } else {
            result = -1;
        }
        return result;
    }

    char valueToHexCh(int value) {
        char result = '\0';
        if (value >= 0 && value <= 9) {
            result = (char) (value + 48); //48为ascii编码的‘0’字符编码值
        } else if (value >= 10 && value <= 15) {
            result = (char) (value - 10 + 65); //减去10则找出其在16进制的偏移量，65为ascii的'A'的字符编码值
        } else {
            ;
        }
        return result;
    }

    public static int strlen(char[] arr) {
        int n;
        for (n = 0; n < arr.length; n++) {
            if (arr[n] == 0) {
                return n;
            }
        }
        return n;
    }


    public static String decrypt(char[] key, String str) throws Exception {
        char[] input = new char[102400];
        char[] c = str.toCharArray();
        for (int i = 0; i < c.length; i++) {
            input[i] = c[i];
        }
        char[] result = new char[102400];
        CBm53AES aes = new CBm53AES(key);
        aes.InvCipherStr(input, result);
        StringBuilder sb = new StringBuilder();
        byte[] bytes = new byte[50000];
        for (int i = 0; i < result.length; i++) {
            if((int)result[i] == 0) {
                break;
            }
            char c1 = result[i];
            byte tmp = (byte) ((byte) c1&0xff);
            bytes[i] = tmp;
            sb.append(result[i]);
        }
        return String.valueOf(sb);
    }


    public static String decrypt_bytes(char[] key, String str) throws Exception {
        char[] input = new char[102400];
        char[] c = str.toCharArray();
        for (int i = 0; i < c.length; i++) {
            input[i] = c[i];
        }
        char[] result = new char[102400];
        CBm53AES aes = new CBm53AES(key);
        aes.InvCipherStr(input, result);
        byte[] bytes = new byte[50000];
        for (int i = 0; i < result.length; i++) {
            if((int)result[i] == 0) {
                break;
            }
            char c1 = result[i];
            byte tmp = (byte) ((byte) c1&0xff);
            bytes[i] = tmp;
        }
        return new String(bytes, "UTF-8");
    }

    public static void main(String[] args) throws Exception {
        String miwen_hex = ""
        char key[] = "".toCharArray();
        String result = decrypt_bytes(key, miwen_hex);
        System.out.println(result);
    }
}
