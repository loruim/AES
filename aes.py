class AES:
    __sub = (0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
             0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
             0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
             0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
             0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
             0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
             0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
             0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
             0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
             0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
             0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
             0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
             0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
             0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
             0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
             0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16)
        
    __invSub = (0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
                0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
                0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
                0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
                0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
                0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
                0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
                0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
                0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
                0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
                0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
                0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
                0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
                0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
                0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
                0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d)
    
    __Nb = 4
    
    def __init__(self, key : bytes):
        self.__key_w, self.__Nr = self._KeyExpansion(key)

    def __get_row_dword(self, state : int, row : int):
        first = (state >> (8 * (15 - row))) & 0xFF
        second = (state >> (8 * (11 - row))) & 0xFF
        third = (state >> (8 * (7 - row))) & 0xFF
        forth = (state >> (8 * (3 - row))) & 0xFF
        dword = (first << (8 * 3)) | (second << (8 * 2)) | (third << (8 * 1)) | forth
        return dword


    def __get_column_dword(self, state : int, column : int):
        dword = (state >> (32 * (3 - column))) & 0xFFFFFFFF
        return dword

    def __get_byte_from_dword(self, dword : int, r : int):
        byte = (dword >> 8 * (3 - r)) & 0xFF
        return byte

    def _SubBytes(self, state : int) -> int:
        result = 0
        for i in range(self.__Nb):
            dword = self.__get_column_dword(state, i)
            for j in range(4):
                byte = self.__get_byte_from_dword(dword, j)
                result = (result << 8) | self.__sub[byte]
        return result

    def _ShiftRows(self, state : int):
        result = 0
        for i in range(4):
            row = self.__get_row_dword(state, i)
            row = ((row << (8 * i)) | (row >> (8 * (4 - i)))) & 0xFFFFFFFF
            result = (result
                    | (((row >> (8 * 3)) & 0XFF) << (8 * (15 - i)))
                    | (((row >> (8 * 2)) & 0xFF) << (8 * (11 - i)))
                    | (((row >> (8 * 1)) & 0xFF) << (8 * (7 - i)))
                    | (((row >> (8 * 0)) & 0xFF) << (8 * (3 - i))))
        return result

    def __mult_by_two(self, byte : int):
        # Умножение на {02}
        byte <<= 1
        if byte.bit_length() > 8:
            byte = (byte & 0xFF) ^ 0x1b
        return byte                     
    
    def __mult_by_three(self, byte : int):
        # Умножение на {03}
        byte ^= self.__mult_by_two(byte)
        return byte
    
    def __mult_by_four(self, byte : int):
        # Умножение на {04}
        byte = self.__mult_by_two(byte) << 1
        if byte.bit_length() > 8:
            byte = (byte & 0xFF) ^ 0x1b
        return byte
    
    def __mult_by_eight(self, byte : int):
        # Умножение на {08}
        byte = self.__mult_by_four(byte) << 1
        if byte.bit_length() > 8:
            byte = (byte & 0xFF) ^ 0x1b
        return byte
    
    def __mult_by_nine(self, byte : int):
        # Умножение на {09}
        byte ^= self.__mult_by_eight(byte)
        return byte
    
    def __mult_by_b(self, byte : int):
        # Умножение на {0b}
        byte ^= self.__mult_by_eight(byte) ^ self.__mult_by_two(byte)
        return byte
    
    def __mult_by_d(self, byte : int):
        # Умножение на {0d}
        byte ^= self.__mult_by_eight(byte) ^ self.__mult_by_four(byte)
        return byte
    
    def __mult_by_e(self, byte : int):
        # Умножение на {0e}
        byte = self.__mult_by_eight(byte) ^ self.__mult_by_four(byte) ^ self.__mult_by_two(byte)
        return byte

    def _MixColumns(self, state: int):
        result = 0
        for i in range(self.__Nb):
            dword = self.__get_column_dword(state, i)
        
            first_byte = self.__get_byte_from_dword(dword, 0)
            second_byte = self.__get_byte_from_dword(dword, 1)
            third_byte = self.__get_byte_from_dword(dword, 2)
            fourth_byte = self.__get_byte_from_dword(dword, 3)

            s_0_c = self.__mult_by_two(first_byte) ^ self.__mult_by_three(second_byte) ^ third_byte ^ fourth_byte
            s_1_c = first_byte ^ self.__mult_by_two(second_byte) ^ self.__mult_by_three(third_byte) ^ fourth_byte
            s_2_c = first_byte ^ second_byte ^ self.__mult_by_two(third_byte) ^ self.__mult_by_three(fourth_byte)
            s_3_c = self.__mult_by_three(first_byte) ^ second_byte ^ third_byte ^ self.__mult_by_two(fourth_byte)

            result =(result << 32) | (s_0_c << 8 * 3) | (s_1_c << 8 * 2) | (s_2_c << 8 * 1) | (s_3_c << 8 * 0)

        return result
    
    def _AddRoundKey(self, state : int, dword_round_key : list):
        result = 0
        for i in range(self.__Nb):
            result = (result << 32) | (self.__get_column_dword(state, i) ^ dword_round_key[i])
        return result
    
    def _KeyExpansion(self, key : bytes):
        def SubWord(dword : int):
            result = 0
            for i in range(4):
                byte = self.__get_byte_from_dword(dword, i)
                byte = self.__sub[byte]
                result = ((result << 8) | byte)
            return result

        def RotWord(dword : int):
            result = ((dword << 8) | (dword >> (8 * 3))) & 0xFFFFFFFF
            return result
        # key size: 128, 192, 256
        if len(key) not in (16, 24, 32):
            raise ValueError(f"Key must 16, 24 or 32 bytes")
        
        N_k = len(key) // 4
        N_r = 6 + N_k

        key_int = int.from_bytes(key, byteorder='big')
        key_w = [0 for _ in range(4 * (N_r + 1))]
        for i in range(N_k):
            shift = (key_int >> (32 * (N_k - i - 1))) & 0xFFFFFFFF
            key_w[i] = shift
        
        # Выше сделал массив w[i]

        temp = 0
        R = 0x01000000
        for i in range(N_k, self.__Nb * (N_r + 1)):
            temp = key_w[i - 1]
            if (i % N_k == 0):
                temp = SubWord(RotWord(temp)) ^ R
                R = R << 1
                if R.bit_length() > 32:
                    R = (R & 0xFFFFFFFF) ^ 0x1b000000
            elif (N_k > 6 and i % N_k == 4):
                temp = SubWord(temp)
            
            key_w[i] =  key_w[i - N_k] ^ temp
        
        return key_w, N_r
    
    def _InvShiftRows(self, state : int):
        result = 0
        for i in range(4):
            row = self.__get_row_dword(state, i)
            row = ((row >> (8 * i)) | (row << (8 * (4 - i)))) & 0xFFFFFFFF
            result = (result
                    | (((row >> (8 * 3)) & 0XFF) << (8 * (15 - i)))
                    | (((row >> (8 * 2)) & 0xFF) << (8 * (11 - i)))
                    | (((row >> (8 * 1)) & 0xFF) << (8 * (7 - i)))
                    | (((row >> (8 * 0)) & 0xFF) << (8 * (3 - i))))
        return result
    
    def _InvSubBytes(self, state : int):
        result = 0
        for i in range(self.__Nb):
            dword = self.__get_column_dword(state, i)
            for j in range(4):
                byte = self.__get_byte_from_dword(dword, j)
                result = (result << 8) | self.__invSub[byte]
        return result

    def _InvMixColumns(self, state : int):                  
        result = 0
        for i in range(self.__Nb):
            dword = self.__get_column_dword(state, i)
            
            first_byte = self.__get_byte_from_dword(dword, 0)
            second_byte = self.__get_byte_from_dword(dword, 1)
            third_byte = self.__get_byte_from_dword(dword, 2)
            fourth_byte = self.__get_byte_from_dword(dword, 3)

            s_0_c = self.__mult_by_e(first_byte) ^ self.__mult_by_b(second_byte) ^ self.__mult_by_d(third_byte) ^ self.__mult_by_nine(fourth_byte)
            s_1_c = self.__mult_by_nine(first_byte) ^ self.__mult_by_e(second_byte) ^ self.__mult_by_b(third_byte) ^ self.__mult_by_d(fourth_byte)
            s_2_c = self.__mult_by_d(first_byte) ^ self.__mult_by_nine(second_byte) ^ self.__mult_by_e(third_byte) ^ self.__mult_by_b(fourth_byte)
            s_3_c = self.__mult_by_b(first_byte) ^ self.__mult_by_d(second_byte) ^ self.__mult_by_nine(third_byte) ^ self.__mult_by_e(fourth_byte)

            result =(result << 32) | (s_0_c << 8 * 3) | (s_1_c << 8 * 2) | (s_2_c << 8 * 1) | (s_3_c << 8 * 0)

        return result
    
    def encrypt_block(self, plaintext : bytes):
        if len(plaintext) != 16:
            raise ValueError(f"Plaintext must contain 16 bytes")
        
        state = int.from_bytes(plaintext, byteorder="big")
        state = self._AddRoundKey(state, self.__key_w[0:self.__Nb])

        for i in range(1, self.__Nr):
            state = self._SubBytes(state)
            state = self._ShiftRows(state)
            state = self._MixColumns(state)
            state = self._AddRoundKey(state, self.__key_w[i * self.__Nb : (i+1) * self.__Nb])
        state = self._SubBytes(state)
        state = self._ShiftRows(state)
        state = self._AddRoundKey(state, self.__key_w[self.__Nr * self.__Nb : (self.__Nr+1) * self.__Nb])
        return state.to_bytes(16, "big")
    
    def decrypt_block(self, ciphertext : bytes):
        if len(ciphertext) != 16:
            raise ValueError(f"Ciphertext must contain 16 bytes")
        
        state = int.from_bytes(ciphertext, byteorder="big")
        state = self._AddRoundKey(state, self.__key_w[self.__Nr * self.__Nb : (self.__Nr + 1) * self.__Nb])

        for i in range(self.__Nr-1, 0, -1):
            state = self._InvShiftRows(state)
            state = self._InvSubBytes(state)
            state = self._AddRoundKey(state, self.__key_w[i * self.__Nb : (i + 1) * self.__Nb])
            state = self._InvMixColumns(state)
        state = self._InvShiftRows(state)
        state = self._InvSubBytes(state)
        state = self._AddRoundKey(state, self.__key_w[0 : self.__Nb])
        return state.to_bytes(16, "big")