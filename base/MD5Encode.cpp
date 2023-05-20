//
// Created by clay on 12/17/22.
//

#include <cstring>
#include <valarray>
#include "MD5Encode.h"
const int Md5Encode::kA = 0x67452301;
const int Md5Encode::kB = 0xefcdab89;
const int Md5Encode::kC = 0x98badcfe;
const int Md5Encode::kD = 0x10325476;

const unsigned long long Md5Encode::k_ti_num_integer = 4294967296;

// function: CycleMoveLeft
// @param src_num:要左移的数
// @param bit_num_to_move:要移动的bit位数
// @return  循环左移后的结果数
UInt32 Md5Encode::CycleMoveLeft(UInt32 src_num, int bit_num_to_move) {
    UInt32 src_num1 = src_num;
    UInt32 src_num2 = src_num;
    if (0 >= bit_num_to_move) {
        return src_num;
    }
    UInt32 num1 = src_num1 << bit_num_to_move;
    UInt32 num2 = src_num2 >> (32 - bit_num_to_move);

    return ((src_num1 << bit_num_to_move) \
        | (src_num2 >> (32 - bit_num_to_move)));
}

// function: FillData
// @param in_data_ptr:    要加密的信息数据
// @param data_byte_len: 数据的字节数
// @param out_data_ptr:  填充必要信息后的数据
// return : 填充信息后的数据长度,以字节为单位
UInt32 Md5Encode::FillData(const char *in_data_ptr, int data_byte_len, char** out_data_ptr) {
    int bit_num = data_byte_len*BIT_OF_BYTE;
    int grop_num = bit_num / BIT_OF_GROUP;
    int mod_bit_num = bit_num % BIT_OF_GROUP;
    int bit_need_fill = 0;
    if (mod_bit_num > (BIT_OF_GROUP - SRC_DATA_LEN)) {
        bit_need_fill = (BIT_OF_GROUP - mod_bit_num);
        bit_need_fill += (BIT_OF_GROUP - SRC_DATA_LEN);
    }
    else {
        bit_need_fill = (BIT_OF_GROUP - SRC_DATA_LEN) - mod_bit_num; //  这里多加了一个BIT_OF_GROUP，避免bit_need_fill正好等于0,暂时不加
    }
    int all_bit = bit_num + bit_need_fill;
    if (0 < bit_need_fill) {
        *out_data_ptr = new char[all_bit / BIT_OF_BYTE + SRC_DATA_LEN / BIT_OF_BYTE];
        memset(*out_data_ptr, 0, all_bit / BIT_OF_BYTE + SRC_DATA_LEN / BIT_OF_BYTE);
        // copy data
        memcpy(*out_data_ptr, in_data_ptr, data_byte_len);
        // fill rest data
        unsigned char *tmp = reinterpret_cast<unsigned char *>(*out_data_ptr);
        tmp += data_byte_len;
        // fill 1 and 0
        *tmp = 0x80;
        // fill origin data len
        unsigned long long * origin_num = (unsigned long long *)((*out_data_ptr) + ((all_bit / BIT_OF_BYTE)));
        *origin_num = data_byte_len*BIT_OF_BYTE;
    }
    return (all_bit / BIT_OF_BYTE + SRC_DATA_LEN / BIT_OF_BYTE);
}

void Md5Encode::RoundF(char *data_BIT_OF_GROUP_ptr, ParamDynamic & param) {
    UInt32 *M = reinterpret_cast<UInt32*>(data_BIT_OF_GROUP_ptr);
    int s[] = { 7, 12, 17, 22 };
    for (int i = 0; i < 16; ++i) {
        UInt32 ti = k_ti_num_integer * abs(sin(i + 1));
        if (i % 4 == 0) {
            FF(param.ua_, param.ub_, param.uc_, param.ud_, M[i], s[i % 4], ti);
        }
        else if (i % 4 == 1) {
            FF(param.ud_, param.ua_, param.ub_, param.uc_, M[i], s[i % 4], ti);
        }
        else if (i % 4 == 2) {
            FF(param.uc_, param.ud_, param.ua_, param.ub_, M[i], s[i % 4], ti);
        }
        else if (i % 4 == 3) {
            FF(param.ub_, param.uc_, param.ud_, param.ua_, M[i], s[i % 4], ti);
        }
    }
}

void Md5Encode::RoundG(char *data_BIT_OF_GROUP_ptr, ParamDynamic & param) {
    UInt32 *M = reinterpret_cast<UInt32*>(data_BIT_OF_GROUP_ptr);
    int s[] = { 5, 9, 14, 20 };
    for (int i = 0; i < 16; ++i) {
        UInt32 ti = k_ti_num_integer * abs(sin(i + 1 + 16));
        int index = (i * 5 + 1) % 16;
        if (i % 4 == 0) {
            GG(param.ua_, param.ub_, param.uc_, param.ud_, M[index], s[i % 4], ti);
        }
        else if (i % 4 == 1) {
            GG(param.ud_, param.ua_, param.ub_, param.uc_, M[index], s[i % 4], ti);
        }
        else if (i % 4 == 2) {
            GG(param.uc_, param.ud_, param.ua_, param.ub_, M[index], s[i % 4], ti);
        }
        else if (i % 4 == 3) {
            GG(param.ub_, param.uc_, param.ud_, param.ua_, M[index], s[i % 4], ti);
        }
    }
}

void Md5Encode::RoundH(char *data_BIT_OF_GROUP_ptr, ParamDynamic & param) {
    UInt32 *M = reinterpret_cast<UInt32*>(data_BIT_OF_GROUP_ptr);
    int s[] = { 4, 11, 16, 23 };
    for (int i = 0; i < 16; ++i) {
        UInt32 ti = k_ti_num_integer * abs(sin(i + 1 + 32));
        int index = (i * 3 + 5) % 16;
        if (i % 4 == 0) {
            HH(param.ua_, param.ub_, param.uc_, param.ud_, M[index], s[i % 4], ti);
        }
        else if (i % 4 == 1) {
            HH(param.ud_, param.ua_, param.ub_, param.uc_, M[index], s[i % 4], ti);
        }
        else if (i % 4 == 2) {
            HH(param.uc_, param.ud_, param.ua_, param.ub_, M[index], s[i % 4], ti);
        }
        else if (i % 4 == 3) {
            HH(param.ub_, param.uc_, param.ud_, param.ua_, M[index], s[i % 4], ti);
        }
    }
}

void Md5Encode::RoundI(char *data_BIT_OF_GROUP_ptr, ParamDynamic & param) {
    UInt32 *M = reinterpret_cast<UInt32*>(data_BIT_OF_GROUP_ptr);
    int s[] = { 6, 10, 15, 21 };
    for (int i = 0; i < 16; ++i) {
        UInt32 ti = k_ti_num_integer * abs(sin(i + 1 + 48));
        int index = (i * 7 + 0) % 16;
        if (i % 4 == 0) {
            II(param.ua_, param.ub_, param.uc_, param.ud_, M[index], s[i % 4], ti);
        }
        else if (i % 4 == 1) {
            II(param.ud_, param.ua_, param.ub_, param.uc_, M[index], s[i % 4], ti);
        }
        else if (i % 4 == 2) {
            II(param.uc_, param.ud_, param.ua_, param.ub_, M[index], s[i % 4], ti);
        }
        else if (i % 4 == 3) {
            II(param.ub_, param.uc_, param.ud_, param.ua_, M[index], s[i % 4], ti);
        }
    }
}

void Md5Encode::RotationCalculate(char *data_512_ptr, ParamDynamic & param) {
    if (NULL == data_512_ptr) {
        return;
    }
    RoundF(data_512_ptr, param);
    RoundG(data_512_ptr, param);
    RoundH(data_512_ptr, param);
    RoundI(data_512_ptr, param);
    param.ua_ = param.va_last_ + param.ua_;
    param.ub_ = param.vb_last_ + param.ub_;
    param.uc_ = param.vc_last_ + param.uc_;
    param.ud_ = param.vd_last_ + param.ud_;

    param.va_last_ = param.ua_;
    param.vb_last_ = param.ub_;
    param.vc_last_ = param.uc_;
    param.vd_last_ = param.ud_;
}

// 转换成十六进制字符串输出
std::string Md5Encode::GetHexStr(unsigned int num_str) {
    std::string hexstr = "";
    char szch[] = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };
    unsigned char *tmptr = (unsigned char *)&num_str;
    int len = sizeof(num_str);
    // 小端字节序，逆序打印
    for (int i = 0; i < len; i++){
        unsigned char ch = tmptr[i] & 0xF0;
        ch = ch >> 4;
        hexstr.append(1, szch[ch]);
        ch = tmptr[i] & 0x0F;
        hexstr.append(1, szch[ch]);
    }
    return hexstr;
}

// function: Encode
// @param src_info:要加密的信息
// return :加密后的MD5值
std::string Md5Encode::Encode(std::string src_info) {
    ParamDynamic param;
    param.ua_ = kA;
    param.ub_ = kB;
    param.uc_ = kC;
    param.ud_ = kD;
    param.va_last_ = kA;
    param.vb_last_ = kB;
    param.vc_last_ = kC;
    param.vd_last_ = kD;

    std::string result;
    const char *src_data = src_info.c_str();
    char *out_data_ptr = NULL;
    int total_byte = FillData(src_data, strlen(src_data), &out_data_ptr);
    //char * data_BIT_OF_GROUP = out_data_ptr;
    for (int i = 0; i < total_byte / (BIT_OF_GROUP / BIT_OF_BYTE); ++i) {
        char * data_BIT_OF_GROUP = out_data_ptr;
        data_BIT_OF_GROUP += i*(BIT_OF_GROUP / BIT_OF_BYTE);
        RotationCalculate(data_BIT_OF_GROUP, param);
    }
    if (NULL != out_data_ptr) {
        delete[] out_data_ptr, out_data_ptr = NULL;
    }
    result.append(GetHexStr(param.ua_));
    result.append(GetHexStr(param.ub_));
    result.append(GetHexStr(param.uc_));
    result.append(GetHexStr(param.ud_));
    return result;
}