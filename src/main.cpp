#include <cstdint>
#include <iostream>
#include "signature.h"


int main() {

    gen_field_base(field_base);

    Signature signer(64);
    std::vector<uint8_t> msg = {0x11,0x22};
    // gen_field_base(field_base);
    // std::vector<uint8_t> witness(22*256/8);
    // signer.gen_witness(witness.data(), 0);

    // field::GF2_256 key,s1,s2,s3,in_;
    // key.from_bytes(witness.data());
    // s1.from_bytes(witness.data()+32UL);
    // s2.from_bytes(witness.data()+64UL);
    // s3.from_bytes(witness.data()+96UL);

    // std::vector<uint8_t> in = {
    //     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    //     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    //     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

    // in_.from_bytes(in.data());

    // if(s1.inverse() == key + roundconst[0] + in_) std::cout<<"1 pass"<<std::endl;

    // if(s2.inverse() == s1.multiply_with_transposed_GF2_matrix(matrix_transposed[0])+key+roundconst[1]) std::cout<<"2 pass"<<std::endl;

    // s3 += key;
    // if(s3.inverse() == s2.multiply_with_transposed_GF2_matrix(matrix_transposed[1])+key+roundconst[2]) std::cout<<"3 pass"<<std::endl;
    signature_t sig;

    signer.sign(41,msg,&sig);

    if(signer.verify(msg,&sig)){
        std::cout<<"pass"<<std::endl;
    }else{
        std::cout<<"fail"<<std::endl;
    }
    return 0;
}