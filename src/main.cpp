/*
 *  SPDX-License-Identifier: MIT
//  */

// #include "vole.h"
// #include "instances.h"
// #include "randomness.h"
// #include "universal_hashing.h"
// #include "signature.h"

// #include <iostream>
// #include <cmath>
// #include <array>
// #include <vector>

// namespace {
//   constexpr std::array<uint8_t, 32> rootKey{
//       0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
//       0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
//       0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
//   };
//   constexpr std::array<uint8_t, 16> iv{};
// } // namespace

// int main(){
//     // uint8_t chal      = 0x42;
//     // uint8_t chal_b[8] = {0};
//     // ChalDec(&chal, 0, 8, 1, 0, 0, chal_b);
//     // std::cout<<NumRec(8,chal_b)<<' '<<chal<<std::endl;

//     // Signature signer;
//     unsigned int lambda = 256;
//     unsigned int lambdaBytes = 256/8;
//     unsigned int k0 = 8;
//     unsigned int k1 = 8;
//     unsigned int tau = 32;
//     std::vector<uint8_t> hcom, hcomRec, u, b, chal, c;
//     hcom.resize(lambdaBytes * 2);
//     hcomRec.resize(lambdaBytes * 2);
//     u.resize(lambdaBytes);
//     b.resize(MAX(k0,k1), 0);
//     chal.resize(lambdaBytes);
//     rand_bytes(chal.data(), chal.size());
//     c.resize((tau - 1) * lambdaBytes);
//     std::vector<vec_com_t> vec_com;
//     vec_com.resize(tau);
//     std::vector<uint8_t*> v, q, pdec, com_j;
//     v.resize(lambda);
//     q.resize(lambda);
//     pdec.resize(tau);
//     com_j.resize(tau);
//     v[0] = new uint8_t[lambda * lambdaBytes];
//     q[0] = new uint8_t[lambda * lambdaBytes];
//     for (unsigned int i = 1; i < lambda; ++i) {
//       v[i] = v[0] + i * lambdaBytes;
//       q[i] = q[0] +[ i * lambdaBytes;]
//     }
//     paramset_t params;
//     params.lambda = 256;
//     params.k1 = 8;
//     params.k0 = 8;
//     params.tau0 = 0;
//     params.tau1 = 32;
//     params.tau = 32;
//     vole_commit(rootKey.data(), iv.data(), lambda, &params, hcom.data(),
//     vec_com.data(), c.data(),
//                 u.data(), v.data());

//     unsigned int running_idx = 0;
//     for (uint32_t i = 0; i < params.tau; i++) {
//       const uint32_t depth =
//           (i < params.tau0) ? params.k0 : params.k1;

//       pdec[i]  = new uint8_t[depth * lambdaBytes];
//       com_j[i] = new uint8_t[lambdaBytes * 2];

//       ChalDec(chal.data(), i, params.k0, params.tau0, params.k1,
//               params.tau1, b.data());
//       vector_open(vec_com[i].k, vec_com[i].com, b.data(), pdec[i], com_j[i],
//       depth, lambdaBytes); vec_com_clear(&vec_com[i]);
//     }

//     vole_reconstruct(iv.data(), chal.data(), pdec.data(), com_j.data(),
//     hcomRec.data(), q.data(),
//                      lambda, &params);
//         for (unsigned int i = 0; i < params.tau; ++i) {
//       const uint32_t depth =
//           (i < params.tau0) ? params.k0 : params.k1;

//       ChalDec(chal.data(), i, params.k0, params.tau0, params.k1,
//               params.tau1, b.data());
//       for (unsigned int j = 0; j != depth; ++j, ++running_idx) {
//         for (unsigned int inner = 0; inner != lambdaBytes; ++inner) {
//           if (b[j]) {
//             // need to correct the vole correlation
//             if (i > 0) {
//               std::cout<<((q[(running_idx)][inner] ^ c[(i - 1) * lambdaBytes
//               + inner] ^
//                           u[inner]) == v[(running_idx)][inner])<<std::endl;
//             } else {
//               std::cout<<((q[(running_idx)][inner] ^ u[inner]) ==
//               v[(running_idx)][inner])<<std::endl;
//             }
//           } else {
//             std::cout<<(q[(running_idx)][inner] ==
//             v[(running_idx)][inner])<<std::endl;
//           }
//         }
//       }
//     }
//     return 0;
// }
#include <cstdint>
#include <iostream>
#include "signature.h"


int main() {

    gen_field_base(field_base);

    Signature signer;
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

    signer.sign(0,msg);

    return 0;
}