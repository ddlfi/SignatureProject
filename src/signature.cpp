#include "signature.h"

std::vector<uint8_t> XOR_(const std::vector<uint8_t>& a,
                          const std::vector<uint8_t>& b) {
    std::vector<uint8_t> result;
    if (a.size() != b.size()) return result;
    for (auto i = 0; i < a.size(); i++) {
        result.push_back(a[i] ^ b[i]);
    }
    return result;
}

void Signature::keygen() {
    for (auto i = 0; i < 8; i++) {
        rain(skey_[i], rain_msg_, pkey_[i], nullptr, 0);
    }
}

void Signature::treegen() {
    for (int i = 8; i < 16; i++) {
        tree_[i] = pkey_[i - 8];
    }
    int index = 7;
    while (index != 0) {
        hash_1(tree_[2 * index], tree_[2 * index + 1], s_0_, tree_[index],
               nullptr, 0);
        index--;
    }
}

void Signature::hash_1(const std::vector<uint8_t>& input_0,
                       const std::vector<uint8_t>& input_1,
                       const std::vector<uint8_t>& s_byte,
                       std::vector<uint8_t>& output, uint8_t* witness,
                       bool flag) {
    if (flag && witness) {
        (witness, input_0.data(), 32UL);
        memcpy(witness + 32UL, input_1.data(), 32UL);
        memcpy(witness + 64UL, s_byte.data(), 32UL);
        witness += 96UL;
    }
    field::GF2_256 i_0, i_1, s, s_, key, msg, rain_output, result;

    i_0.from_bytes(input_0.data());
    i_1.from_bytes(input_1.data());
    s.from_bytes(s_byte.data());
    s_ = (i_0 + i_1) * s;
    if (flag && witness) {
        s_.to_bytes(witness);
        witness += 32UL;
    }
    key = s_ + i_1;
    msg = s_ + i_0;

    rain(key, msg, rain_output, witness, flag);
    witness += 64UL;

    result = rain_output + msg;
    result.to_bytes(output.data());

    if (flag && witness) {
        result.to_bytes(witness);
    }
}

void Signature::hash_pk_msg(const std::vector<uint8_t>& msg,
                            std::vector<uint8_t>& mu) {
    H1_context_t h1_ctx;
    H1_init(&h1_ctx, lambda_);
    for (auto& pk : pkey_) {
        H1_update(&h1_ctx, pk.data(), pk.size());
    }
    H1_update(&h1_ctx, msg.data(), msg.size());
    H1_final(&h1_ctx, mu.data(), 2 * lambda_bytes_);
}

void Signature::hash_challenge_1(const std::vector<uint8_t>& mu,
                                 const std::vector<uint8_t>& hcom,
                                 const std::vector<uint8_t>& c,
                                 const std::vector<uint8_t>& iv,
                                 std::vector<uint8_t>& chall_1,
                                 unsigned int ell, unsigned int tau) {
    const unsigned int ell_hat_bytes =
        ell / 8 + lambda_bytes_ * 2 + UNIVERSAL_HASH_B;
    H2_context_t h2_ctx;
    H2_init(&h2_ctx, lambda_);
    H2_update(&h2_ctx, mu.data(), lambda_bytes_ * 2);
    H2_update(&h2_ctx, hcom.data(), lambda_bytes_ * 2);
    H2_update(&h2_ctx, c.data(), ell_hat_bytes * (tau - 1));
    H2_update(&h2_ctx, iv.data(), IV_SIZE);
    H2_final(&h2_ctx, chall_1.data(), 5 * lambda_bytes_ + 8);
}

static void hash_challenge_2(std::vector<uint8_t>& chall_2,
                             const std::vector<uint8_t>& chall_1,
                             const std::vector<uint8_t>& u_tilde,
                             const std::vector<uint8_t>& h_v,
                             const std::vector<uint8_t>& d, unsigned int lambda,
                             unsigned int ell) {
    const unsigned int lambda_bytes = lambda / 8;
    const unsigned int ell_bytes = ell / 8;
    const unsigned int u_tilde_bytes = lambda_bytes + UNIVERSAL_HASH_B;

    H2_context_t h2_ctx_1;
    H2_init(&h2_ctx_1, lambda);
    H2_update(&h2_ctx_1, chall_1.data(), 5 * lambda_bytes + 8);
    H2_update(&h2_ctx_1, u_tilde.data(), u_tilde_bytes);
    H2_update(&h2_ctx_1, h_v.data(), 2 * lambda_bytes);
    H2_update(&h2_ctx_1, d.data(), ell_bytes);
    H2_final(&h2_ctx_1, chall_2.data(), 3 * lambda_bytes + 8);
}

static void hash_challenge_3(std::vector<uint8_t>& chall_3,
                             const std::vector<uint8_t>& chall_2,
                             const std::vector<uint8_t>& a_tilde,
                             const std::vector<uint8_t>& b_tilde,
                             unsigned int lambda) {
    const unsigned int lambda_bytes = lambda / 8;

    H2_context_t h2_ctx_2;
    H2_init(&h2_ctx_2, lambda);
    H2_update(&h2_ctx_2, chall_2.data(), 3 * lambda_bytes + 8);
    H2_update(&h2_ctx_2, a_tilde.data(), lambda_bytes);
    H2_update(&h2_ctx_2, b_tilde.data(), lambda_bytes);
    H2_final(&h2_ctx_2, chall_3.data(), lambda_bytes);
}

void Signature::gen_rootkey_iv(const std::vector<uint8_t>& mu,
                               const uint8_t signer_index,
                               std::vector<uint8_t>& rootkey,
                               std::vector<uint8_t>& iv) {
    H3_context_t h3_ctx;
    H3_init(&h3_ctx, lambda_);
    H3_update(&h3_ctx, skey_[signer_index].data(), lambda_bytes_);
    H3_update(&h3_ctx, mu.data(), lambda_bytes_ * 2);
    H3_final(&h3_ctx, rootkey.data(), lambda_bytes_, iv.data());
}

void Signature::gen_witness(uint8_t* witness, uint8_t index) {
    std::vector<uint8_t> tmp;
    rain(skey_[index], rain_msg_, tmp, witness, 1);
    witness += 3 * 32UL;  // 最后一个witness和下一次hash重叠了，因此+3而非4
    index = index + 8;
    while (index != 1) {
        if (index % 2) {
            hash_1(tree_[index], tree_[index - 1], s_1_, tmp, witness, 1);
            witness += 6 * 32UL;
            index = index / 2;
        } else {
            hash_1(tree_[index], tree_[index + 1], s_0_, tmp, witness, 1);
            witness += 6 * 32UL;
            index = index / 2;
        }
    }
}

void Signature::sign(const uint8_t signer_index,
                     const std::vector<uint8_t>& msg) {
    const unsigned int ell = (4 + 6 + 6 + 6) * 256;
    const unsigned int muti_times = 3 + 4 + 4 + 4;
    const unsigned int ell_bytes = ell / 8;
    const unsigned int ell_hat = ell + lambda_ * 2 + UNIVERSAL_HASH_B_BITS;
    const unsigned int ell_hat_bytes = ell_hat / 8;
    std::vector<uint8_t> mu(2 * lambda_bytes_);
    hash_pk_msg(msg, mu);
    std::cout << "1" << std::endl;
    std::vector<uint8_t> rootkey(lambda_bytes_);
    std::vector<uint8_t> iv(iv_size_);
    gen_rootkey_iv(mu, signer_index, rootkey, iv);

    std::vector<uint8_t> hcom(lambda_bytes_ * 2);
    std::vector<vec_com_t> vecCom(params_.tau);
    std::vector<uint8_t> u(ell_hat_bytes);
    std::vector<uint8_t*> V(lambda_);
    V[0] = new uint8_t[lambda_ * ell_hat_bytes];
    for (unsigned int i = 1; i < lambda_; ++i) {
        V[i] = V[0] + i * ell_hat_bytes;
    }
    std::cout << "2" << std::endl;

    std::vector<uint8_t> c((params_.tau - 1) * ell_hat_bytes);
    vole_commit(rootkey.data(), iv.data(), ell_hat, &(params_), hcom.data(),
                vecCom.data(), c.data(), u.data(), V.data());
    std::cout << "3" << std::endl;
    std::vector<uint8_t> chall_1(5 * lambda_bytes_ + 8);
    hash_challenge_1(mu, hcom, c, iv, chall_1, ell, params_.tau);

    std::vector<uint8_t> u_tilde(lambda_bytes_ + UNIVERSAL_HASH_B);
    vole_hash(u_tilde.data(), chall_1.data(), u.data(), ell, lambda_);
    std::cout << "4" << std::endl;
    std::vector<uint8_t> h_v(lambda_bytes_ * 2);
    {
        H1_context_t h1_ctx_1;
        H1_init(&h1_ctx_1, lambda_);
        std::vector<uint8_t> V_tilde(lambda_bytes_ + UNIVERSAL_HASH_B);
        for (unsigned int i = 0; i != lambda_; ++i) {
            // Step 7
            vole_hash(V_tilde.data(), chall_1.data(), V[i], ell, lambda_);
            // Step 8
            H1_update(&h1_ctx_1, V_tilde.data(),
                      lambda_bytes_ + UNIVERSAL_HASH_B);
        }
        // Step: 8
        H1_final(&h1_ctx_1, h_v.data(), lambda_bytes_ * 2);
    }
    std::cout << "5" << std::endl;
    std::vector<uint8_t> witness(ell_bytes);
    gen_witness(witness.data(), signer_index);
    std::vector<uint8_t> d(ell_bytes);
    xor_u8_array(witness.data(), u.data(), d.data(), ell_bytes);
    std::cout << "6" << std::endl;
    std::vector<uint8_t> chall_2(3 * lambda_bytes_ + 8);
    hash_challenge_2(chall_2, chall_1, u_tilde, h_v, d, lambda_, ell);
    std::cout << "7" << std::endl;
    std::vector<field::GF2_256> v_gf_256_vec(ell_hat);
    std::vector<field::GF2_256> v_combined_gf_256_vec(ell_hat / 256);
    convert_vec_to_field(V.data(), v_gf_256_vec.data(), ell_hat, lambda_);
    gen_combined_field_vec(v_gf_256_vec.data(), v_combined_gf_256_vec.data(),
                           ell);
    std::cout << "8" << std::endl;
    std::vector<field::GF2_256> A_0(muti_times);
    std::vector<field::GF2_256> A_1(muti_times);
    path_prove(witness.data(), v_combined_gf_256_vec.data(), rain_msg_,
               A_0.data(), A_1.data());
    std::cout << "9" << std::endl;
    std::vector<uint8_t> chall_3(lambda_bytes_);
    std::vector<uint8_t*> pdec(params_.tau);
    std::vector<uint8_t*> com(params_.tau);
    std::vector<uint8_t> A_0_bytes(muti_times * 32);
    std::vector<uint8_t> A_1_bytes(muti_times * 32);
    for (int i = 0; i < muti_times; i++) {
        A_0[i].to_bytes(A_0_bytes.data() + 32 * i);
        A_1[i].to_bytes(A_1_bytes.data() + 32 * i);
    }
    hash_challenge_3(chall_3, chall_2, A_1_bytes, A_0_bytes, lambda_);
    std::cout << "10" << std::endl;
    for (unsigned int i = 0; i < params_.tau; i++) {
        // Step 20
        uint8_t s_[12];
        ChalDec(chall_3.data(), i, params_.k0, params_.tau0, params_.k1,
                params_.tau1, s_);

        std::cout << "1" << std::endl;
        // Step 21
        const unsigned int depth = i < params_.tau0 ? params_.k0 : params_.k1;
        pdec[i] = new uint8_t[depth * lambda_bytes_];
        com[i] = new uint8_t[2 * lambda_bytes_];
        vector_open(vecCom[i].k, vecCom[i].com, s_, pdec[i], com[i], depth,
                    lambda_bytes_);
        vec_com_clear(&vecCom[i]);
    }
    std::cout << "11" << std::endl;
    ///////////////////////////////////////////////////////////////////////
    std::vector<uint8_t*> Q(lambda_);
    Q[0] = new uint8_t[lambda_ * ell_hat_bytes];
    for (unsigned int i = 1; i < lambda_; ++i) {
        Q[i] = Q[0] + i * ell_hat_bytes;
    }
    vole_reconstruct(iv.data(), chall_3.data(), pdec.data(), com.data(),
                     hcom.data(), Q.data(), ell_hat, &params_);

    std::vector<uint8_t*> Q_(lambda_);
    Q_[0] = new uint8_t[lambda_ * ell_hat_bytes];
    for (unsigned int i = 1; i < lambda_; ++i) {
        Q_[i] = Q_[0] + i * ell_hat_bytes;
    }
    std::cout << "12" << std::endl;
    std::vector<uint8_t*> Dtilde(lambda_);
    Dtilde[0] = new uint8_t[lambda_ * (lambda_bytes_ + UNIVERSAL_HASH_B)];
    for (unsigned int i = 1; i < lambda_; ++i) {
        Dtilde[i] = Dtilde[0] + i * (lambda_bytes_ + UNIVERSAL_HASH_B);
    }

    unsigned int Dtilde_idx = 0;
    unsigned int q_idx = 0;
    for (unsigned int i = 0; i < params_.tau; i++) {
        const unsigned int depth = i < params_.tau0 ? params_.k0 : params_.k1;

        // Step 11
        uint8_t delta[MAX_DEPTH];
        ChalDec(chall_3.data(), i, params_.k0, params_.tau0, params_.k1,
                params_.tau1, delta);
        // Step 16
        for (unsigned int j = 0; j != depth; ++j, ++Dtilde_idx) {
            // for scan-build
            assert(Dtilde_idx < lambda_);
            masked_xor_u8_array(Dtilde[Dtilde_idx], u_tilde.data(),
                                Dtilde[Dtilde_idx], delta[j],
                                lambda_bytes_ + UNIVERSAL_HASH_B);
        }

        if (i == 0) {
            // Step 8
            memcpy(Q_[q_idx], Q[q_idx], ell_hat_bytes * depth);
            q_idx += depth;
        } else {
            // Step 14
            for (unsigned int d = 0; d < depth; ++d, ++q_idx) {
                masked_xor_u8_array(Q[q_idx],
                                    c.data() + (i - 1) * ell_hat_bytes,
                                    Q_[q_idx], delta[d], ell_hat_bytes);
            }
        }
    }

    for (unsigned int i = 0, col = 0; i < params_.tau; i++) {
        unsigned int depth = i < params_.tau0 ? params_.k0 : params_.k1;
        uint8_t decoded_challenge[MAX_DEPTH];
        ChalDec(chall_3.data(), i, params_.k0, params_.tau0, params_.k1,
                params_.tau1, decoded_challenge);
        for (unsigned int j = 0; j < depth; j++, ++col) {
            if (decoded_challenge[j] == 1) {
                xor_u8_array(d.data(), Q_[col], Q_[col], ell_bytes);
            }
        }
    }

    std::vector<field::GF2_256> q_gf_256_vec(ell);
    std::vector<field::GF2_256> q_combined_gf_256_vec(ell / 256);
    convert_vec_to_field(Q_.data(), q_gf_256_vec.data(), ell, lambda_);
    gen_combined_field_vec(q_gf_256_vec.data(), q_combined_gf_256_vec.data(),
                           ell);

    field::GF2_256 delta_field;
    delta_field.from_bytes(chall_3.data());

    std::vector<field::GF2_256> B(muti_times);
    path_verify(q_combined_gf_256_vec.data(), delta_field, rain_msg_, B.data());

    for (int i = 0; i < ell / 256; i++) {
        field::GF2_256 test_field;
        test_field.from_bytes(witness.data() + 32UL * i);
        if (test_field * delta_field + v_combined_gf_256_vec[i] ==
            q_combined_gf_256_vec[i]) {
            std::cout << "111111111here" << std::endl;
        } else {
            std::cout << "2222222" << std::endl;
        }
    }



    if ((q_gf_256_vec[15] == v_gf_256_vec[15] + delta_field &&
         (witness[1] >> 1 & 0x01 == 0x01)) ||
        (q_gf_256_vec[15] == v_gf_256_vec[15] &&
         (witness[1] >> 1 & 0x01 == 0x00))) {
        std::cout << "111111111111111111" << std::endl;
    } else {
        std::cout << "2222222222" << std::endl;
    }

    if (A_0[1] + delta_field * A_1[1] == B[1]) {
        std::cout << "111111111111111111" << std::endl;
    } else {
        std::cout << "2222" << std::endl;
    }
    // unsigned int running_idx = 0;
    // std::vector<uint8_t> b(params_.k0);
    // for (unsigned int i = 0; i < params_.tau; ++i) {
    //     const uint32_t depth = 8;

    //     ChalDec(chall_3.data(), i, params_.k0, params_.tau0,
    //             params_.k1, params_.tau1, b.data());
    //     for (unsigned int j = 0; j != depth; ++j, ++running_idx) {
    //         for (unsigned int inner = 0; inner != ell_bytes; ++inner) {
    //             if (b[j]) {
    //                 // need to correct the vole correlation
    //                 if (i > 0) {
    //                     std::cout<<"11  "<<((Q_[(running_idx)][inner] ^
    //                                 witness[inner]) ==
    //                                 V[(running_idx)][inner])<<std::endl;
    //                 } else {
    //                     std::cout<<"22  "<<((Q_[(running_idx)][inner] ^
    //                     witness[inner]) ==
    //                                V[(running_idx)][inner])<<std::endl;
    //                 }
    //             } else {
    //                 std::cout<<"33  "<<(Q_[(running_idx)][inner] ==
    //                            V[(running_idx)][inner])<<std::endl;
    //             }
    //         }
    //     }
    // }
}

void Signature::verify() {}