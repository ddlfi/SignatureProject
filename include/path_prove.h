#include <iostream>

#include "field.h"
#include "rain.h"
#include "utils.h"

void rain_enc_forward_256_1(const uint8_t* witness,
                            const std::vector<uint8_t>& in,
                            field::GF2_256* bf_y);

void rain_enc_forward_256_prover(field::GF2_256* v, field::GF2_256* v_vec,
                                 field::GF2_256* bf_y);

void rain_enc_forward_256_verifier(field::GF2_256* q, field::GF2_256* q_vec,
                                   field::GF2_256 delta,
                                   const std::vector<uint8_t>& in,
                                   field::GF2_256* bf_y);

void rain_enc_backword_256_1(const uint8_t* witness, field::GF2_256* bf_y);

void rain_enc_backword_256_prover(field::GF2_256* v, field::GF2_256* bf_y);

void rain_enc_backword_256_verifier(field::GF2_256* q, field::GF2_256* bf_y);

void rain_enc_constrain_256_prover(field::GF2_256* v, field::GF2_256* v_vec,
                                   const uint8_t* witness,
                                   const std::vector<uint8_t>& in,
                                   field::GF2_256* A_0, field::GF2_256* A_1);

void rain_enc_constrain_256_verifier(field::GF2_256* q, field::GF2_256* q_vec,
                                     field::GF2_256 delta,
                                     const std::vector<uint8_t>& in,
                                     field::GF2_256* B);

void hash_forward_256_1(const uint8_t* witness, field::GF2_256* bf_y,
                        field::GF2_256* muti_gate_input);

void hash_forward_256_prover(field::GF2_256* v, field::GF2_256* v_vec,
                             field::GF2_256* bf_y,
                             field::GF2_256* muti_gate_input);

void hash_forward_256_verifier(field::GF2_256* q, field::GF2_256* q_vec,
                               field::GF2_256 delta, field::GF2_256* bf_y,
                               field::GF2_256* muti_gate_input);

void hash_backword_256_1(const uint8_t* witness, field::GF2_256* bf_y,
                         field::GF2_256* muti_gate_output);

void hash_backword_256_prover(field::GF2_256* v, field::GF2_256* bf_y,
                              field::GF2_256* muti_gate_output);

void hash_backword_256_verifier(field::GF2_256* q, field::GF2_256* bf_y,
                                field::GF2_256* muti_gate_output);

void hash_constrain_256_prover(field::GF2_256* v, field::GF2_256* v_vec,
                               const uint8_t* witness, field::GF2_256* A_0,
                               field::GF2_256* A_1);

void hash_constrain_256_verifier(field::GF2_256* q, field::GF2_256* q_vec,
                                 field::GF2_256 delta, field::GF2_256* B);

void path_prove(const uint8_t* witness, field::GF2_256* v,
                field::GF2_256* v_vec, const std::vector<uint8_t>& in,
                field::GF2_256* A_0, field::GF2_256* A_1,
                unsigned int hash_times);

void path_verify(field::GF2_256* q, field::GF2_256* q_vec, field::GF2_256 delta,
                 const std::vector<uint8_t>& in, field::GF2_256* B,
                 unsigned int hash_times);

void convert_vec_to_field(uint8_t** vec, field::GF2_256* field_vec,
                          const unsigned int ell, const unsigned int lambda);

void gen_combined_field_vec(field::GF2_256* field_vec,
                            field::GF2_256* combined_field_vec,
                            const unsigned int ell);