### A2L源码分析

### Random Puzzle

* PSetup(1*λ*)

  ```c
  int generate_cl_params(cl_params_t params);
  int generate_keys_and_write_to_file(const cl_params_t params);
  ```

* PGen(pp*, ζ*)

  ```c
  int cl_enc(cl_ciphertext_t ciphertext,
  					 const GEN plaintext,
  					 const cl_public_key_t public_key,
  					 const cl_params_t params);
  int promise_init_handler(tumbler_state_t state, void *socket, uint8_t *data);
  ```

* PSolve(td*, Z*)

  ```c
  int cl_dec(GEN *plaintext,
  					 const cl_ciphertext_t ciphertext,
  					 const cl_secret_key_t secret_key,
  					 const cl_params_t params);
  int payment_init_handler(tumbler_state_t state, void *socket, uint8_t *data);
  ```

* PRand(pp*, Z*)

  ```c
  
  int puzzle_share(bob_state_t state, void *socket);
  ```

  

