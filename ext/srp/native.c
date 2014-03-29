#include <ruby.h>
#include "srp.h"

/* Helper function to convert a byte array to a hexadecimal string */
void bytes_to_hex(unsigned char *bytes, unsigned int len, char **hex)
{
  
  char          hex_str[]= "0123456789abcdef";
  unsigned int  i;

  *hex = (char *)malloc(len * 2 + 1);
  (*hex)[len * 2] = 0;

  if (!hex)
    return;
  
  for (i = 0; i < len; i++) {
    (*hex)[i * 2 + 0] = hex_str[bytes[i] >> 4  ];
    (*hex)[i * 2 + 1] = hex_str[bytes[i] & 0x0F];
  }
    
}

/* Helper function and macro to convert a hex string to a byte array */
#define digit_to_int(d) ((d) <= '9' ? (d) - '0' : (d) - 'a' + 10)
 
void hex_to_bytes(char* hex, unsigned char ** bytes) {
  
  int i;
  char a, b;
  
  int hex_len = (int) strlen(hex);
  int bin_len = hex_len / 2;

  *bytes = (unsigned char*) malloc(bin_len);

  for (i = 0; i < bin_len; ++i) {
    a = hex[2 * i + 0]; b = hex[2 * i + 1];
    (*bytes)[i] = (digit_to_int(a) << 4) | digit_to_int(b);
  }
  
}

const char* get_as_string(VALUE self, char* ivar) {
  
  VALUE val = rb_iv_get(self, ivar);
  return StringValue(val);
  
}

const unsigned char* get_hex_as_bytes(VALUE self, char* ivar) {
  
  const char* hex = get_as_string(self, ivar);
  const unsigned char * bytes;
  hex_to_bytes(hex, &bytes);
  
  return  bytes;
  
}

const unsigned char* hex_val_to_bytes(VALUE val) {
  
  const char* str_val = StringValue(val);
  const unsigned char * bytes;
  hex_to_bytes(str_val, &bytes);
  
  return bytes;
  
}

static VALUE csrp_verifier;
typedef struct SRPVerifier SRPVerifier;
  
SRP_HashAlgorithm unwrap_hash_fn(VALUE hash_fn) {
  return (SRP_HashAlgorithm) NUM2INT(hash_fn);
}

SRP_NGType unwrap_ng_type(VALUE ng_type) {
  return (SRP_NGType) NUM2INT(ng_type);
}

static VALUE csrp;
static VALUE csrp_client;
static VALUE csrp_server;

static VALUE client_initialize(VALUE self, VALUE hash_fn2, VALUE ng_type2)
{	
  SRP_HashAlgorithm hash_fn = SRP_SHA1;
  SRP_NGType        ng_type = SRP_NG_1024;
  
  rb_iv_set(self, "@hash_fn", INT2NUM((int) hash_fn));
  rb_iv_set(self, "@ng_type", INT2NUM((int) ng_type));
  
  return self;
}

static VALUE client_set_salt(VALUE self, VALUE salt) {
  rb_iv_set(self, "@salt", salt);
  return self;
}

/* Create a salt+verification key for the user's password. The salt and
 * key need to be computed at the time the user's password is set and
 * must be stored by the server-side application for use during the
 * authentication process.
 */
static VALUE client_create_verifier(VALUE self, VALUE username_val, VALUE password_val) {
  
	rb_iv_set(self, "@username", username_val);
	rb_iv_set(self, "@password", password_val);
	
  const char * username = StringValue(username_val);
  const char * password = StringValue(password_val);
  
  SRP_HashAlgorithm alg = unwrap_hash_fn(rb_iv_get(self, "@hash_fn"));
  SRP_NGType ng_type = unwrap_ng_type(rb_iv_get(self, "@hash_fn"));

  int len_s   = 0;
  int len_v   = 0;

  const unsigned char * bytes_v = 0;
  
  const unsigned char* bytes_s = get_hex_as_bytes(self, "@salt");
  
  srp_create_salted_verification_key( alg, ng_type, username, 
                                      (const unsigned char *)password, 
                                      strlen(password), bytes_s,
                                      &bytes_v, &len_v,
                                      NULL, NULL );
                                      
  char * verifier_hex;
  bytes_to_hex(bytes_v, len_v, &verifier_hex);
  VALUE verifier = rb_str_new((const char*) verifier_hex, strlen(verifier_hex));
  rb_iv_set(self, "@verifier", verifier);
               
  return self;
  
}

static VALUE client_start_authentication(VALUE self) {
  
  struct SRPUser     * usr;
  
  const char * username = get_as_string(self, "@username");
  const char * password = get_as_string(self, "@password");
  
  SRP_HashAlgorithm alg = unwrap_hash_fn(rb_iv_get(self, "@hash_fn"));
  SRP_NGType ng_type = unwrap_ng_type(rb_iv_get(self, "@hash_fn"));
  
  /* Begin authentication process */
  usr =  srp_user_new( alg, ng_type, username, 
                       (const unsigned char *)password, 
                       strlen(password), NULL, NULL );

                    
  const char * auth_username = 0;
  const unsigned char * bytes_A = 0;
  int len_A   = 0;

  srp_user_start_authentication( usr, &auth_username, &bytes_A, &len_A );

  char * A_hex;
  bytes_to_hex(bytes_A, len_A, &A_hex);
  VALUE A = rb_str_new((const char*) A_hex, strlen(A_hex));
  rb_iv_set(self, "@A", A);
  
  return self;
  
}

static VALUE client_process_challenge(VALUE self, VALUE B) {
  
  struct SRPUser     * usr;
  
  SRP_HashAlgorithm alg = unwrap_hash_fn(rb_iv_get(self, "@hash_fn"));
  SRP_NGType ng_type = unwrap_ng_type(rb_iv_get(self, "@hash_fn"));
  
  // Get username and password and convert to char*
  const char * username = get_as_string(self, "@username");
  const char * password = get_as_string(self, "@password");
  
  //  Get salt and convert to byte array
  const unsigned char* bytes_s = get_hex_as_bytes(self, "@salt");
  int len_s = (int) sizeof(bytes_s);
  
  // Get B and convert to byte array
  const unsigned char* bytes_B = hex_val_to_bytes(B);
  int len_B = (int) sizeof(bytes_B);
  
  // Build user
  usr =  srp_user_new( alg, ng_type, username, 
                       (const unsigned char *)password, 
                       strlen(password), NULL, NULL );
  
  int len_M;
  const unsigned char * bytes_M;
                     
  /* Host -> User: (bytes_s, bytes_B) */
  srp_user_process_challenge( usr, bytes_s, len_s, bytes_B, len_B, &bytes_M, &len_M );

  if ( !bytes_M ) {
     printf("User SRP-6a safety check violation!\n");
     return Qfalse;
  }
  
  char * M_hex;
  bytes_to_hex(bytes_M, len_M, &M_hex);
  VALUE M = rb_str_new((const char*) M_hex, strlen(M_hex));
  rb_iv_set(self, "@M", M);

  return self;

}

static VALUE server_initialize(VALUE self, VALUE hash_fn2, VALUE ng_type2)
{	
  
  if (1) {
    
    SRP_HashAlgorithm hash_fn = SRP_SHA1;
    SRP_NGType        ng_type = SRP_NG_1024;

    rb_iv_set(self, "@hash_fn", INT2NUM((int) hash_fn));
    rb_iv_set(self, "@ng_type", INT2NUM((int) ng_type));

  } else {
    
    rb_iv_set(self, "@hash_fn", hash_fn2);
    rb_iv_set(self, "@ng_type", ng_type2);
    
  }
  
  return self;
}

/* Set username, salt and verifier */
static VALUE server_set_credentials(VALUE self, VALUE username, VALUE salt_hex, VALUE verifier_hex)
{
	
	rb_iv_set(self, "@username", username);
	rb_iv_set(self, "@salt", salt_hex);
	rb_iv_set(self, "@verifier", verifier_hex);
	
  return self;
}

static VALUE server_start_authentication(VALUE self, VALUE A) {
  
  struct SRPVerifier * ver;
  
  SRP_HashAlgorithm alg = unwrap_hash_fn(rb_iv_get(self, "@hash_fn"));
  SRP_NGType ng_type = unwrap_ng_type(rb_iv_get(self, "@ng_type"));

  // Get username from instance
  VALUE username_val = get_as_string(self, "@username");
  const char* username = StringValue(username_val);
  
  // Get hex salt and convert to bytes
  const unsigned char* bytes_s = get_hex_as_bytes(self, "@salt");
  int len_s = (int) sizeof(bytes_s);
  
  // Get hex verifier and convert to bytes
  const unsigned char* bytes_v = get_hex_as_bytes(self, "@verifier");
  int len_v = (int) sizeof(bytes_v);
  
  // Convert client A value to bytes
  const unsigned char* bytes_A = hex_val_to_bytes(A);
  int len_A = (int) sizeof(bytes_A);
    
  // Create buffer for server B value
  const unsigned char * bytes_B;
  int len_B = 0;
  
  /* User -> Host: (username, bytes_A) */
  ver =  srp_verifier_new(alg, ng_type, username, bytes_s, len_s, bytes_v, len_v, 
                          bytes_A, len_A, &bytes_B, &len_B, NULL, NULL);

  // Store the 
  char * B_hex;
  bytes_to_hex(bytes_B, len_B, &B_hex);
  VALUE B = rb_str_new((const char*) B_hex, strlen(B_hex));
  rb_iv_set(self, "@B", B);
  
  VALUE verifier = Data_Wrap_Struct(csrp_verifier, 0, free, ver);
  
  rb_iv_set(self, "@verifier", verifier);
  
}

static VALUE server_verify_session(VALUE self, VALUE M) {
  
  VALUE verifier = rb_iv_get(self, "@verifier");
  
  struct SRPVerifier * ver;
  Data_Get_Struct(verifier, SRPVerifier, ver);
  
  // Convert client M value to bytes
  const unsigned char* bytes_M = hex_val_to_bytes(M);
  
  // Create buffer for H AMK
  const unsigned char *bytes_HAMK;
  
  // User -> Host: (bytes_M)
  srp_verifier_verify_session( ver, bytes_M, &bytes_HAMK );

  if ( !bytes_HAMK ) {
     printf("User authentication failed!\n");
     return Qfalse;
  }
  
  char * HAMK_hex;
  bytes_to_hex(bytes_HAMK, (int) sizeof(bytes_HAMK), &HAMK_hex);
  VALUE HAMK = rb_str_new((const char*) HAMK_hex, strlen(HAMK_hex));
  rb_iv_set(self, "@HAMK", HAMK);

  return self;
  
}

static VALUE csrp_test(VALUE self) {
/*

  // Host -> User: (HAMK)
  srp_user_verify_session( usr, bytes_HAMK );

  if ( !srp_user_is_authenticated(usr) ) {
     printf("Server authentication failed!\n");
     goto auth_failed;
  }
  
  return Qtrue;

auth_failed:
  srp_verifier_delete( ver );
  srp_user_delete( usr );

  free( (char *)bytes_s );
  free( (char *)bytes_v );

  return Qfalse;
*/
  return Qnil;
  
};

void Init_native(void) {
  
	csrp = rb_define_module("CSRP");
	
	csrp_verifier = rb_define_class_under(csrp, "Verifier", rb_cObject);
	
	csrp_client = rb_define_class_under(csrp, "Client", rb_cObject);
	
	rb_define_method(csrp_client, "initialize", client_initialize, 2);
	rb_define_method(csrp_client, "salt=", client_set_salt, 1);
  rb_define_method(csrp_client, "create_verifier", client_create_verifier, 2);
  rb_define_method(csrp_client, "start_authentication", client_start_authentication, 0);
  rb_define_method(csrp_client, "process_challenge", client_process_challenge, 1);
  
	rb_attr(csrp_client, rb_intern("salt"), 1, 1, 1);
	rb_attr(csrp_client, rb_intern("verifier"), 1, 1, 1);
	rb_attr(csrp_client, rb_intern("A"), 1, 1, 1);
	rb_attr(csrp_client, rb_intern("M"), 1, 1, 1);
	
	csrp_server = rb_define_class_under(csrp, "Server", rb_cObject);
	
	rb_define_method(csrp_server, "initialize", server_initialize, 2);
	rb_define_method(csrp_server, "set_credentials", server_set_credentials, 3);
	rb_define_method(csrp_server, "start_authentication", server_start_authentication, 1);
	rb_define_method(csrp_server, "verify_session", server_verify_session, 1);
	rb_attr(csrp_server, rb_intern("B"), 1, 1, 1);
	rb_attr(csrp_server, rb_intern("HAMK"), 1, 1, 1);
	
}
