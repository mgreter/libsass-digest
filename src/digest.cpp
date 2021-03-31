#include <cstdlib>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <fstream>
#include <string>
#include "sass.h"
#include "crc.h"
#include "md5.h"

#define BUFFERSIZE 1024
#include "b64/encode.hpp"

std::string md5s(const std::string& text, struct SassCompiler* comp, void*)
{
  MD5 digester;
  digester.update(text.c_str(), text.length());
  digester.finalize();
  return digester.hexdigest();
}

struct SassValue* file_not_found(const std::string& file)
{
  std::string err("File not found: ");
  err += file; // add the filename
  return sass_make_error(err.c_str());
}

struct SassValue* md5f(const std::string& file, struct SassCompiler* comp, void*)
{
  char *path = sass_compiler_find_file(file.c_str(), comp);
  if (*path == '\0') {
    std::free(path);
    return sass_make_error("No filename given");
  }
  else {
    char in[1024];
    MD5 digester;
    std::ifstream fh;
    fh.open(path, std::ios::binary);
    std::free(path);
    if (fh.fail()) return file_not_found(file);
    while(fh.read(in, sizeof(in))) {
      std::streamsize s = fh.gcount();
      digester.update(in, s);
    }
    std::streamsize s = fh.gcount();
    digester.update(in, s);
    digester.finalize();
    std::string rv(digester.hexdigest());
    return sass_make_string(rv.c_str(), false);
  }
}

std::string crc16s(const std::string& text, struct SassCompiler* comp, void*)
{
  short int crc = 0xFFFF;
  crc = crc16(text.c_str(), text.length(), crc);
  std::stringstream ss;
  ss << std::setfill('0')
     << std::setw(2)
     << std::hex
     << ((crc & 0x00FF) >> 0)
      << ((crc & 0xFF00) >> 8);
  return ss.str();
}

std::string crc32s(const std::string& text, struct SassCompiler* comp, void*)
{
  unsigned long int crc = 0xFFFFFFFF;
  crc = crc32buf(text.c_str(), text.length(), crc);
  std::stringstream ss;
  ss << std::setfill('0')
     << std::setw(8)
     << std::hex
     << (0xFFFFFFFF & crc);
  return ss.str();
}

struct SassValue* crc16f(const std::string& file, struct SassCompiler* comp, void*)
{
  char *path = sass_compiler_find_file(file.c_str(), comp);
  if (*path == '\0') {
    std::free(path);
    return sass_make_error("No filename given");
  }
  else {
    char in[1024];
    std::ifstream fh;
    short int crc = 0xFFFF;
    fh.open(path, std::ios::binary);
    std::free(path);
    if (fh.fail()) return file_not_found(file);
    while(fh.read(in, sizeof(in))) {
      std::streamsize s = fh.gcount();
      crc = crc16(in, s, crc);
    }
    std::streamsize s = fh.gcount();
    crc = crc16(in, s, crc);
    std::stringstream ss;
    ss << std::setfill('0')
       << std::setw(2)
       << std::hex
       << ((crc & 0x00FF) >> 0)
       << ((crc & 0xFF00) >> 8);
    std::string rv(ss.str());
    return sass_make_string(rv.c_str(), false);
  }
}

struct SassValue* crc32f(const std::string& file, struct SassCompiler* comp, void*)
{
  char *path = sass_compiler_find_file(file.c_str(), comp);
  if (*path == '\0') {
    std::free(path);
    return sass_make_error("No filename given");
  }
  else {
    char in[1024];
    std::ifstream fh;
    unsigned long int crc = 0xFFFFFFFF;
    fh.open(path, std::ios::binary);
    std::free(path);
    if (fh.fail()) return file_not_found(file);
    while(fh.read(in, sizeof(in))) {
      std::streamsize s = fh.gcount();
      crc = crc32buf(in, s, crc);
    }
    std::streamsize s = fh.gcount();
    crc = crc32buf(in, s, crc);
    std::stringstream ss;
    ss << std::setfill('0')
       << std::setw(8)
       << std::hex
       << (0xFFFFFFFF & crc);
    std::string rv(ss.str());
    return sass_make_string(rv.c_str(), false);
  }
}

std::string base64s(const std::string& text, struct SassCompiler* comp, void*)
{
  int len = 0;
  char out[1368];
  size_t size = 1024;
  base64::encoder enc;
  std::stringstream ss;
  const char* in = text.c_str();
  for (size_t i = 0, L = text.length(); i < L; i += size) {
    if (L < i + size) size = L - i;
    len = enc.encode(in, size, out);
    ss << std::string(out, out + len);
    in += size;
  }
  // finalize base64 string
  len = enc.encode_end(out);
  ss << std::string(out, out + len);
  // return string instance
  return ss.str();
}

struct SassValue* base64f(const std::string& file, struct SassCompiler* comp, void*)
{
  char *path = sass_compiler_find_file(file.c_str(), comp);
  if (*path == '\0') {
    std::free(path);
    return sass_make_error("No filename given");
  }
  else {
    int len = 0;
    char in[1024];
    char out[1368];
    std::ifstream fh;
    base64::encoder enc;
    fh.open(path, std::ios::binary);
    std::free(path);
    if (fh.fail()) return file_not_found(file);
    std::stringstream ss;
    // read into chunks
    while(fh.read(in, sizeof(in))) {
      // encode the readed part
      std::streamsize s = fh.gcount();
      len = enc.encode(in, s, out);
      ss << std::string(out, out + len);
    }
    // encode the final part
    std::streamsize s = fh.gcount();
    len = enc.encode(in, s, out);
    ss << std::string(out, out + len);
    // finalize base64 string
    len = enc.encode_end(out);
    ss << std::string(out, out + len);
    // return string instance
    std::string rv(ss.str());
    return sass_make_string(rv.c_str(), false);
  }
}

// most functions are very simple
#define IMPLEMENT_STR_FN(fn) \
struct SassValue* fn_##fn(struct SassValue* s_args, struct SassCompiler* comp, void* cookie) \
{ \
  if (!sass_value_is_list(s_args)) { \
    return sass_make_error("Invalid arguments for " #fn); \
  } \
  if (sass_list_get_size(s_args) != 1) { \
    return sass_make_error("Exactly one arguments expected for " #fn); \
  } \
  struct SassValue* inp = sass_list_get_value(s_args, 0); \
  if (!sass_value_is_string(inp)) { \
    return sass_make_error("You must pass a string into " #fn); \
  } \
  const char* inp_str = sass_string_get_value(inp); \
  std::string rv = fn(inp_str, comp, cookie); \
  return sass_make_string(rv.c_str(), false); \
} \

// string digest functions
IMPLEMENT_STR_FN(md5s)
IMPLEMENT_STR_FN(crc16s)
IMPLEMENT_STR_FN(crc32s)
IMPLEMENT_STR_FN(base64s)

// most functions are very simple
#define IMPLEMENT_FILE_FN(fn) \
struct SassValue* fn_##fn(struct SassValue* s_args, struct SassCompiler* comp, void* cookie) \
{ \
  if (!sass_value_is_list(s_args)) { \
    return sass_make_error("Invalid arguments for " #fn); \
  } \
  if (sass_list_get_size(s_args) != 1) { \
    return sass_make_error("Exactly one arguments expected for " #fn); \
  } \
  struct SassValue* inp = sass_list_get_value(s_args, 0); \
  if (!sass_value_is_string(inp)) { \
    return sass_make_error("You must pass a string into " #fn); \
  } \
  const char* inp_str = sass_string_get_value(inp); \
  return fn(inp_str, comp, cookie); \
} \

// file digest functions
IMPLEMENT_FILE_FN(md5f)
IMPLEMENT_FILE_FN(crc16f)
IMPLEMENT_FILE_FN(crc32f)
IMPLEMENT_FILE_FN(base64f)

// return version of libsass we are linked against
extern "C" const char* ADDCALL libsass_get_version() {
  return libsass_version();
}

// entry point for libsass to request custom functions from plugin
extern "C" void ADDCALL libsass_init_plugin(struct SassCompiler* compiler)
{

  // string digest functions
  sass_compiler_add_custom_function(compiler, sass_make_function("md5($x)", fn_md5s, 0));
  sass_compiler_add_custom_function(compiler, sass_make_function("crc16($x)", fn_crc16s, 0));
  sass_compiler_add_custom_function(compiler, sass_make_function("crc32($x)", fn_crc32s, 0));
  sass_compiler_add_custom_function(compiler, sass_make_function("base64($x)", fn_base64s, 0));

  // file digest functions
  sass_compiler_add_custom_function(compiler, sass_make_function("md5f($x)", fn_md5f, 0));
  sass_compiler_add_custom_function(compiler, sass_make_function("crc16f($x)", fn_crc16f, 0));
  sass_compiler_add_custom_function(compiler, sass_make_function("crc32f($x)", fn_crc32f, 0));
  sass_compiler_add_custom_function(compiler, sass_make_function("base64f($x)", fn_base64f, 0));

}
