"""Small ctypes wrapper: exercise the same PCRE2 syntax used by Wazuh."""
import ctypes as C
from ctypes.util import find_library

lib = C.CDLL(find_library('pcre2-8') or 'libpcre2-8.so.0')
ptr, size = C.c_void_p, C.c_size_t
lib.pcre2_compile_8.argtypes = [C.c_char_p, size, C.c_uint32, C.POINTER(C.c_int), C.POINTER(size), ptr]
lib.pcre2_compile_8.restype = ptr
lib.pcre2_code_free_8.argtypes = [ptr]
lib.pcre2_match_data_create_from_pattern_8.argtypes = [ptr, ptr]
lib.pcre2_match_data_create_from_pattern_8.restype = ptr
lib.pcre2_match_data_free_8.argtypes = [ptr]
lib.pcre2_match_8.argtypes = [ptr, C.c_char_p, size, size, C.c_uint32, ptr, ptr]
lib.pcre2_match_8.restype = C.c_int
lib.pcre2_get_ovector_pointer_8.argtypes = [ptr]
lib.pcre2_get_ovector_pointer_8.restype = C.POINTER(size)


def search(pattern, subject):
    expression, data = pattern.encode(), subject.encode()
    error, offset = C.c_int(), size()
    code = lib.pcre2_compile_8(expression, len(expression), 0, C.byref(error), C.byref(offset), None)
    if not code:
        raise ValueError(f'PCRE2 error {error.value} at {offset.value}: {pattern}')
    match = lib.pcre2_match_data_create_from_pattern_8(code, None)
    try:
        count = lib.pcre2_match_8(code, data, len(data), 0, 0, match, None)
        if count == -1:
            return None
        if count < 0:
            raise ValueError(f'PCRE2 match error {count}: {pattern}')
        vector = lib.pcre2_get_ovector_pointer_8(match)
        return tuple(data[vector[2*i]:vector[2*i+1]].decode() for i in range(1, count))
    finally:
        lib.pcre2_match_data_free_8(match)
        lib.pcre2_code_free_8(code)
