
#ifndef __NARGV_H__
#define __NARGV_H__

typedef struct NARGV {
    char **argv, *data;
    const char *error_message;
    int argc, data_length, error_index, error_code;
} NARGV;

VEILCORE_API void nargv_free(NARGV* props);
VEILCORE_API void nargv_ifs(char *nifs);
VEILCORE_API NARGV *nargv_parse(char *input);

#endif // __NARGV_H__
