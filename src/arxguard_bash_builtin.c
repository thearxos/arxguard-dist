#include <stdio.h>
#include <string.h>
#include "builtins.h"
#include "common.h"
#include "shell.h"
#include "arxguard_engine.h"

int arxguard_builtin(WORD_LIST *list) {
    struct arxguard_result r;
    size_t len = 0;
    for (WORD_LIST *w=list; w; w=w->next) len += strlen(w->word->word) + 1;
    char *buf = (char *)xmalloc(len ? len : 1);
    size_t p=0;
    for (WORD_LIST *w=list; w; w=w->next) {
        size_t n=strlen(w->word->word);
        memcpy(buf+p,w->word->word,n); p+=n;
        if (w->next) buf[p++]=' ';
    }
    int rc=arxguard_scan_bytes((const unsigned char*)buf,p,&r);
    for (size_t i=0;i<r.findings;++i) internal_error("%s", r.finding[i].reason);
    free(buf);
    return rc;
}

char *arxguard_builtin_doc[] = {
    "Scan command arguments with the native ARXGuard engine.",
    (char *)0
};

struct builtin arxguard_struct = {
    .name = "arxguard-scan",
    .function = arxguard_builtin,
    .flags = BUILTIN_ENABLED,
    .long_doc = arxguard_builtin_doc,
    .short_doc = "arxguard-scan COMMAND",
    .handle = 0
};
