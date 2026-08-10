#include "arxguard_engine.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void print_result(const struct arxguard_result *r) {
    for (size_t i=0;i<r->findings;++i) fputs(r->finding[i].reason, stderr), fputc('\n', stderr);
}

int main(int argc, char **argv) {
    struct arxguard_result r;
    if (argc > 1) {
        size_t total=0;
        for (int i=1;i<argc;++i) total += strlen(argv[i]) + 1;
        unsigned char *buf = (unsigned char*)malloc(total ? total : 1);
        if (!buf) return 4;
        size_t p=0;
        for (int i=1;i<argc;++i) { size_t n=strlen(argv[i]); memcpy(buf+p,argv[i],n); p+=n; if(i+1<argc) buf[p++]=' '; }
        int rc=arxguard_scan_bytes(buf,p,&r); free(buf); print_result(&r); return rc;
    }
    unsigned char buf[65536];
    size_t n=fread(buf,1,sizeof(buf),stdin);
    int rc=arxguard_scan_bytes(buf,n,&r); print_result(&r); return rc;
}
