#include "arxguard_engine.h"
#include <string.h>

#define AG_MIN(a,b) ((a)<(b)?(a):(b))

static void add(struct arxguard_result *r, int sev, const char *reason) {
    if (r->findings < sizeof(r->finding)/sizeof(r->finding[0])) {
        r->finding[r->findings].severity = sev;
        r->finding[r->findings].reason = reason;
        r->findings++;
    }
    if (sev == ARXGUARD_BLOCK || (sev == ARXGUARD_WARN && r->code == ARXGUARD_CLEAN))
        r->code = sev;
}

static int has(const unsigned char *s, size_t n, const char *needle) {
    size_t m = strlen(needle);
    if (!m || m > n) return 0;
    for (size_t i = 0; i + m <= n; ++i)
        if (s[i] == (unsigned char)needle[0] && memcmp(s + i, needle, m) == 0) return 1;
    return 0;
}

static int has_any(const unsigned char *s, size_t n, const char *a, const char *b,
                   const char *c, const char *d) {
    return has(s,n,a) || has(s,n,b) || has(s,n,c) || has(s,n,d);
}

static int ascii_ci(unsigned char c) {
    return c >= 'A' && c <= 'Z' ? c + ('a'-'A') : c;
}

static int has_ci(const unsigned char *s, size_t n, const char *needle) {
    size_t m = strlen(needle);
    if (!m || m > n) return 0;
    for (size_t i = 0; i + m <= n; ++i) {
        size_t j = 0;
        for (; j < m; ++j)
            if (ascii_ci(s[i+j]) != ascii_ci((unsigned char)needle[j])) break;
        if (j == m) return 1;
    }
    return 0;
}

static int command_word(const unsigned char *s, size_t n, const char *word) {
    size_t m = strlen(word);
    for (size_t i=0; i+m<=n; ++i) {
        if (i && ((s[i-1]>='a'&&s[i-1]<='z')||(s[i-1]>='A'&&s[i-1]<='Z')||s[i-1]=='_'||s[i-1]=='-')) continue;
        if (memcmp(s+i,word,m)!=0) continue;
        if (i+m<n && ((s[i+m]>='a'&&s[i+m]<='z')||(s[i+m]>='A'&&s[i+m]<='Z')||s[i+m]=='_'||s[i+m]=='-')) continue;
        return 1;
    }
    return 0;
}

static int remote_shell(const unsigned char *s, size_t n) {
    if (has(s,n,"/dev/tcp/") || has(s,n,"/dev/udp/")) return 1;
    if ((has_ci(s,n,"nc ") || has_ci(s,n,"ncat ") || has_ci(s,n,"socat ")) && has_ci(s,n,"-e")) return 1;
    if (has_ci(s,n,"mkfifo") && has_any(s,n,"| sh","| bash","| zsh","| ksh")) return 1;
    return 0;
}

static int destructive(const unsigned char *s, size_t n) {
    if (has_ci(s,n,"rm -rf /") || has_ci(s,n,"rm -fr /") || has_ci(s,n,"rm -rf ~") ||
        has_ci(s,n,"rm -rf .") || has_ci(s,n,"rm --recursive --force /")) return 1;
    if (has_ci(s,n,"of=/dev/sda") || has_ci(s,n,"of=/dev/nvme") || has_ci(s,n,"of=/dev/vda") ||
        has_ci(s,n,"of=/dev/mmcblk") || has_ci(s,n,"mkfs /dev/") || has_ci(s,n,"wipefs")) return 1;
    if (has_ci(s,n," :(){ :|:& };:") || has(s,n,":(){ :|:& };:")) return 1;
    return 0;
}

int arxguard_scan_bytes(const unsigned char *input, size_t len, struct arxguard_result *out) {
    if (!out) return -1;
    memset(out, 0, sizeof(*out));
    if (!input || !len) return 0;

    /* Tier 0: raw-byte sentinels. This is intentionally before UTF-8 parsing. */
    for (size_t i=0; i<len; ++i) {
        unsigned char b=input[i];
        if (b==0x1b && i+1<len && (input[i+1]=='[' || input[i+1]==']' || input[i+1]=='P' || input[i+1]=='_')) {
            add(out, ARXGUARD_BLOCK, "[CRITICAL] terminal escape/control sequence");
            break;
        }
        if (b==0x00 || b==0x7f || (b<0x20 && b!='\n' && b!='\t' && b!='\r' && b!=0x1b)) {
            add(out, ARXGUARD_WARN, "[HIGH] unexpected control byte");
            break;
        }
    }

    /* UTF-8 security controls: test exact byte sequences, avoiding a Unicode library in hot path. */
    static const char *unicode_controls[] = {
        "\xE2\x80\x8B", "\xE2\x80\x8C", "\xE2\x80\x8D", "\xE2\x80\x8E", "\xE2\x80\x8F",
        "\xE2\x80\xAA", "\xE2\x80\xAB", "\xE2\x80\xAC", "\xE2\x80\xAD", "\xE2\x80\xAE",
        "\xE2\x81\xA0", "\xE2\x81\xA6", "\xE2\x81\xA7", "\xE2\x81\xA8", "\xE2\x81\xA9",
        "\xEF\xBB\xBF", "\xE3\x85\x9F", "\xE3\x86\xA4", "\xE1\x85\x9F", "\xE1\x86\xA0"
    };
    for (size_t i=0;i<sizeof(unicode_controls)/sizeof(unicode_controls[0]);++i)
        if (has((const unsigned char*)input,len,unicode_controls[i])) {
            add(out, ARXGUARD_BLOCK, "[CRITICAL] invisible/bidi Unicode control"); break;
        }

    /* Tier 1: cheap byte patterns. */
    if (destructive(input,len)) add(out, ARXGUARD_BLOCK, "[CRITICAL] destructive or raw-disk command");
    if (has_ci(input,len,"base64 -d") || has_ci(input,len,"base64 --decode") || has_ci(input,len,"xxd -r") || has_ci(input,len,"openssl enc -d")) {
        if (has(input,len,"|") || has(input,len,"| ")) add(out, ARXGUARD_BLOCK, "[CRITICAL] decoded payload piped to execution");
    }
    if (remote_shell(input,len)) add(out, ARXGUARD_BLOCK, "[CRITICAL] network-to-shell/reverse-shell pattern");

    if ((command_word(input,len,"curl") || command_word(input,len,"wget") || command_word(input,len,"fetch")) &&
        (has(input,len,"| sh") || has(input,len,"| bash") || has(input,len,"| zsh") || has(input,len,"| sudo sh") || has(input,len,"| sudo bash")))
        add(out, ARXGUARD_BLOCK, "[CRITICAL] remote content piped into shell");

    if ((has_ci(input,len,"curl ") || has_ci(input,len,"wget ")) &&
        (has_ci(input,len," -k ") || has_ci(input,len," --insecure") || has_ci(input,len," --no-check-certificate")))
        add(out, ARXGUARD_WARN, "[HIGH] transport verification disabled");

    if ((has_ci(input,len,"apt ") || has_ci(input,len,"apt-get ") || has_ci(input,len,"dnf ") || has_ci(input,len,"yum ") || has_ci(input,len,"pacman ")) &&
        (has_ci(input,len,"--allow-unauthenticated") || has_ci(input,len,"--nogpgcheck") || has_ci(input,len,"trusted=yes")))
        add(out, ARXGUARD_BLOCK, "[CRITICAL] package signature verification disabled");

    if ((has_ci(input,len,"curl ") || has_ci(input,len,"wget ") || has_ci(input,len,"scp ") || has_ci(input,len,"rsync ")) &&
        (has_ci(input,len,".ssh/") || has_ci(input,len,"id_rsa") || has_ci(input,len,"id_ed25519") || has_ci(input,len,".aws/") ||
         has_ci(input,len,".netrc") || has_ci(input,len,".git-credentials") || has_ci(input,len,".kube/config") || has_ci(input,len,"github_token")))
        add(out, ARXGUARD_BLOCK, "[CRITICAL] network command references credential material");

    if ((has_ci(input,len,"authorized_keys") || has_ci(input,len,"/etc/cron") || has_ci(input,len,".bashrc") || has_ci(input,len,".zshrc")) &&
        (has(input,len,">>") || has(input,len,"> ") || has_ci(input,len,"tee")))
        add(out, ARXGUARD_WARN, "[HIGH] persistence or authorization modification");

    if (has_ci(input,len,"chmod 777") || has_ci(input,len,"eval ") && (has_ci(input,len,"curl") || has_ci(input,len,"wget")))
        add(out, ARXGUARD_WARN, "[HIGH] unsafe privilege or dynamic execution pattern");

    /* Homograph gate: a network command containing non-ASCII bytes is escalated. */
    if ((has_ci(input,len,"http://") || has_ci(input,len,"https://") || has_ci(input,len,"www."))) {
        for (size_t i=0;i<len;++i) if (input[i] >= 0x80) {
            add(out, ARXGUARD_WARN, "[HIGH] non-ASCII network text requires homograph/IDN review"); break;
        }
    }

    /* Unknown dangerous constructs remain eligible for the richer Rust layer. */
    return out->code;
}

int arxguard_scan_cstr(const char *input, struct arxguard_result *out) {
    if (!input) return arxguard_scan_bytes(NULL, 0, out);
    return arxguard_scan_bytes((const unsigned char*)input, strlen(input), out);
}

const char *arxguard_version(void) { return "0.2.0-native"; }
