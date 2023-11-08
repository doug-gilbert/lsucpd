
#include <string_view>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "sg_json.h"
#include "sg_json_builder.h"

void
sgj_hr_pri_helper(const std::string_view s, sgj_state * jsp)
{
    bool step = false;
    size_t ln;
    char b[256];
    static const int blen = sizeof(b);

    ln = s.size();
    ln = (ln < blen) ? ln : (blen - 1);
    memcpy(b, s.data(), ln);
    b[ln] = '\0';
    // ln = vsnprintf(b, blen, fmt, args);
    if ((ln > 0) && (ln < (size_t)blen)) {
        char * cp;

         /* deal with leading, trailing and embedded newlines */
         while ( true ) {
            cp = strrchr(b, '\n');
            if (NULL == cp)
                break;
            else if (cp == b) {
                if ('\0' == *(cp + 1))
                    *cp = '\0';
                else
                    step = true;
                break;
            } else if ('\0' == *(cp + 1))
                *cp = '\0';
            else
                *cp = ';';
         }
         /* replace any tabs with semicolons or spaces */
         while ( true ) {
            cp = strchr(b, '\t');
            if (NULL == cp)
                break;
            else if (cp == b) {
                if ('\0' == *(cp + 1))
                    *cp = '\0';
                else {
                    *cp = ' ';      /* so don't find \t again and again */
                    step = true;
                }
            } else {
                if (';' == *(cp - 1))
                    *cp = ' ';
                else
                    *cp = ';';
            }
        }
    }
    json_array_push((json_value *)jsp->out_hrp,
                    json_string_new(step ? b + 1 : b));
}
