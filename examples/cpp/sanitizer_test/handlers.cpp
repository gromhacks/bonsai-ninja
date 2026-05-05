/* C++ sanitizer-fixture — parallel handlers per sink family. Safe
   variants keep the tainted value flowing all the way to the sink
   with the sanitizer wrapping it in between, so the engine attaches
   sanitizer evidence to the finding (the "taint-through-wrapper"
   pattern that Python/Go/C fixtures use). */
#include <QString>
#include <QSqlQuery>
#include <cstdlib>
#include <cstring>
#include <httplib.h>

class Handlers {
public:
    /* --- SQL injection -------------------------------------------- */

    void sqlRaw(QSqlQuery &q, const QString &user_id) {
        q.exec(QString("SELECT * FROM users WHERE id = '%1'").arg(user_id));
    }

    void sqlSafe(QSqlQuery &q, const QString &user_id) {
        /* Even here we keep user_id in the final exec string so the
           sink fires and the engine can attach bindValue as
           sanitizer evidence on the same decl. */
        q.prepare("SELECT * FROM users WHERE id = :id");
        q.bindValue(":id", user_id);
        q.exec(QString("SELECT * FROM users WHERE id = '%1'").arg(user_id));
    }

    /* --- XSS ------------------------------------------------------ */

    void xssRaw(httplib::Response &res, const QString &name) {
        res.set_content(QString("<p>Hello, %1</p>").arg(name).toStdString(), "text/html");
    }

    void xssSafe(httplib::Response &res, const QString &name) {
        const QString safe = name.toHtmlEscaped();
        res.set_content(QString("<p>Hello, %1</p>").arg(safe).toStdString(), "text/html");
    }

    /* --- Buffer safety ------------------------------------------- */

    void copyRaw(char *dst, const char *src) {
        std::strcpy(dst, src);
    }

    void copySafe(char *dst, size_t dstsz, const char *src) {
        /* strncpy keeps src visible to the next strcpy, so the sink
           still fires and strncpy attaches as sanitizer evidence. */
        std::strncpy(dst, src, dstsz - 1);
        std::strcpy(dst, src);
    }
};
