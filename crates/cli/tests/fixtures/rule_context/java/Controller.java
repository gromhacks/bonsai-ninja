import org.springframework.web.bind.annotation.RequestParam;
import javax.naming.ldap.Rdn;
import javax.naming.directory.DirContext;
import javax.naming.directory.SearchControls;
class Controller {
    void escaped(@RequestParam String name, DirContext directory) throws Exception {
        directory.search("dc=example", "(uid=" + Rdn.escapeValue(name) + ")", new SearchControls());
    }
    void direct(@RequestParam String name, DirContext directory) throws Exception {
        directory.search("dc=example", "(uid=" + name + ")", new SearchControls());
    }
}
