import javax.naming.ldap.Rdn
import javax.naming.directory.DirContext
import javax.naming.directory.SearchControls
import javax.servlet.http.HttpServletRequest
class Controller {
  def direct(request: HttpServletRequest, directory: DirContext): Unit = {
    val name = request.getParameter("name")
    directory.search("dc=example", "(uid=" + name + ")", new SearchControls())
  }
  def escaped(request: HttpServletRequest, directory: DirContext): Unit = {
    val name = request.getParameter("name")
    directory.search("dc=example", "(uid=" + Rdn.escapeValue(name) + ")", new SearchControls())
  }
}
