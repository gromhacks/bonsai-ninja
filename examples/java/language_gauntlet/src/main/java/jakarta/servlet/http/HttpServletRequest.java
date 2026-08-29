package jakarta.servlet.http;

public interface HttpServletRequest {
    String getParameter(String name);
    String getHeader(String name);
}
