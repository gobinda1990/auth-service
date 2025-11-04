package comtax.gov.webapp.util;


import jakarta.servlet.http.HttpServletResponse;
import java.util.Optional;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import java.util.Arrays;

public class CookieUtil {

    private CookieUtil() {}

    /**
     * Add a cookie to the response with full production-safe attributes
     * @param response HttpServletResponse
     * @param name cookie name
     * @param value cookie value
     * @param maxAge max age in seconds
     * @param httpOnly HttpOnly flag
     * @param secure Secure flag
     * @param sameSite SameSite attribute (Strict, Lax, None)
     * @param domain optional domain
     */
    public static void addCookie(HttpServletResponse response, String name, String value, int maxAge,
                                 boolean httpOnly, boolean secure, String sameSite, String domain) {
        StringBuilder headerValue = new StringBuilder();
        headerValue.append(name).append("=").append(value)
                   .append("; Max-Age=").append(maxAge)
                   .append("; Path=/");

        if (secure) headerValue.append("; Secure");
        if (httpOnly) headerValue.append("; HttpOnly");
        if (sameSite != null) headerValue.append("; SameSite=").append(sameSite);
        if (domain != null && !domain.isBlank()) headerValue.append("; Domain=").append(domain);

        response.addHeader("Set-Cookie", headerValue.toString());
    }

    /**
     * Delete a cookie safely
     */
    public static void deleteCookie(HttpServletResponse response, String name, String domain) {
        StringBuilder headerValue = new StringBuilder();
        headerValue.append(name).append("=; Max-Age=0; Path=/; HttpOnly; Secure; SameSite=Strict");
        if (domain != null && !domain.isBlank()) headerValue.append("; Domain=").append(domain);
        response.addHeader("Set-Cookie", headerValue.toString());
    }

    /**
     * Get cookie value from request
     */
    public static Optional<String> getCookieValue(HttpServletRequest request, String name) {
        if (request.getCookies() == null) return Optional.empty();
        return Arrays.stream(request.getCookies())
                     .filter(cookie -> cookie.getName().equals(name))
                     .map(Cookie::getValue)
                     .findFirst();
    }
}