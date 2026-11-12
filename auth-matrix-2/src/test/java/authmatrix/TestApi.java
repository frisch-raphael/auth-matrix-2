package authmatrix;

import burp.api.montoya.MontoyaApi;
import java.lang.reflect.*;
import java.util.*;
import javax.swing.JPanel;

final class TestApi {
    static MontoyaApi create(String name, String id, Map<String, String> stored) {
        return proxy(MontoyaApi.class, name, id, stored);
    }
    @SuppressWarnings("unchecked")
    private static <T> T proxy(Class<T> type, String name, String id, Map<String, String> stored) {
        return (T) Proxy.newProxyInstance(type.getClassLoader(), new Class[]{type}, (object, method, args) -> {
            return switch (method.getName()) {
                case "name" -> name;
                case "id" -> id;
                case "getString" -> stored.get((String) args[0]);
                case "setString" -> { stored.put((String) args[0], (String) args[1]); yield null; }
                case "uiComponent" -> new JPanel();
                case "isModified" -> false;
                case "toString" -> type.getSimpleName();
                default -> {
                    Class<?> result = method.getReturnType();
                    if (result == void.class) yield null;
                    if (result == boolean.class) yield false;
                    if (result.isInterface()) yield proxy(result, name, id, stored);
                    yield null;
                }
            };
        });
    }
}
