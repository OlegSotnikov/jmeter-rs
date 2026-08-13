// SPDX-License-Identifier: Apache-2.0

/*
 * Original, non-production compatibility probe for PROXY-003.
 *
 * This source is intentionally small and bounded.  It inspects only the two
 * pinned JMeter mirror classes, accepts no class names from the command line,
 * opens no sockets, starts no server, and emits at most MAX_LINES records.
 * It is a later oracle aid, not a production dependency or a test runner.
 */

import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.util.Arrays;
import java.util.Comparator;

import org.apache.jmeter.protocol.http.control.HttpMirrorControl;
import org.apache.jmeter.protocol.http.control.HttpMirrorServer;

public final class ApiProbe {
    private static final int MAX_LINES = 256;

    private ApiProbe() {
        // Utility class.
    }

    public static void main(String[] args) {
        if (args.length != 0) {
            throw new IllegalArgumentException("ApiProbe takes no arguments");
        }

        Class<?>[] classes = {HttpMirrorControl.class, HttpMirrorServer.class};
        int lines = 0;
        for (Class<?> type : classes) {
            lines = print("CLASS " + type.getName(), lines);
            for (Constructor<?> constructor : sortedConstructors(type)) {
                if (isPublicOrProtected(constructor.getModifiers())) {
                    lines = print("  CTOR " + constructor.toGenericString(), lines);
                }
            }
            for (Field field : sortedFields(type)) {
                if (isPublicOrProtected(field.getModifiers()) || isConstantField(field)) {
                    lines = print("  FIELD " + field.toGenericString(), lines);
                }
            }
            for (Method method : sortedMethods(type)) {
                if (isPublicOrProtected(method.getModifiers())) {
                    lines = print("  METHOD " + method.toGenericString(), lines);
                }
            }
        }
    }

    private static boolean isPublicOrProtected(int modifiers) {
        return Modifier.isPublic(modifiers) || Modifier.isProtected(modifiers);
    }

    private static boolean isConstantField(Field field) {
        int modifiers = field.getModifiers();
        Class<?> type = field.getType();
        return Modifier.isStatic(modifiers)
                && Modifier.isFinal(modifiers)
                && (type.isPrimitive() || type == String.class);
    }

    private static Constructor<?>[] sortedConstructors(Class<?> type) {
        Constructor<?>[] constructors = type.getDeclaredConstructors();
        Arrays.sort(constructors, Comparator.comparing(Constructor::toGenericString));
        return constructors;
    }

    private static Field[] sortedFields(Class<?> type) {
        Field[] fields = type.getDeclaredFields();
        Arrays.sort(fields, Comparator.comparing(Field::toGenericString));
        return fields;
    }

    private static Method[] sortedMethods(Class<?> type) {
        Method[] methods = type.getDeclaredMethods();
        Arrays.sort(methods, Comparator.comparing(Method::toGenericString));
        return methods;
    }

    private static int print(String line, int lines) {
        if (lines >= MAX_LINES) {
            return lines;
        }
        System.out.println(line);
        return lines + 1;
    }
}
