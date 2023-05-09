/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package vn.mobileid.serialize;

import java.lang.reflect.Field;
import vn.mobileid.exsig.Profile;
import java.lang.reflect.Modifier;
import java.util.Base64;
import java.util.Iterator;
import java.util.List;

/**
 *
 * @author GIATK
 */
public class ProfileJSONSerializer {

    public static String writeObject(Object profile) {
        StringBuilder builder = new StringBuilder();
        builder.append(writeStartJSON());
        Field[] fields = profile.getClass().getDeclaredFields();
        if (profile.getClass().getSuperclass().getSuperclass() != null) {
            Field[] fields_ = profile.getClass().getSuperclass().getSuperclass().getDeclaredFields();
            //SuperClass
            for (Field field : fields_) {
                try {
                    field.setAccessible(true);
                    if (Modifier.isTransient(field.getModifiers())) {
                        continue;
                    }
                    Object type = field.get(profile);
                    if (type instanceof String) {
                        builder.append(writeStringField(field.getName(), (String) field.get(profile)));
                    } else if (type instanceof Integer) {
                        builder.append(writeNumberField(field.getName(), field.getInt(profile)));
                    } else if (type instanceof Long) {
                        builder.append(writeNumberField(field.getName(), field.getLong(profile)));
                    } else if (type instanceof Double) {
                        builder.append(writeNumberField(field.getName(), field.getDouble(profile)));
                    } else if (type instanceof byte[]) {
                        builder.append(writeByteField(field.getName(), (byte[]) field.get(profile)));
                    } else if (type instanceof Boolean) {
                        builder.append(writeBooleanField(field.getName(), field.getBoolean(profile)));
                    } else if (type instanceof List) {
                        builder.append(writeStartArrayField(field.getName()));
                        List<?> list = (List) field.get(profile);
                        Iterator s = list.iterator();
                        while (true) {
                            Object object = s.next();

                            if (object instanceof String) {
                                builder.append(writeString((String) object));
                            } else if (object instanceof byte[]) {
                                builder.append(writeByte((byte[]) object));
                            }
                            if (s.hasNext()) {
                                builder.append(",");
                            } else {
                                break;
                            }

                        }
                        builder.append(writeEndArray());
                    } else if (type != null) {
                        if (field.getName().equals("algorithm")) {
                            builder.append("\"" + field.getName() + "Attr\":");
                        } else {
                            builder.append("\"" + field.getName() + "\":");
                        }
                        builder.append(writeClassField(field.get(profile)));
                    } else {
                        continue;
                    }

                    builder.append(",");
                } catch (Exception ex) {
                    System.out.println("Ex:" + ex);
                }
            }
        }
        for (Field field : fields) {
            try {
                field.setAccessible(true);
                if (Modifier.isTransient(field.getModifiers())) {
                    continue;
                }
                Object type = field.get(profile);
                if (type instanceof String) {
                    builder.append(writeStringField(field.getName(), (String) field.get(profile)));
                } else if (type instanceof Integer) {
                    builder.append(writeNumberField(field.getName(), field.getInt(profile)));
                } else if (type instanceof Long) {
                    builder.append(writeNumberField(field.getName(), field.getLong(profile)));
                } else if (type instanceof Double) {
                    builder.append(writeNumberField(field.getName(), field.getDouble(profile)));
                } else if (type instanceof byte[]) {
                    builder.append(writeByteField(field.getName(), (byte[]) field.get(profile)));
                } else if (type instanceof Boolean) {
                    builder.append(writeBooleanField(field.getName(), field.getBoolean(profile)));
                } else if (type instanceof List) {
                    builder.append(writeStartArrayField(field.getName()));
                    List<?> list = (List) field.get(profile);
                    Iterator s = list.iterator();
                    while (true) {
                        Object object = s.next();
                        if (object instanceof String) {
                            builder.append(writeString((String) object));
                        } else if (object instanceof byte[]) {
                            builder.append(writeByte((byte[]) object));
                        }
                        if (s.hasNext()) {
                            builder.append(",");
                            continue;
                        } else {
                            break;
                        }
                    }
                    builder.append(writeEndArray());
                } else if (type != null) {
                    builder.append("\"" + field.getName() + "\":");
                    builder.append(writeClassField(field.get(profile)));
                } else {
                    continue;
                }
                builder.append(",");
            } catch (Exception ex) {
                System.out.println("Ex:" + ex);
            }
        }

        builder.deleteCharAt(builder.lastIndexOf(","));
        builder.append(writeEndJSON());
        return builder.toString();
    }

    private static Field getField(Class clazz, String fieldName) throws NoSuchFieldException {
        try {
            return clazz.getDeclaredField(fieldName);
        } catch (NoSuchFieldException e) {
            Class superClass = clazz.getSuperclass();
            if (superClass == null) {
                throw e;
            } else {
                return getField(superClass, fieldName);
            }
        }
    }

    private static String writeStartJSON() {
        return "{";
    }

    private static String writeEndJSON() {
        return "}";
    }

    private static String writeStartArrayField(String field) {
        return "\"" + field + "\":[";
    }

    private static String writeEndArray() {
        return "]";
    }

    private static String writeNumberField(String field, int value) {
        return "\"" + field + "\":" + value;
    }

    private static String writeNumberField(String field, long value) {
        return "\"" + field + "\":" + value;
    }

    private static String writeNumberField(String field, float value) {
        return "\"" + field + "\":" + value;
    }

    private static String writeNumberField(String field, double value) {
        return "\"" + field + "\":" + value;
    }

    private static String writeStringField(String field, String value) {
        return "\"" + field + "\":\"" + value + "\"";
    }

    private static String writeString(String value) {
        return "\"" + value + "\"";
    }

    /**
     * Note: this byte array will be converted to base64 before append into JSON
     * String
     */
    private static String writeByteField(String field, byte[] value) {
        String data = new String(Base64.getEncoder().encodeToString(value));
        return "\"" + field + "\":\"" + data + "\"";
    }

    /**
     * Note: this byte array will be converted to base64 before append into JSON
     * String
     */
    private static String writeByte(byte[] value) {
        String data = new String(Base64.getEncoder().encodeToString(value));
        return "\"" + data + "\"";
    }

    private static String writeBooleanField(String field, boolean value) {
        return "\"" + field + "\":" + value;
    }

    private static String writeClassField(Object object) {
        StringBuilder builder = new StringBuilder();
        if (object.getClass().isEnum()) {
            builder.append(writeStartJSON());
            Field[] enum_ = object.getClass().getDeclaredFields();
            for (Field field : enum_) {
                if (field.isEnumConstant()) {
                    continue;
                }
                try {
                    field.setAccessible(true);
                    Object type = field.get(object);

                    if (type instanceof String) {
                        builder.append(writeStringField(field.getName(), (String) field.get(object)));
                    } else if (type instanceof Integer) {
                        builder.append(writeNumberField(field.getName(), field.getInt(object)));
                    } else if (type instanceof Long) {
                        builder.append(writeNumberField(field.getName(), field.getLong(object)));
                    } else if (type instanceof Double) {
                        builder.append(writeNumberField(field.getName(), field.getDouble(object)));
                    } else if (type instanceof byte[]) {
                        builder.append(writeByteField(field.getName(), (byte[]) field.get(object)));
                    } else if (type instanceof Boolean) {
                        builder.append(writeBooleanField(field.getName(), field.getBoolean(object)));
                    } else {
                        continue;
                    }
                    builder.append(",");
                } catch (Exception ex) {
                    continue;
                }
            }
            builder.deleteCharAt(builder.lastIndexOf(","));
            builder.append(writeEndJSON());
            System.out.println("\n\nClass:" + builder.toString() + "\n\n");
            return builder.toString();
        }
        if (object.getClass().isInterface()) {
            return builder.toString();
        }

        return writeObject(object);
    }
}
