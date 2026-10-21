package org.qbdi.abi;

import java.util.Arrays;

/** Independent Java receiver for the arm64 JNI acceptance probe. */
public final class JniAbiProbe {
    private static String phase;
    private static int mode;

    public static void context(String value, int callMode) {
        phase = value;
        mode = callMode;
    }

    private static void observe(String name, String values) {
        System.out.println("QTRACE_ABI_JAVA {\"phase\":\"" + phase +
                "\",\"mode\":" + mode + ",\"case\":\"" + name +
                "\",\"values\":" + values + "}");
    }

    public static long simple(int a, int b, byte[] bytes) {
        observe("simple", "[" + a + "," + b + "," + Arrays.toString(bytes) + "]");
        boolean ints = (a == 2 && b == -38) ||
                (a == Integer.MIN_VALUE && b == Integer.MAX_VALUE);
        return ints && Arrays.equals(bytes, new byte[]{0, -1, 42, 127, -128}) ? 42 : -1;
    }

    public static long mixed(int a, long wide, double d, float f, byte[] bytes,
                             int i0, int i1, int i2, int i3, int i4, int i5, int i6,
                             double d0, double d1, double d2, double d3,
                             double d4, double d5, double d6, double d7) {
        int[] ints = {i0, i1, i2, i3, i4, i5, i6};
        double[] doubles = {d0, d1, d2, d3, d4, d5, d6, d7};
        observe("mixed", "[" + a + "," + wide + "," + d + "," + f + "," +
                Arrays.toString(bytes) + "," + Arrays.toString(ints) + "," +
                Arrays.toString(doubles) + "]");
        return a == -17 && wide == -81985529216486895L && d == -2.5 && f == 1.25f &&
                Arrays.equals(bytes, new byte[]{0, -1, 42, 127, -128}) &&
                Arrays.equals(ints, new int[]{5, -6, 7, -8, 9, -10, 11}) &&
                Arrays.equals(doubles, new double[]{0.5, -1.5, 2.5, -3.5, 4.5, -5.5, 6.5, -7.5})
                ? 42 : -1;
    }

    public static double narrow(boolean z, byte b, short s, char c, float f) {
        observe("narrow", "[" + z + "," + b + "," + s + "," + (int)c + "," + f + "]");
        return z && b == -5 && s == -1234 && c == 0x8123 && f == -1.5f ? -3.25 : -99;
    }

    public static int throwing(int value) {
        observe("throwing", "[" + value + "]");
        throw new IllegalArgumentException("abi-probe-" + value);
    }

    public static class BaseReceiver {
        public float floatValue;
        public double doubleValue;
        public static float staticFloatValue;
        public static double staticDoubleValue;
        public boolean valid;

        public BaseReceiver() {}

        public BaseReceiver(int a, int b, byte[] bytes) {
            observe("constructor", "[" + a + "," + b + "," + Arrays.toString(bytes) + "]");
            valid = validReceiverArguments(a, b, bytes);
        }

        public long value(int a, int b, byte[] bytes) {
            observe("nonvirtual", "[" + a + "," + b + "," + Arrays.toString(bytes) + "]");
            return validReceiverArguments(a, b, bytes) ? 42 : -1;
        }
    }

    public static final class DerivedReceiver extends BaseReceiver {
        @Override public long value(int a, int b, byte[] bytes) {
            observe("instance", "[" + a + "," + b + "," + Arrays.toString(bytes) + "]");
            return validReceiverArguments(a, b, bytes) ? 43 : -1;
        }
    }

    private static boolean validReceiverArguments(int a, int b, byte[] bytes) {
        return a == 2 && b == -38 && Arrays.equals(bytes, new byte[]{0, -1, 42, 127, -128});
    }

    public static void resetFields(BaseReceiver receiver) {
        receiver.floatValue = 0;
        receiver.doubleValue = 0;
        BaseReceiver.staticFloatValue = 0;
        BaseReceiver.staticDoubleValue = 0;
    }

    public static int checkFields(BaseReceiver receiver) {
        observe("fields", "[" + receiver.floatValue + "," + receiver.doubleValue + "," +
                BaseReceiver.staticFloatValue + "," + BaseReceiver.staticDoubleValue + "]");
        return receiver.floatValue == -1.5f && receiver.doubleValue == -3.25 &&
                BaseReceiver.staticFloatValue == 1.25f && BaseReceiver.staticDoubleValue == -2.5 ? 42 : -1;
    }

    private static native String run(String directory, String packageName, String session);

    public static void main(String[] args) {
        System.load(args[0] + "/libjni_abi_probe.so");
        System.out.println("QTRACE_ABI_RESULT " + run(args[0], args[1], args[2]));
    }
}
