package io.github.miner7222.scrolltranslate;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

/**
 * Version-agnostic discovery of the Google app's flag accessor methods.
 *
 * <p>The Lens "live translate" (Scroll and translate) gates are implemented as
 * zero-argument boolean getters on generated Dagger component classes. Those
 * classes are obfuscated and renamed on every Google app release, but the body
 * of the getter always contains the Phenotype/GServices flag id as a
 * {@code const-string} instruction. This scanner parses the APK's DEX files,
 * finds every method whose code references one of the requested flag ids and
 * keeps the ones that look like flag getters ({@code ()Z}).</p>
 *
 * <p>No Android APIs are used, so the same code can be validated off-device
 * against known APKs.</p>
 */
final class DexFlagScanner {

    private DexFlagScanner() {
    }

    /** A method whose code reads one of the requested flag ids. */
    static final class FlagMethod {
        final String flagId;
        final String className;
        final String methodName;
        final String dexName;

        FlagMethod(String flagId, String className, String methodName, String dexName) {
            this.flagId = flagId;
            this.className = className;
            this.methodName = methodName;
            this.dexName = dexName;
        }

        String key() {
            return className + "#" + methodName;
        }

        @Override
        public String toString() {
            return flagId + " -> " + className + "." + methodName + "() [" + dexName + "]";
        }
    }

    /** Non-fatal problems, surfaced to the caller for logging. */
    static final class ScanReport {
        final List<FlagMethod> hits = new ArrayList<>();
        final List<String> notes = new ArrayList<>();
    }

    static ScanReport scan(List<File> apks, String[] flagIds) {
        ScanReport report = new ScanReport();
        Set<String> pending = new HashSet<>(Arrays.asList(flagIds));
        Set<String> seenMethods = new HashSet<>();

        for (File apk : apks) {
            if (pending.isEmpty()) {
                break;
            }
            if (apk == null || !apk.isFile()) {
                continue;
            }
            try (ZipFile zip = new ZipFile(apk)) {
                for (String dexName : dexEntryNames(zip)) {
                    if (pending.isEmpty()) {
                        break;
                    }
                    ZipEntry entry = zip.getEntry(dexName);
                    if (entry == null) {
                        continue;
                    }
                    byte[] dex;
                    try {
                        dex = readEntry(zip, entry);
                    } catch (IOException e) {
                        report.notes.add("read_failed " + dexName + ": " + e);
                        continue;
                    }
                    if (dex == null) {
                        continue;
                    }
                    try {
                        scanDex(dex, dexName, pending, seenMethods, report);
                    } catch (Throwable t) {
                        report.notes.add("dex_scan_failed " + dexName + ": " + t);
                    }
                }
            } catch (Throwable t) {
                report.notes.add("apk_open_failed " + apk + ": " + t);
            }
        }
        if (!pending.isEmpty()) {
            report.notes.add("flag_without_accessor " + pending);
        }
        return report;
    }

    /**
     * Finds zero-argument int-returning methods whose body mentions {@code value} as
     * an int constant. Resource ids are compiled to plain int constants, so this is
     * how a UI class (for example the "Scroll and translate" action, whose
     * {@code c()} getter returns the label resource id) can be located without
     * knowing its obfuscated name.
     */
    static ScanReport findZeroArgIntMethods(List<File> apks, int value) {
        ScanReport report = new ScanReport();
        Set<String> seenMethods = new HashSet<>();
        for (File apk : apks) {
            if (apk == null || !apk.isFile()) {
                continue;
            }
            try (ZipFile zip = new ZipFile(apk)) {
                for (String dexName : dexEntryNames(zip)) {
                    ZipEntry entry = zip.getEntry(dexName);
                    if (entry == null) {
                        continue;
                    }
                    byte[] dex;
                    try {
                        dex = readEntry(zip, entry);
                    } catch (IOException e) {
                        report.notes.add("read_failed " + dexName + ": " + e);
                        continue;
                    }
                    if (dex == null) {
                        continue;
                    }
                    try {
                        scanDexForInt(dex, dexName, value, seenMethods, report);
                    } catch (Throwable t) {
                        report.notes.add("dex_scan_failed " + dexName + ": " + t);
                    }
                }
            } catch (Throwable t) {
                report.notes.add("apk_open_failed " + apk + ": " + t);
            }
        }
        if (report.hits.isEmpty()) {
            report.notes.add("no_zero_arg_int_method_for_" + Integer.toHexString(value));
        }
        return report;
    }

    private static void scanDexForInt(byte[] dex, String dexName, int value,
                                      Set<String> seenMethods, ScanReport report) {
        if (dex.length < 0x70 || u4(dex, 0) != 0x0a786564L) {
            return;
        }
        int typeIdsOff = i4(dex, 0x44);
        int protoIdsOff = i4(dex, 0x4C);
        int methodIdsOff = i4(dex, 0x5C);
        int stringIdsSize = i4(dex, 0x38);
        int stringIdsOff = i4(dex, 0x3C);
        int classDefsSize = i4(dex, 0x60);
        int classDefsOff = i4(dex, 0x64);
        if (stringIdsSize <= 0 || classDefsSize <= 0) {
            return;
        }

        for (int i = 0; i < classDefsSize; i++) {
            int classDefOff = classDefsOff + i * 32;
            if (classDefOff + 32 > dex.length) {
                break;
            }
            int classIdx = i4(dex, classDefOff);
            int classDataOff = i4(dex, classDefOff + 24);
            if (classDataOff == 0) {
                continue;
            }
            Cursor cursor = new Cursor(dex, classDataOff);
            int staticFields = cursor.uleb();
            int instanceFields = cursor.uleb();
            int directMethods = cursor.uleb();
            int virtualMethods = cursor.uleb();
            if (staticFields < 0 || instanceFields < 0 || directMethods < 0 || virtualMethods < 0) {
                continue;
            }
            for (int f = 0; f < staticFields + instanceFields; f++) {
                if (cursor.uleb() < 0 || cursor.uleb() < 0) {
                    break;
                }
            }
            if (cursor.pointer >= dex.length) {
                continue;
            }
            int methodIdx = 0;
            String className = null;
            int totalMethods = directMethods + virtualMethods;
            for (int m = 0; m < totalMethods; m++) {
                if (m == directMethods) {
                    methodIdx = 0;
                }
                int methodIdxDiff = cursor.uleb();
                int accessFlags = cursor.uleb();
                int codeOff = cursor.uleb();
                if (methodIdxDiff < 0 || accessFlags < 0 || codeOff < 0) {
                    break;
                }
                methodIdx += methodIdxDiff;
                if (codeOff == 0 || codeOff + 16 > dex.length) {
                    continue;
                }
                if (!returnsIntNoArgs(dex, methodIdx, methodIdsOff, protoIdsOff,
                        typeIdsOff, stringIdsOff, stringIdsSize)) {
                    continue;
                }
                if (!codeContainsInt(dex, codeOff, value)) {
                    continue;
                }
                if (className == null) {
                    className = typeName(dex, classIdx, typeIdsOff, stringIdsOff, stringIdsSize);
                    if (className == null) {
                        break;
                    }
                }
                String methodName = methodName(dex, methodIdx, methodIdsOff, stringIdsOff, stringIdsSize);
                if (methodName == null) {
                    continue;
                }
                if (seenMethods.add(className + "#" + methodName)) {
                    report.hits.add(new FlagMethod(Integer.toHexString(value),
                            descriptorToClassName(className), methodName, dexName));
                }
            }
        }
    }

    private static boolean returnsIntNoArgs(byte[] dex, int methodIdx, int methodIdsOff,
                                            int protoIdsOff, int typeIdsOff, int stringIdsOff,
                                            int stringIdsSize) {
        int methodOff = methodIdsOff + methodIdx * 8;
        if (methodOff + 8 > dex.length) {
            return false;
        }
        int protoIdx = u2(dex, methodOff + 2);
        int protoOff = protoIdsOff + protoIdx * 12;
        if (protoOff + 12 > dex.length) {
            return false;
        }
        if (i4(dex, protoOff + 8) != 0) {
            return false;
        }
        String returnType = typeName(dex, i4(dex, protoOff + 4), typeIdsOff, stringIdsOff, stringIdsSize);
        return "I".equals(returnType);
    }

    /** Scans a method body for const / const-16 / const-high16 / const-4 carrying {@code value}. */
    private static boolean codeContainsInt(byte[] dex, int codeOff, int value) {
        int insnsSize = i4(dex, codeOff + 12);
        int insnsOff = codeOff + 16;
        if (insnsSize <= 0 || insnsSize > 0x400000 || insnsOff + insnsSize * 2 > dex.length) {
            return false;
        }
        int k = 0;
        while (k < insnsSize) {
            int insn = u2(dex, insnsOff + k * 2);
            int opcode = insn & 0xFF;
            switch (opcode) {
                case 0x12: { // const/4 vA, #+B
                    int lit = (insn >> 12) & 0xF;
                    if (lit > 7) {
                        lit -= 16;
                    }
                    if (lit == value) {
                        return true;
                    }
                    k += 1;
                    break;
                }
                case 0x13: { // const/16 vAA, #+BBBB
                    if (k + 1 >= insnsSize) {
                        return false;
                    }
                    int lit = (short) u2(dex, insnsOff + (k + 1) * 2);
                    if (lit == value) {
                        return true;
                    }
                    k += 2;
                    break;
                }
                case 0x14: { // const vAA, #+BBBBBBBB
                    if (k + 2 >= insnsSize) {
                        return false;
                    }
                    int lit = u2(dex, insnsOff + (k + 1) * 2) | (u2(dex, insnsOff + (k + 2) * 2) << 16);
                    if (lit == value) {
                        return true;
                    }
                    k += 3;
                    break;
                }
                case 0x15: { // const/high16 vAA, #+BBBB0000
                    if (k + 1 >= insnsSize) {
                        return false;
                    }
                    int lit = u2(dex, insnsOff + (k + 1) * 2) << 16;
                    if (lit == value) {
                        return true;
                    }
                    k += 2;
                    break;
                }
                case 0x1A: // const-string
                    k += 2;
                    break;
                case 0x1B: // const-string/jumbo
                    k += 3;
                    break;
                default:
                    k += 1;
                    break;
            }
        }
        return false;
    }


    /** Returns classes.dex, classes2.dex ... in load order. */
    private static List<String> dexEntryNames(ZipFile zip) {
        List<String> names = new ArrayList<>();
        var entries = zip.entries();
        while (entries.hasMoreElements()) {
            ZipEntry entry = entries.nextElement();
            String name = entry.getName();
            if (name.length() >= 11
                    && name.startsWith("classes")
                    && name.endsWith(".dex")
                    && !name.contains("/")) {
                names.add(name);
            }
        }
        names.sort((a, b) -> {
            int na = dexOrdinal(a);
            int nb = dexOrdinal(b);
            return Integer.compare(na, nb);
        });
        return names;
    }

    private static int dexOrdinal(String name) {
        String middle = name.substring("classes".length(), name.length() - ".dex".length());
        if (middle.isEmpty()) {
            return 1;
        }
        try {
            return Integer.parseInt(middle);
        } catch (NumberFormatException e) {
            return Integer.MAX_VALUE;
        }
    }

    private static byte[] readEntry(ZipFile zip, ZipEntry entry) throws IOException {
        long size = entry.getSize();
        if (size <= 0) {
            return null;
        }
        if (size > 96L * 1024L * 1024L) {
            return null;
        }
        byte[] data = new byte[(int) size];
        int read = 0;
        try (InputStream in = zip.getInputStream(entry)) {
            while (read < data.length) {
                int n = in.read(data, read, data.length - read);
                if (n < 0) {
                    break;
                }
                read += n;
            }
        }
        return read == data.length ? data : null;
    }

    private static void scanDex(byte[] dex, String dexName, Set<String> pending,
                                Set<String> seenMethods, ScanReport report) {
        if (dex.length < 0x70 || u4(dex, 0) != 0x0a786564L) {
            return;
        }
        int stringIdsSize = i4(dex, 0x38);
        int stringIdsOff = i4(dex, 0x3C);
        int typeIdsOff = i4(dex, 0x44);
        int protoIdsOff = i4(dex, 0x4C);
        int methodIdsOff = i4(dex, 0x5C);
        int classDefsSize = i4(dex, 0x60);
        int classDefsOff = i4(dex, 0x64);
        if (stringIdsSize <= 0 || classDefsSize <= 0) {
            return;
        }

        Map<Integer, String> stringIndexToFlag = new HashMap<>();
        for (String flagId : pending) {
            int index = findStringIndex(dex, stringIdsSize, stringIdsOff, flagId);
            if (index >= 0) {
                stringIndexToFlag.put(index, flagId);
            }
        }
        if (stringIndexToFlag.isEmpty()) {
            return;
        }

        boolean[] foundHere = new boolean[pending.size()];
        for (int i = 0; i < classDefsSize; i++) {
            int classDefOff = classDefsOff + i * 32;
            if (classDefOff + 32 > dex.length) {
                break;
            }
            int classIdx = i4(dex, classDefOff);
            int classDataOff = i4(dex, classDefOff + 24);
            if (classDataOff == 0) {
                continue;
            }
            Cursor cursor = new Cursor(dex, classDataOff);
            int staticFields = cursor.uleb();
            int instanceFields = cursor.uleb();
            int directMethods = cursor.uleb();
            int virtualMethods = cursor.uleb();
            if (staticFields < 0 || instanceFields < 0 || directMethods < 0 || virtualMethods < 0) {
                continue;
            }
            for (int f = 0; f < staticFields + instanceFields; f++) {
                if (cursor.uleb() < 0 || cursor.uleb() < 0) {
                    break;
                }
            }
            if (cursor.pointer >= dex.length) {
                continue;
            }
            int methodIdx = 0;
            int totalMethods = directMethods + virtualMethods;
            String className = null;
            for (int m = 0; m < totalMethods; m++) {
                // The first element of each list (direct, then virtual) is represented
                // directly, so the diff accumulator restarts at the boundary.
                if (m == directMethods) {
                    methodIdx = 0;
                }
                int methodIdxDiff = cursor.uleb();
                int accessFlags = cursor.uleb();
                int codeOff = cursor.uleb();
                if (methodIdxDiff < 0 || accessFlags < 0 || codeOff < 0) {
                    break;
                }
                methodIdx += methodIdxDiff;
                if (codeOff == 0 || codeOff + 16 > dex.length) {
                    continue;
                }
                String flagId = scanMethodCode(dex, methodIdx, codeOff, methodIdsOff, protoIdsOff,
                        typeIdsOff, stringIdsOff, stringIdsSize, stringIndexToFlag);
                if (flagId == null) {
                    continue;
                }
                if (className == null) {
                    className = typeName(dex, classIdx, typeIdsOff, stringIdsOff, stringIdsSize);
                    if (className == null) {
                        break;
                    }
                }
                String methodName = methodName(dex, methodIdx, methodIdsOff, stringIdsOff, stringIdsSize);
                if (methodName == null) {
                    continue;
                }
                String key = className + "#" + methodName;
                if (!seenMethods.add(key)) {
                    continue;
                }
                report.hits.add(new FlagMethod(flagId, descriptorToClassName(className), methodName, dexName));
                pending.remove(flagId);
                if (pending.isEmpty()) {
                    return;
                }
            }
            if (pending.isEmpty()) {
                return;
            }
        }
    }

    /**
     * Returns the flag id referenced from a zero-argument boolean method, or null.
     */
    private static String scanMethodCode(byte[] dex, int methodIdx, int codeOff, int methodIdsOff,
                                         int protoIdsOff, int typeIdsOff, int stringIdsOff,
                                         int stringIdsSize, Map<Integer, String> stringIndexToFlag) {
        int methodOff = methodIdsOff + methodIdx * 8;
        if (methodOff + 8 > dex.length) {
            return null;
        }
        int protoIdx = u2(dex, methodOff + 2);
        int protoOff = protoIdsOff + protoIdx * 12;
        if (protoOff + 12 > dex.length) {
            return null;
        }
        int returnTypeIdx = i4(dex, protoOff + 4);
        int parametersOff = i4(dex, protoOff + 8);
        if (parametersOff != 0) {
            return null;
        }
        String returnType = typeName(dex, returnTypeIdx, typeIdsOff, stringIdsOff, stringIdsSize);
        if (!"Z".equals(returnType)) {
            return null;
        }
        int insnsSize = i4(dex, codeOff + 12);
        int insnsOff = codeOff + 16;
        if (insnsSize <= 0 || insnsSize > 0x400000 || insnsOff + insnsSize * 2 > dex.length) {
            return null;
        }
        for (int k = 0; k + 1 < insnsSize; k++) {
            int opcode = u2(dex, insnsOff + k * 2) & 0xFF;
            if (opcode == 0x1A) {
                int index = u2(dex, insnsOff + (k + 1) * 2);
                String flagId = stringIndexToFlag.get(index);
                if (flagId != null) {
                    return flagId;
                }
                k++;
            } else if (opcode == 0x1B && k + 2 < insnsSize) {
                int index = u2(dex, insnsOff + (k + 1) * 2) | (u2(dex, insnsOff + (k + 2) * 2) << 16);
                String flagId = stringIndexToFlag.get(index);
                if (flagId != null) {
                    return flagId;
                }
                k += 2;
            }
        }
        return null;
    }

    /** "Ldefpackage/xce;" -> "defpackage.xce" */
    private static String descriptorToClassName(String descriptor) {
        if (descriptor.length() > 2 && descriptor.charAt(0) == 'L' && descriptor.endsWith(";")) {
            return descriptor.substring(1, descriptor.length() - 1).replace('/', '.');
        }
        return descriptor;
    }

    private static int findStringIndex(byte[] dex, int size, int offset, String target) {
        int lo = 0;
        int hi = size - 1;
        while (lo <= hi) {
            int mid = (lo + hi) >>> 1;
            int dataOff = i4(dex, offset + mid * 4);
            String value = readString(dex, dataOff, target.length() + 4);
            if (value == null) {
                return -1;
            }
            int cmp = value.compareTo(target);
            if (cmp == 0) {
                return mid;
            }
            if (cmp < 0) {
                lo = mid + 1;
            } else {
                hi = mid - 1;
            }
        }
        return -1;
    }

    private static String readString(byte[] dex, int off, int cap) {
        if (off <= 0 || off >= dex.length) {
            return null;
        }
        int[] position = {off};
        int utf16Length = uleb128(dex, position);
        if (utf16Length < 0) {
            return null;
        }
        int end = Math.min(utf16Length, cap);
        StringBuilder sb = new StringBuilder(end);
        int p = position[0];
        for (int i = 0; i < end && p < dex.length; i++) {
            int b = dex[p++] & 0xFF;
            if (b < 0x80) {
                sb.append((char) b);
            } else if ((b & 0xE0) == 0xC0 && p < dex.length) {
                int b2 = dex[p++] & 0x3F;
                sb.append((char) (((b & 0x1F) << 6) | b2));
            } else if ((b & 0xF0) == 0xE0 && p + 1 < dex.length) {
                int b2 = dex[p++] & 0x3F;
                int b3 = dex[p++] & 0x3F;
                sb.append((char) (((b & 0x0F) << 12) | (b2 << 6) | b3));
            }
        }
        return sb.toString();
    }

    private static String typeName(byte[] dex, int typeIdx, int typeIdsOff, int stringIdsOff, int stringIdsSize) {
        if (typeIdx < 0 || typeIdsOff + typeIdx * 4 + 4 > dex.length) {
            return null;
        }
        int stringIdx = i4(dex, typeIdsOff + typeIdx * 4);
        if (stringIdx < 0 || stringIdx >= stringIdsSize) {
            return null;
        }
        int dataOff = i4(dex, stringIdsOff + stringIdx * 4);
        return readString(dex, dataOff, 256);
    }

    private static String methodName(byte[] dex, int methodIdx, int methodIdsOff, int stringIdsOff, int stringIdsSize) {
        int methodOff = methodIdsOff + methodIdx * 8;
        if (methodOff + 8 > dex.length) {
            return null;
        }
        int nameIdx = i4(dex, methodOff + 4);
        if (nameIdx < 0 || nameIdx >= stringIdsSize) {
            return null;
        }
        int dataOff = i4(dex, stringIdsOff + nameIdx * 4);
        return readString(dex, dataOff, 256);
    }

    private static int uleb128(byte[] dex, int[] position) {
        int result = 0;
        int shift = 0;
        int p = position[0];
        while (p < dex.length) {
            int b = dex[p++] & 0xFF;
            result |= (b & 0x7F) << shift;
            if ((b & 0x80) == 0) {
                position[0] = p;
                return result;
            }
            shift += 7;
            if (shift > 28) {
                return -1;
            }
        }
        return -1;
    }

    private static int u2(byte[] data, int off) {
        return (data[off] & 0xFF) | ((data[off + 1] & 0xFF) << 8);
    }

    private static int i4(byte[] data, int off) {
        return (data[off] & 0xFF)
                | ((data[off + 1] & 0xFF) << 8)
                | ((data[off + 2] & 0xFF) << 16)
                | ((data[off + 3] & 0xFF) << 24);
    }

    private static long u4(byte[] data, int off) {
        return i4(data, off) & 0xFFFFFFFFL;
    }

    /** Minimal uleb128 cursor over a class_data_item. */
    private static final class Cursor {
        final byte[] data;
        final int[] holder;
        int pointer;

        Cursor(byte[] data, int offset) {
            this.data = data;
            this.pointer = offset;
            this.holder = new int[]{offset};
        }

        int uleb() {
            holder[0] = pointer;
            int value = uleb128(data, holder);
            pointer = holder[0];
            return value;
        }
    }
}
