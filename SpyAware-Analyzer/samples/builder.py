"""Synthetic sample APK generator and signer for SpyAware-Analyzer.

Builds valid AndroidManifest.xml and synthetic APK packages representing
benign applications, suspicious surveillance packages, and critical stalkerware,
plus malformed/unsupported APK files for defensive testing.

Supports Android SDK packaging and signing:
1. Manifest compilation via aapt
2. Synthetic DEX and native library injection
3. 4-byte zipalign
4. Signature via apksigner (v1, v2, v3 schemes) using a local debug keystore
5. Verification via apksigner
"""

import os
import shutil
import struct
import subprocess
import tempfile
import zipfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

SAMPLES_DIR = Path(__file__).resolve().parent


def find_android_build_tools() -> Dict[str, Optional[str]]:
    """Discovers host Android SDK build tools, platform jars, and keytool."""
    android_home = (
        os.environ.get("ANDROID_HOME")
        or os.environ.get("ANDROID_SDK_ROOT")
        or str(Path.home() / "Android" / "Sdk")
    )

    tools: Dict[str, Optional[str]] = {
        "aapt": shutil.which("aapt"),
        "zipalign": shutil.which("zipalign"),
        "apksigner": shutil.which("apksigner"),
        "keytool": shutil.which("keytool") or "/usr/bin/keytool" if os.path.exists("/usr/bin/keytool") else None,
        "javac": shutil.which("javac") or "/usr/bin/javac" if os.path.exists("/usr/bin/javac") else None,
        "d8": shutil.which("d8"),
        "android_jar": None,
    }

    # Search build-tools directories in ANDROID_HOME
    sdk_path = Path(android_home)
    build_tools_dir = sdk_path / "build-tools"
    if build_tools_dir.exists() and build_tools_dir.is_dir():
        versions = sorted([p for p in build_tools_dir.iterdir() if p.is_dir()], reverse=True)
        for ver_dir in versions:
            if not tools["aapt"]:
                aapt_candidate = ver_dir / "aapt"
                if aapt_candidate.exists() and os.access(aapt_candidate, os.X_OK):
                    tools["aapt"] = str(aapt_candidate)
            if not tools["zipalign"]:
                zipalign_candidate = ver_dir / "zipalign"
                if zipalign_candidate.exists() and os.access(zipalign_candidate, os.X_OK):
                    tools["zipalign"] = str(zipalign_candidate)
            if not tools["apksigner"]:
                apksigner_candidate = ver_dir / "apksigner"
                if apksigner_candidate.exists() and os.access(apksigner_candidate, os.X_OK):
                    tools["apksigner"] = str(apksigner_candidate)
            if not tools.get("d8"):
                d8_candidate = ver_dir / "d8"
                if d8_candidate.exists() and os.access(d8_candidate, os.X_OK):
                    tools["d8"] = str(d8_candidate)

    # Search platforms for android.jar
    platforms_dir = sdk_path / "platforms"
    if platforms_dir.exists() and platforms_dir.is_dir():
        platforms = sorted([p for p in platforms_dir.iterdir() if p.is_dir()], reverse=True)
        for plat in platforms:
            jar_candidate = plat / "android.jar"
            if jar_candidate.exists():
                tools["android_jar"] = str(jar_candidate)
                break

    return tools


def ensure_debug_keystore(keystore_path: Optional[Path] = None) -> Path:
    """Ensures a local debug keystore is present for signing test APKs.
    
    If the keystore does not exist, uses keytool to generate a standard Android
    debug keystore with alias 'androiddebugkey' and password 'android'.
    """
    ks = keystore_path or (Path.home() / ".android" / "debug.keystore")
    if ks.exists():
        return ks

    ks.parent.mkdir(parents=True, exist_ok=True)
    keytool = shutil.which("keytool") or "/usr/bin/keytool"
    if not (os.path.exists(keytool) and os.access(keytool, os.X_OK)):
        raise RuntimeError(f"keytool not found; cannot generate local debug keystore at {ks}")

    cmd = [
        keytool,
        "-genkeypair",
        "-v",
        "-keystore",
        str(ks),
        "-alias",
        "androiddebugkey",
        "-keyalg",
        "RSA",
        "-keysize",
        "2048",
        "-validity",
        "10000",
        "-storepass",
        "android",
        "-keypass",
        "android",
        "-dname",
        "CN=Android Debug,O=Android,C=US",
    ]
    subprocess.run(cmd, check=True, capture_output=True, text=True)
    return ks


def zipalign_apk(
    input_apk: Path,
    output_apk: Path,
    zipalign_path: Optional[str] = None,
) -> bool:
    """Aligns an APK to 4-byte boundaries using zipalign."""
    tools = find_android_build_tools()
    zipalign = zipalign_path or tools["zipalign"]
    if not zipalign or not os.path.exists(zipalign):
        # Fallback: copy file without alignment
        shutil.copyfile(input_apk, output_apk)
        return False

    cmd = [zipalign, "-f", "-p", "4", str(input_apk), str(output_apk)]
    res = subprocess.run(cmd, capture_output=True, text=True)
    if res.returncode != 0:
        raise RuntimeError(f"zipalign failed: {res.stderr}")
    return True


def sign_apk(
    apk_path: Path,
    keystore_path: Optional[Path] = None,
    apksigner_path: Optional[str] = None,
) -> bool:
    """Signs an APK using apksigner with Android v1, v2, and v3 signature schemes."""
    tools = find_android_build_tools()
    apksigner = apksigner_path or tools["apksigner"]
    ks = ensure_debug_keystore(keystore_path)

    if not apksigner or not os.path.exists(apksigner):
        # Fallback to jarsigner if apksigner not available
        jarsigner = shutil.which("jarsigner") or "/usr/bin/jarsigner"
        if jarsigner and os.path.exists(jarsigner):
            cmd = [
                jarsigner,
                "-keystore",
                str(ks),
                "-storepass",
                "android",
                "-keypass",
                "android",
                str(apk_path),
                "androiddebugkey",
            ]
            res = subprocess.run(cmd, capture_output=True, text=True)
            return res.returncode == 0
        return False

    cmd = [
        apksigner,
        "sign",
        "--ks",
        str(ks),
        "--ks-pass",
        "pass:android",
        "--ks-key-alias",
        "androiddebugkey",
        "--key-pass",
        "pass:android",
        "--v1-signing-enabled",
        "true",
        "--v2-signing-enabled",
        "true",
        "--v3-signing-enabled",
        "true",
        str(apk_path),
    ]
    res = subprocess.run(cmd, capture_output=True, text=True)
    if res.returncode != 0:
        raise RuntimeError(f"apksigner failed: {res.stderr}")
    return True


def verify_apk_signature(
    apk_path: Path,
    apksigner_path: Optional[str] = None,
) -> Dict[str, Any]:
    """Verifies APK signature using apksigner."""
    tools = find_android_build_tools()
    apksigner = apksigner_path or tools["apksigner"]

    result = {
        "verified": False,
        "v1": False,
        "v2": False,
        "v3": False,
        "signer_dn": None,
        "signer_sha256": None,
        "raw_output": "",
    }

    if not apksigner or not os.path.exists(apksigner):
        result["raw_output"] = "apksigner not available on host"
        return result

    cmd = [apksigner, "verify", "--verbose", "--print-certs", str(apk_path)]
    res = subprocess.run(cmd, capture_output=True, text=True)
    result["raw_output"] = res.stdout + ("\n" + res.stderr if res.stderr else "")

    if res.returncode == 0:
        result["verified"] = True
        for line in res.stdout.splitlines():
            line_str = line.strip()
            if "Verified using v1 scheme" in line_str and "true" in line_str.lower():
                result["v1"] = True
            elif "Verified using v2 scheme" in line_str and "true" in line_str.lower():
                result["v2"] = True
            elif "Verified using v3 scheme" in line_str and "true" in line_str.lower():
                result["v3"] = True
            elif "certificate DN:" in line_str:
                result["signer_dn"] = line_str.split("certificate DN:", 1)[1].strip()
            elif "certificate SHA-256 digest:" in line_str:
                result["signer_sha256"] = line_str.split("certificate SHA-256 digest:", 1)[1].strip()

    return result


def build_binary_axml(package_name: str, permissions: Optional[List[str]] = None) -> bytes:
    """Encodes a basic binary AndroidManifest.xml (pure Python fallback)."""
    perms = permissions or []
    strings = [
        "android",                                    # 0
        "http://schemas.android.com/apk/res/android", # 1
        "manifest",                                   # 2
        "package",                                    # 3
        "uses-permission",                            # 4
        "name",                                       # 5
        package_name,                                 # 6
    ] + perms

    string_count = len(strings)
    flags = 1 << 8  # UTF-8
    offsets = []
    encoded_strings = []
    cur_offset = 0

    for s in strings:
        offsets.append(cur_offset)
        raw = s.encode("utf-8")
        b = bytes([len(s), len(raw)]) + raw + b"\x00"
        encoded_strings.append(b)
        cur_offset += len(b)

    strings_data = b"".join(encoded_strings)
    rem = len(strings_data) % 4
    if rem:
        strings_data += b"\x00" * (4 - rem)

    offsets_data = b"".join(struct.pack("<I", o) for o in offsets)
    header_size = 28
    strings_start = header_size + len(offsets_data)
    pool_chunk_size = strings_start + len(strings_data)
    string_pool = struct.pack(
        "<HHIIIIII",
        0x0001,
        header_size,
        pool_chunk_size,
        string_count,
        0,
        flags,
        strings_start,
        0,
    ) + offsets_data + strings_data

    nodes = []
    # Start namespace
    ns_start = struct.pack("<HHIIIII", 0x0100, 16, 24, 1, 0xFFFFFFFF, 0, 1)
    nodes.append(ns_start)

    # Start element manifest
    pkg_attr = struct.pack("<IIIII", 0xFFFFFFFF, 3, 6, (3 << 24) | 8, 6)
    elem_manifest = struct.pack(
        "<HHIIIIIHHII", 0x0102, 16, 36 + 20, 1, 0xFFFFFFFF, 0xFFFFFFFF, 2, 20, 20, 1, 0
    ) + pkg_attr
    nodes.append(elem_manifest)

    # uses-permission tags
    for i, p in enumerate(perms):
        p_idx = 7 + i
        p_attr = struct.pack("<IIIII", 1, 5, p_idx, (3 << 24) | 8, p_idx)
        elem_perm = struct.pack(
            "<HHIIIIIHHII", 0x0102, 16, 36 + 20, 2 + i, 0xFFFFFFFF, 0xFFFFFFFF, 4, 20, 20, 1, 0
        ) + p_attr
        nodes.append(elem_perm)
        end_perm = struct.pack("<HHIIIII", 0x0103, 16, 24, 2 + i, 0xFFFFFFFF, 0xFFFFFFFF, 4)
        nodes.append(end_perm)

    # End element manifest
    end_manifest = struct.pack("<HHIIIII", 0x0103, 16, 24, 100, 0xFFFFFFFF, 0xFFFFFFFF, 2)
    nodes.append(end_manifest)

    # End namespace
    ns_end = struct.pack("<HHIIIII", 0x0101, 16, 24, 100, 0xFFFFFFFF, 0, 1)
    nodes.append(ns_end)

    xml_content = b"".join(nodes)
    total_size = 8 + len(string_pool) + len(xml_content)
    file_header = struct.pack("<HHI", 0x0003, 8, total_size)
    return file_header + string_pool + xml_content


def generate_synthetic_dex(strings: List[str]) -> bytes:
    """Builds a basic DEX byte buffer embedding the specified string literals."""
    str_data_items = []
    offsets = []
    cur_offset = 0x70 + (len(strings) * 4)  # right after string_ids table

    for s in strings:
        raw = s.encode("utf-8")
        item = bytes([len(s)]) + raw + b"\x00"
        str_data_items.append(item)
        offsets.append(cur_offset)
        cur_offset += len(item)

    string_ids = b"".join(struct.pack("<I", off) for off in offsets)
    all_str_data = b"".join(str_data_items)

    total_size = 0x70 + len(string_ids) + len(all_str_data)

    # DEX 035 Header (112 bytes = 0x70)
    magic = b"dex\n035\x00"
    checksum = 0x12345678
    signature = b"\x00" * 20
    file_size = total_size
    header_size = 0x70
    endian_tag = 0x12345678
    link_size = 0
    link_off = 0
    map_off = 0
    string_ids_size = len(strings)
    string_ids_off = 0x70
    type_ids_size = 0
    type_ids_off = 0
    proto_ids_size = 0
    proto_ids_off = 0
    field_ids_size = 0
    field_ids_off = 0
    method_ids_size = 0
    method_ids_off = 0
    class_defs_size = 0
    class_defs_off = 0
    data_size = len(all_str_data)
    data_off = 0x70 + len(string_ids)

    header = struct.pack(
        "<8sI20sIIIIIIIIIIIIIIIIIIII",
        magic,
        checksum,
        signature,
        file_size,
        header_size,
        endian_tag,
        link_size,
        link_off,
        map_off,
        string_ids_size,
        string_ids_off,
        type_ids_size,
        type_ids_off,
        proto_ids_size,
        proto_ids_off,
        field_ids_size,
        field_ids_off,
        method_ids_size,
        method_ids_off,
        class_defs_size,
        class_defs_off,
        data_size,
        data_off,
    )

    return header + string_ids + all_str_data


def compile_manifest_with_aapt(
    manifest_xml: str,
    output_apk: Path,
    aapt_path: Optional[str] = None,
    android_jar_path: Optional[str] = None,
) -> bool:
    """Compiles AndroidManifest.xml into output_apk using aapt."""
    tools = find_android_build_tools()
    aapt = aapt_path or tools["aapt"]
    android_jar = android_jar_path or tools["android_jar"]

    if not aapt or not android_jar:
        return False

    with tempfile.TemporaryDirectory() as td:
        manifest_file = Path(td) / "AndroidManifest.xml"
        manifest_file.write_text(manifest_xml, encoding="utf-8")

        cmd = [
            aapt,
            "package",
            "-f",
            "-M",
            str(manifest_file),
            "-I",
            android_jar,
            "-F",
            str(output_apk),
        ]
        res = subprocess.run(cmd, capture_output=True, text=True)
        return res.returncode == 0


def compile_real_dex(
    package_name: str,
    dex_strings: List[str],
    tools: Dict[str, Optional[str]],
    custom_sources: Optional[Dict[str, str]] = None,
) -> Optional[bytes]:
    """Compiles valid Activity and component classes embedding dex_strings into classes.dex."""
    javac = tools.get("javac")
    d8 = tools.get("d8")
    android_jar = tools.get("android_jar")
    if not (javac and d8 and android_jar):
        return None

    try:
        with tempfile.TemporaryDirectory() as td:
            td_path = Path(td)
            pkg_path = td_path / "src" / Path(*package_name.split("."))
            pkg_path.mkdir(parents=True, exist_ok=True)

            if custom_sources:
                for fname, src in custom_sources.items():
                    (pkg_path / fname).write_text(src, encoding="utf-8")
            else:
                escaped_strings = []
                for s in dex_strings:
                    clean_s = s.replace("\\", "\\\\").replace('"', '\\"')
                    escaped_strings.append(f'        "{clean_s}"')
                strings_literal = ",\n".join(escaped_strings)

                java_src = f"""package {package_name};

import android.app.Activity;
import android.os.Bundle;

public class MainActivity extends Activity {{
    public static final String[] INDICATORS = new String[] {{
{strings_literal}
    }};

    @Override
    protected void onCreate(Bundle savedInstanceState) {{
        super.onCreate(savedInstanceState);
    }}
}}
"""
                java_file = pkg_path / "MainActivity.java"
                java_file.write_text(java_src, encoding="utf-8")

            classes_dir = td_path / "classes"
            classes_dir.mkdir(parents=True, exist_ok=True)

            java_files = [str(p) for p in pkg_path.glob("*.java")]
            if not java_files:
                return None

            javac_cmd = [
                javac,
                "--release", "11",
                "-cp", android_jar,
                "-d", str(classes_dir),
            ] + java_files
            res_javac = subprocess.run(javac_cmd, capture_output=True, text=True, check=False)
            if res_javac.returncode != 0:
                return None

            dex_dir = td_path / "dex"
            dex_dir.mkdir(parents=True, exist_ok=True)
            class_files = [str(p) for p in classes_dir.rglob("*.class")]
            if not class_files:
                return None

            d8_cmd = [
                d8,
                "--output", str(dex_dir),
                "--lib", android_jar,
            ] + class_files
            res_d8 = subprocess.run(d8_cmd, capture_output=True, text=True, check=False)
            if res_d8.returncode != 0:
                return None

            out_dex = dex_dir / "classes.dex"
            if out_dex.exists():
                return out_dex.read_bytes()
    except Exception:
        return None
    return None


def build_and_sign_apk(
    output_apk_path: Path,
    package_name: str,
    manifest_xml: str,
    dex_strings: List[str],
    native_libs: Optional[Dict[str, bytes]] = None,
    permissions_fallback: Optional[List[str]] = None,
    custom_sources: Optional[Dict[str, str]] = None,
) -> Path:
    """Builds, aligns, signs, and verifies a complete synthetic APK."""
    tools = find_android_build_tools()
    real_dex = compile_real_dex(package_name, dex_strings, tools, custom_sources=custom_sources)
    if real_dex:
        dex_bytes = real_dex
    else:
        dex_bytes = generate_synthetic_dex(dex_strings)

    with tempfile.TemporaryDirectory() as td:
        raw_apk = Path(td) / "raw.apk"
        aligned_apk = Path(td) / "aligned.apk"

        # 1. Compile manifest with aapt if available
        aapt_ok = compile_manifest_with_aapt(manifest_xml, raw_apk, tools["aapt"], tools["android_jar"])
        if not aapt_ok:
            # Pure Python fallback
            axml_bytes = build_binary_axml(package_name, permissions_fallback or [])
            with zipfile.ZipFile(raw_apk, "w") as zf:
                zf.writestr("AndroidManifest.xml", axml_bytes)

        # 2. Add classes.dex and native libraries
        with zipfile.ZipFile(raw_apk, "a") as zf:
            zf.writestr("classes.dex", dex_bytes)
            if native_libs:
                for lib_path, lib_bytes in native_libs.items():
                    zf.writestr(lib_path, lib_bytes)

        # 3. Zipalign (4-byte alignment)
        zipalign_apk(raw_apk, aligned_apk, tools["zipalign"])

        # 4. Sign APK (v1, v2, v3 schemes)
        sign_apk(aligned_apk, apksigner_path=tools["apksigner"])

        # 5. Copy to target destination
        output_apk_path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(aligned_apk, output_apk_path)

    return output_apk_path


def build_camera_positive_sample(output_apk: Path) -> Path:
    """Builds a positive control APK that genuinely initializes and opens the Camera API."""
    manifest = """<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.spyaware.positive.camera"
    android:versionCode="1"
    android:versionName="1.0">
    <uses-sdk android:minSdkVersion="26" android:targetSdkVersion="34" />
    <uses-permission android:name="android.permission.CAMERA" />
    <application android:label="Camera Positive Sample">
        <activity android:name=".MainActivity" android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>
    </application>
</manifest>
"""
    java_src = """package com.spyaware.positive.camera;

import android.app.Activity;
import android.content.Context;
import android.hardware.camera2.CameraDevice;
import android.hardware.camera2.CameraManager;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.util.Log;

public class MainActivity extends Activity {
    private static final String TAG = "SpyAwareCameraTest";
    private CameraDevice mCameraDevice;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        Log.i(TAG, "Starting positive camera control for com.spyaware.positive.camera");
        try {
            CameraManager manager = (CameraManager) getSystemService(Context.CAMERA_SERVICE);
            if (manager != null) {
                String[] cameraIds = manager.getCameraIdList();
                if (cameraIds != null && cameraIds.length > 0) {
                    String cameraId = cameraIds[0];
                    Log.i(TAG, "Opening camera: " + cameraId);
                    manager.openCamera(cameraId, new CameraDevice.StateCallback() {
                        @Override
                        public void onOpened(CameraDevice camera) {
                            mCameraDevice = camera;
                            Log.i(TAG, "CameraDevice openCamera successfully opened: " + camera.getId());
                        }

                        @Override
                        public void onDisconnected(CameraDevice camera) {
                            camera.close();
                            mCameraDevice = null;
                        }

                        @Override
                        public void onError(CameraDevice camera, int error) {
                            Log.w(TAG, "Camera open error: " + error);
                            camera.close();
                            mCameraDevice = null;
                        }
                    }, new Handler(Looper.getMainLooper()));
                } else {
                    Log.w(TAG, "No camera IDs reported by CameraManager");
                }
            }
        } catch (SecurityException se) {
            Log.e(TAG, "Camera security exception: " + se.getMessage());
        } catch (Exception e) {
            Log.e(TAG, "Camera exception: " + e.getMessage());
        }
    }

    @Override
    protected void onDestroy() {
        super.onDestroy();
        if (mCameraDevice != null) {
            try {
                mCameraDevice.close();
            } catch (Exception ignored) {}
            mCameraDevice = null;
        }
    }
}
"""
    return build_and_sign_apk(
        output_apk_path=output_apk,
        package_name="com.spyaware.positive.camera",
        manifest_xml=manifest,
        dex_strings=["openCamera", "CameraManager", "CameraDevice"],
        custom_sources={"MainActivity.java": java_src},
    )


def build_microphone_positive_sample(output_apk: Path) -> Path:
    """Builds a positive control APK that genuinely initializes and starts an AudioRecord capture session."""
    manifest = """<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.spyaware.positive.mic"
    android:versionCode="1"
    android:versionName="1.0">
    <uses-sdk android:minSdkVersion="26" android:targetSdkVersion="34" />
    <uses-permission android:name="android.permission.RECORD_AUDIO" />
    <application android:label="Microphone Positive Sample">
        <activity android:name=".MainActivity" android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>
    </application>
</manifest>
"""
    java_src = """package com.spyaware.positive.mic;

import android.app.Activity;
import android.media.AudioFormat;
import android.media.AudioRecord;
import android.media.MediaRecorder;
import android.os.Bundle;
import android.util.Log;

public class MainActivity extends Activity {
    private static final String TAG = "SpyAwareMicTest";
    private AudioRecord mRecorder;
    private Thread mRecordThread;
    private volatile boolean mIsRecording = false;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        Log.i(TAG, "Starting positive audio recording control for com.spyaware.positive.mic");
        try {
            int sampleRate = 16000;
            int channelConfig = AudioFormat.CHANNEL_IN_MONO;
            int audioFormat = AudioFormat.ENCODING_PCM_16BIT;
            int minBufferSize = AudioRecord.getMinBufferSize(sampleRate, channelConfig, audioFormat);
            int bufferSize = Math.max(minBufferSize, 2048);

            mRecorder = new AudioRecord(
                MediaRecorder.AudioSource.MIC,
                sampleRate,
                channelConfig,
                audioFormat,
                bufferSize
            );

            if (mRecorder.getState() == AudioRecord.STATE_INITIALIZED) {
                mRecorder.startRecording();
                mIsRecording = true;
                Log.i(TAG, "AudioRecord startRecording succeeded for package com.spyaware.positive.mic");

                mRecordThread = new Thread(new Runnable() {
                    @Override
                    public void run() {
                        byte[] buffer = new byte[1024];
                        while (mIsRecording && mRecorder != null) {
                            try {
                                mRecorder.read(buffer, 0, buffer.length);
                                Thread.sleep(100);
                            } catch (Exception ignored) {
                                break;
                            }
                        }
                    }
                });
                mRecordThread.start();
            } else {
                Log.w(TAG, "AudioRecord failed to initialize");
            }
        } catch (Exception e) {
            Log.e(TAG, "AudioRecord exception: " + e.getMessage());
        }
    }

    @Override
    protected void onDestroy() {
        super.onDestroy();
        mIsRecording = false;
        if (mRecorder != null) {
            try {
                mRecorder.stop();
                mRecorder.release();
            } catch (Exception ignored) {}
            mRecorder = null;
        }
    }
}
"""
    return build_and_sign_apk(
        output_apk_path=output_apk,
        package_name="com.spyaware.positive.mic",
        manifest_xml=manifest,
        dex_strings=["AudioRecord", "startRecording", "MediaRecorder"],
        custom_sources={"MainActivity.java": java_src},
    )


def build_location_positive_sample(output_apk: Path) -> Path:
    """Builds a positive control APK that genuinely registers a LocationListener with LocationManager."""
    manifest = """<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.spyaware.positive.location"
    android:versionCode="1"
    android:versionName="1.0">
    <uses-sdk android:minSdkVersion="26" android:targetSdkVersion="34" />
    <uses-permission android:name="android.permission.ACCESS_FINE_LOCATION" />
    <uses-permission android:name="android.permission.ACCESS_COARSE_LOCATION" />
    <application android:label="Location Positive Sample">
        <activity android:name=".MainActivity" android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>
    </application>
</manifest>
"""
    java_src = """package com.spyaware.positive.location;

import android.app.Activity;
import android.content.Context;
import android.location.Location;
import android.location.LocationListener;
import android.location.LocationManager;
import android.os.Bundle;
import android.os.Looper;
import android.util.Log;

public class MainActivity extends Activity implements LocationListener {
    private static final String TAG = "SpyAwareLocTest";
    private LocationManager mLocationManager;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        Log.i(TAG, "Starting positive location control for com.spyaware.positive.location");
        try {
            mLocationManager = (LocationManager) getSystemService(Context.LOCATION_SERVICE);
            if (mLocationManager != null) {
                String provider = LocationManager.PASSIVE_PROVIDER;
                if (mLocationManager.isProviderEnabled(LocationManager.GPS_PROVIDER)) {
                    provider = LocationManager.GPS_PROVIDER;
                }
                Log.i(TAG, "Requesting location updates from " + provider + " for com.spyaware.positive.location");
                mLocationManager.requestLocationUpdates(
                    provider,
                    1000L,
                    0.0f,
                    this,
                    Looper.getMainLooper()
                );
            }
        } catch (SecurityException se) {
            Log.e(TAG, "Location security exception: " + se.getMessage());
        } catch (Exception e) {
            Log.e(TAG, "Location exception: " + e.getMessage());
        }
    }

    @Override
    public void onLocationChanged(Location location) {
        Log.i(TAG, "Location received: " + location);
    }

    @Override
    public void onStatusChanged(String provider, int status, Bundle extras) {}

    @Override
    public void onProviderEnabled(String provider) {}

    @Override
    public void onProviderDisabled(String provider) {}

    @Override
    protected void onDestroy() {
        super.onDestroy();
        if (mLocationManager != null) {
            try {
                mLocationManager.removeUpdates(this);
            } catch (Exception ignored) {}
        }
    }
}
"""
    return build_and_sign_apk(
        output_apk_path=output_apk,
        package_name="com.spyaware.positive.location",
        manifest_xml=manifest,
        dex_strings=["requestLocationUpdates", "LocationManager", "LocationListener"],
        custom_sources={"MainActivity.java": java_src},
    )


def build_service_positive_sample(output_apk: Path) -> Path:
    """Builds a positive control APK that starts and maintains an active background Service."""
    manifest = """<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.spyaware.positive.service"
    android:versionCode="1"
    android:versionName="1.0">
    <uses-sdk android:minSdkVersion="26" android:targetSdkVersion="34" />
    <application android:label="Service Positive Sample">
        <activity android:name=".MainActivity" android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>
        <service android:name=".MonitoringService" android:exported="false" />
    </application>
</manifest>
"""
    svc_src = """package com.spyaware.positive.service;

import android.app.Service;
import android.content.Intent;
import android.os.IBinder;
import android.util.Log;

public class MonitoringService extends Service {
    private static final String TAG = "SpyAwareSvcTest";

    @Override
    public void onCreate() {
        super.onCreate();
        Log.i(TAG, "MonitoringService created for com.spyaware.positive.service");
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        Log.i(TAG, "MonitoringService running background task for com.spyaware.positive.service");
        return START_STICKY;
    }

    @Override
    public IBinder onBind(Intent intent) {
        return null;
    }

    @Override
    public void onDestroy() {
        super.onDestroy();
        Log.i(TAG, "MonitoringService destroyed");
    }
}
"""
    act_src = """package com.spyaware.positive.service;

import android.app.Activity;
import android.content.Intent;
import android.os.Bundle;
import android.util.Log;

public class MainActivity extends Activity {
    private static final String TAG = "SpyAwareSvcTest";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        Log.i(TAG, "Starting MonitoringService from MainActivity");
        Intent svcIntent = new Intent(this, MonitoringService.class);
        startService(svcIntent);
    }
}
"""
    return build_and_sign_apk(
        output_apk_path=output_apk,
        package_name="com.spyaware.positive.service",
        manifest_xml=manifest,
        dex_strings=["MonitoringService", "startService", "ServiceRecord"],
        custom_sources={
            "MainActivity.java": act_src,
            "MonitoringService.java": svc_src,
        },
    )


def build_network_positive_sample(output_apk: Path) -> Path:
    """Builds a positive control APK that performs socket and HTTP network activity."""
    manifest = """<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.spyaware.positive.network"
    android:versionCode="1"
    android:versionName="1.0">
    <uses-sdk android:minSdkVersion="26" android:targetSdkVersion="34" />
    <uses-permission android:name="android.permission.INTERNET" />
    <uses-permission android:name="android.permission.ACCESS_NETWORK_STATE" />
    <application android:label="Network Positive Sample" android:usesCleartextTraffic="true">
        <activity android:name=".MainActivity" android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>
    </application>
</manifest>
"""
    java_src = """package com.spyaware.positive.network;

import android.app.Activity;
import android.os.Bundle;
import android.util.Log;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.URL;

public class MainActivity extends Activity {
    private static final String TAG = "SpyAwareNetTest";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        Log.i(TAG, "Starting positive network control for com.spyaware.positive.network");

        new Thread(new Runnable() {
            @Override
            public void run() {
                for (int i = 0; i < 3; i++) {
                    try {
                        Log.i(TAG, "Attempting HTTP connection to http://10.0.2.2:8765/ping (attempt " + (i + 1) + ")");
                        URL url = new URL("http://10.0.2.2:8765/ping");
                        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
                        conn.setConnectTimeout(2000);
                        conn.setReadTimeout(2000);
                        conn.getInputStream();
                        conn.disconnect();
                    } catch (Exception e) {
                        Log.w(TAG, "HTTP attempt " + (i + 1) + " status: " + e.getMessage());
                    }

                    try {
                        Socket socket = new Socket();
                        socket.connect(new InetSocketAddress("10.0.2.2", 8765), 1500);
                        socket.close();
                    } catch (Exception ignored) {}

                    try {
                        Thread.sleep(800);
                    } catch (InterruptedException ignored) {}
                }
            }
        }).start();
    }
}
"""
    return build_and_sign_apk(
        output_apk_path=output_apk,
        package_name="com.spyaware.positive.network",
        manifest_xml=manifest,
        dex_strings=[
            "http://10.0.2.2:8765/ping",
            "HttpURLConnection",
            "InetSocketAddress",
            "android.permission.INTERNET",
        ],
        custom_sources={"MainActivity.java": java_src},
    )


def generate_all_samples(target_dir: Optional[Path] = None) -> Dict[str, Path]:
    """Generates all synthetic sample APKs with valid signatures and Android manifests."""
    out_dir = target_dir or SAMPLES_DIR
    out_dir.mkdir(parents=True, exist_ok=True)
    results: Dict[str, Path] = {}

    # 1. Benign Sample APK
    benign_manifest = """<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.spyaware.benign"
    android:versionCode="1"
    android:versionName="1.0">
    <uses-sdk android:minSdkVersion="26" android:targetSdkVersion="34" />
    <uses-permission android:name="android.permission.INTERNET" />
    <uses-permission android:name="android.permission.VIBRATE" />
    <uses-permission android:name="android.permission.POST_NOTIFICATIONS" />
    <application android:label="Benign Sample">
        <activity android:name=".MainActivity" android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>
    </application>
</manifest>
"""
    benign_path = out_dir / "benign_sample.apk"
    build_and_sign_apk(
        output_apk_path=benign_path,
        package_name="com.spyaware.benign",
        manifest_xml=benign_manifest,
        dex_strings=[
            "com/spyaware/benign/MainActivity",
            "https://api.weather-service.org/forecast",
            "android/app/Activity",
        ],
        permissions_fallback=[
            "android.permission.INTERNET",
            "android.permission.VIBRATE",
            "android.permission.POST_NOTIFICATIONS",
        ],
    )
    results["benign_sample.apk"] = benign_path

    # 2. Suspicious Surveillance Sample APK
    suspicious_manifest = """<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.spyaware.suspicious"
    android:versionCode="1"
    android:versionName="1.0">
    <uses-sdk android:minSdkVersion="26" android:targetSdkVersion="34" />
    <uses-permission android:name="android.permission.CAMERA" />
    <uses-permission android:name="android.permission.RECORD_AUDIO" />
    <uses-permission android:name="android.permission.ACCESS_FINE_LOCATION" />
    <uses-permission android:name="android.permission.RECEIVE_BOOT_COMPLETED" />
    <uses-permission android:name="android.permission.FOREGROUND_SERVICE" />
    <application android:label="Suspicious Surveillance">
        <activity android:name=".MainActivity" android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>
        <service android:name=".SurveillanceService" android:exported="false" />
        <receiver android:name=".BootReceiver" android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.BOOT_COMPLETED" />
            </intent-filter>
        </receiver>
    </application>
</manifest>
"""
    suspicious_path = out_dir / "suspicious_surveillance_sample.apk"
    build_and_sign_apk(
        output_apk_path=suspicious_path,
        package_name="com.spyaware.suspicious",
        manifest_xml=suspicious_manifest,
        dex_strings=[
            "com/spyaware/suspicious/SurveillanceService",
            "Landroid/hardware/Camera",
            "Landroid/media/AudioRecord",
            "startRecording",
            "Landroid/location/LocationManager",
            "requestLocationUpdates",
        ],
        permissions_fallback=[
            "android.permission.CAMERA",
            "android.permission.RECORD_AUDIO",
            "android.permission.ACCESS_FINE_LOCATION",
            "android.permission.RECEIVE_BOOT_COMPLETED",
            "android.permission.FOREGROUND_SERVICE",
        ],
    )
    results["suspicious_surveillance_sample.apk"] = suspicious_path

    # 3. Critical Stalkerware Sample APK
    critical_manifest = """<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.spyaware.stalkerware"
    android:versionCode="1"
    android:versionName="1.0">
    <uses-sdk android:minSdkVersion="26" android:targetSdkVersion="34" />
    <uses-permission android:name="android.permission.BIND_ACCESSIBILITY_SERVICE" />
    <uses-permission android:name="android.permission.SYSTEM_ALERT_WINDOW" />
    <uses-permission android:name="android.permission.RECEIVE_BOOT_COMPLETED" />
    <uses-permission android:name="android.permission.RECORD_AUDIO" />
    <uses-permission android:name="android.permission.INTERNET" />
    <uses-permission android:name="android.permission.READ_SMS" />
    <application android:label="Stalkerware Service">
        <activity android:name=".MainActivity" android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>
        <service
            android:name=".AccessibilityKeylogger"
            android:permission="android.permission.BIND_ACCESSIBILITY_SERVICE"
            android:exported="true">
            <intent-filter>
                <action android:name="android.accessibilityservice.AccessibilityService" />
            </intent-filter>
        </service>
        <receiver android:name=".BootReceiver" android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.BOOT_COMPLETED" />
            </intent-filter>
        </receiver>
    </application>
</manifest>
"""
    critical_path = out_dir / "critical_stalkerware_sample.apk"
    build_and_sign_apk(
        output_apk_path=critical_path,
        package_name="com.spyaware.stalkerware",
        manifest_xml=critical_manifest,
        dex_strings=[
            "com/spyaware/stalkerware/CovertPayload",
            "Landroid/media/projection/MediaProjection",
            "createVirtualDisplay",
            "/system/bin/sh",
            "su",
            "http://198.51.100.45:8080/c2/exfiltrate",
        ],
        native_libs={
            "lib/arm64-v8a/libstealth_native.so": b"\x7fELF\x02\x01\x01" + b"\x00" * 60
        },
        permissions_fallback=[
            "android.permission.BIND_ACCESSIBILITY_SERVICE",
            "android.permission.SYSTEM_ALERT_WINDOW",
            "android.permission.RECEIVE_BOOT_COMPLETED",
            "android.permission.RECORD_AUDIO",
            "android.permission.INTERNET",
            "android.permission.READ_SMS",
        ],
    )
    results["critical_stalkerware_sample.apk"] = critical_path

    # 4. Positive Control Samples
    results["camera_positive_sample.apk"] = build_camera_positive_sample(out_dir / "camera_positive_sample.apk")
    results["microphone_positive_sample.apk"] = build_microphone_positive_sample(out_dir / "microphone_positive_sample.apk")
    results["location_positive_sample.apk"] = build_location_positive_sample(out_dir / "location_positive_sample.apk")
    results["service_positive_sample.apk"] = build_service_positive_sample(out_dir / "service_positive_sample.apk")
    results["network_positive_sample.apk"] = build_network_positive_sample(out_dir / "network_positive_sample.apk")

    # 5. Malformed Corrupt APK
    corrupt_path = out_dir / "malformed_corrupt.apk"
    with open(corrupt_path, "wb") as f:
        f.write(b"CORRUPTED_RAW_NON_ZIP_BYTES_0123456789")
    results["malformed_corrupt.apk"] = corrupt_path

    # 5. Malformed No Manifest APK
    no_manifest_path = out_dir / "malformed_no_manifest.apk"
    benign_dex = generate_synthetic_dex(["test"])
    with zipfile.ZipFile(no_manifest_path, "w") as zf:
        zf.writestr("assets/dummy.txt", "No AndroidManifest.xml present")
        zf.writestr("classes.dex", benign_dex)
    results["malformed_no_manifest.apk"] = no_manifest_path

    # 6. Malformed Invalid Manifest APK
    invalid_manifest_path = out_dir / "malformed_invalid_manifest.apk"
    with zipfile.ZipFile(invalid_manifest_path, "w") as zf:
        zf.writestr("AndroidManifest.xml", b"TRUNCATED_INVALID_AXML_CONTENT")
    results["malformed_invalid_manifest.apk"] = invalid_manifest_path

    return results


if __name__ == "__main__":
    generated = generate_all_samples()
    print("Sample generation complete. Verifying signatures:")
    for name, path in generated.items():
        if name.endswith("_sample.apk"):
            v = verify_apk_signature(path)
            print(f" -> {name}: Verified={v['verified']}, v1={v['v1']}, v2={v['v2']}, v3={v['v3']}")
            if v["signer_dn"]:
                print(f"    Signer: {v['signer_dn']} (SHA-256: {v['signer_sha256']})")
