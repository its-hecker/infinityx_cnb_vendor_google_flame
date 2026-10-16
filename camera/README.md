# Original stock Google Camera 8.7 for Flame

This directory is selected by the `gcam-experimental-flame` device product.
`GoogleCameraFlame` installs Google's original Camera **8.7.250.494820638.44**
(`65822832`) in /product/app with its base and nine common feature splits.
Six Tensor-specific p21/p22/cheetah modules are excluded.

The payload is copied byte-for-byte from Coral vendor commit
`15499dacfed25dc3ca7d12756e707d3cd7809bb8` in
`its-hecker/infinity_cnb_proprietary_vendor_google_coral`.
Only the outer chunk filenames and build-module names change to Flame.
The reassembled archive SHA-256 remains
`e1ad25c00bc0e712069f69ed3105bc69450e90236424dd45106081054b2086bd`.
The base, feature APKs, native startup library, and Google signatures are untouched.

`source.json` pins the original bundle and every APK. `prebuilt/payload.json`
pins the archive and three sequential 64 MiB-or-smaller Git chunks.
Soong joins `GoogleCameraFlame.apks.*` in filename order; `android_app_set`
installs the original APKs together. Camera requires no build-time download
or Git LFS. Existing radio images keep their original Git LFS requirements.

The tested Flame baseline is vendor commit
`18c5f50f3ac746581f96ce010621abbe0766332b`.
Its camera HAL, firmware, radio, PixelCameraServicesFlame, Face ID and Oslo
payloads are retained. The existing port provenance checks remain enabled.

## Verification

```bash
python3 camera/tools/prepare_camera.py --check-hashes
```

With Android Build Tools 35.0.0 in PATH, verify signatures and manifests too:

```bash
python3 camera/tools/prepare_camera.py --check
```

The read-only Google Camera workflow runs this complete check. It verifies all
ten APKs' hashes, Google signer, package/version/split IDs and startup JNI payload.
The inherited Flame-port workflow checks the original firmware and Face ID/
Motion Sense payloads against their recorded provenance.

A complete Flame Android 17 build and on-device GCam testing are still required.
Follow the matching local-manifest branch's `docs/GCAM_EXPERIMENTAL.md`.
