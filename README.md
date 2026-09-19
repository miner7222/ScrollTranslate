# ScrollTranslate

Enable Google Lens "Scroll and translate" (Live Translate) on unsupported devices via LSPosed.

## Requirements

- A rooted device with LSPosed
- [Google](https://play.google.com/store/apps/details?id=com.google.android.googlequicksearchbox) app
- Android 10 or later (minSdk 29)

Tested on:

| Model | ROM |
|---|---|
| TB324ZC | ZUXOS 2.0 |

## Install

1. Install the APK.
2. In LSPosed, enable the module and select the scopes: **Google app**, **System UI**, and **System framework**.
3. Reboot.

## Build

```bash
./gradlew assembleRelease
```

The APK is written to `app/build/outputs/apk/release/app-release.apk`.

## License

Licensed under the [Apache License 2.0](LICENSE).
