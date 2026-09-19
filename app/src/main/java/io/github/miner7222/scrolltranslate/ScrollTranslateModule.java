package io.github.miner7222.scrolltranslate;

import android.annotation.SuppressLint;
import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.util.Log;
import android.view.SurfaceControl;
import android.view.ViewGroup;
import android.view.WindowManager;

import androidx.annotation.NonNull;

import java.io.File;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;

import io.github.libxposed.api.XposedInterface;
import io.github.libxposed.api.XposedModule;
import io.github.libxposed.api.XposedModuleInterface;

/**
 * Forces the Google app's Lens "live translate" entry point -- shown as
 * "Scroll and translate" in Circle to Search / Lens -- to be available.
 *
 * <p>Gate analysis (Google app 17.3 / 17.27 / 17.59):</p>
 * <pre>
 * chip visible = surfaceIsLensOmni
 *             &amp;&amp; flag(com.google.android.apps.search.lens.device / 45716363)
 *             &amp;&amp; ( flag(com.google.android.apps.search.lens.device / 45724135)
 *                  || pm.hasSystemFeature("com.google.android.feature.CONTEXTUAL_SEARCH_LIVE_TRANSLATE") )
 *             [17.59 only] &amp;&amp; flag(com.google.android.apps.search.lens.user / 45785436)
 *             [17.59 only] &amp;&amp; mediaProjectionSession &amp;&amp; !cameraCaller &amp;&amp; !filterLocked
 * </pre>
 *
 * <p>The module removes the Phenotype/GServices flag and system-feature parts of
 * that conjunction. The method that computes the gate is obfuscated and renamed
 * on every release, so the flag getters are located at runtime by scanning the
 * app's DEX files for the flag id strings.</p>
 *
 * <p>Beyond the entry point, three runtime fixes make the session usable:</p>
 * <ul>
 *   <li>SystemUI: silently grant MediaProjection permission for the Google
 *       app, so no consent dialog fires per session.</li>
 *   <li>system_server: mark the overlay surfaces SKIP_SCREENSHOT (keeps the
 *       overlay out of the secure virtual-display mirror that would feed the
 *       translation back into OCR and flicker) and trusted (so touches to
 *       apps underneath are not dropped as untrusted obscured touches).</li>
 *   <li>system_server: undo the tapjacking alpha clamp (0.8) that
 *       DisplayPolicy applies to the NOT_TOUCHABLE overlay, so the
 *       inpainting boxes fully hide the original text.</li>
 * </ul>
 */
public final class ScrollTranslateModule extends XposedModule {

    private static final String TAG = "ScrollTranslate";

    private static final String TARGET_PACKAGE = "com.google.android.googlequicksearchbox";
    private static final String LENS_PROCESS = TARGET_PACKAGE + ":googleapp";
    private static final String SYSTEMUI_PACKAGE = "com.android.systemui";

    /** WindowManager.LayoutParams constants (kept as ints: WindowManagerGlobal is @hide). */
    private static final int TYPE_APPLICATION_OVERLAY = 2038;
    private static final int FLAG_SECURE_VALUE = 0x00002000;


    private static final String LIVE_TRANSLATE_SYSTEM_FEATURE =
            "com.google.android.feature.CONTEXTUAL_SEARCH_LIVE_TRANSLATE";

    /**
     * Phenotype/GServices flag ids that gate Lens live translate.
     * 45716363 / 45724135 = com.google.android.apps.search.lens.device
     * 45785436            = com.google.android.apps.search.lens.user
     */
    private static final String[] LIVE_TRANSLATE_FLAG_IDS = {
            "45716363",
            "45724135",
            "45785436",
    };

    /**
     * Visibility getter of the Lens contextual action interface
     * (donq / doly / cykb / ... obfuscated per version, the method name is stable).
     */
    private static final String VISIBILITY_METHOD = "i";

    private static final AtomicBoolean FEATURE_HOOKS_DONE = new AtomicBoolean(false);
    private static final AtomicBoolean FLAG_HOOKS_DONE = new AtomicBoolean(false);
    private static final AtomicBoolean APP_CONTEXT_HOOK_DONE = new AtomicBoolean(false);
    private static final AtomicBoolean ACTION_HOOKS_DONE = new AtomicBoolean(false);
    private static final AtomicBoolean OVERLAY_HOOKS_DONE = new AtomicBoolean(false);
    private static final AtomicBoolean CONSENT_HOOKS_DONE = new AtomicBoolean(false);
    private static final AtomicBoolean SYS_HOOKS_DONE = new AtomicBoolean(false);
    private static final AtomicBoolean FEATURE_HIT_LOGGED = new AtomicBoolean(false);

    private volatile String processName = "";
    private volatile ClassLoader appClassLoader;
    private volatile int gsaUid = -1;

    @Override
    public void onModuleLoaded(@NonNull XposedModuleInterface.ModuleLoadedParam param) {
        processName = param.getProcessName();
        log(Log.INFO, TAG, "event=module_loaded process=" + processName
                + " api=" + getApiVersion()
                + " framework=" + getFrameworkName() + " " + getFrameworkVersion());
    }

    @Override
    public void onSystemServerStarting(
            @NonNull XposedModuleInterface.SystemServerStartingParam param) {
        installSystemServerHooks(param.getClassLoader());
    }



    @Override
    public void onPackageReady(@NonNull XposedModuleInterface.PackageReadyParam param) {
        if (SYSTEMUI_PACKAGE.equals(param.getPackageName())) {
            installProjectionConsentHook(param.getClassLoader());
            return;
        }
        if (!TARGET_PACKAGE.equals(param.getPackageName())) {
            return;
        }
        ClassLoader classLoader = param.getClassLoader();
        appClassLoader = classLoader;
        log(Log.INFO, TAG, "event=package_ready package=" + param.getPackageName()
                + " process=" + processName);

        installSystemFeatureHooks(classLoader);
        installOverlaySecureHooks(classLoader);

        if (isLensCapableProcess()) {
            installFlagHooks(param);
            installAppContextHook(classLoader);
        } else {
            log(Log.INFO, TAG, "event=flag_scan_skipped reason=process_out_of_scope process=" + processName);
        }
    }

    /** The Google app hosts the Lens / Circle-to-Search UI in its main and ":googleapp" processes. */
    private boolean isLensCapableProcess() {
        String name = processName;
        return TARGET_PACKAGE.equals(name) || LENS_PROCESS.equals(name);
    }

    // ---------------------------------------------------------------------
    // Gate 1: PackageManager.hasSystemFeature("...CONTEXTUAL_SEARCH_LIVE_TRANSLATE")
    // ---------------------------------------------------------------------

    private void installSystemFeatureHooks(ClassLoader classLoader) {
        if (!FEATURE_HOOKS_DONE.compareAndSet(false, true)) {
            return;
        }
        try {
            Class<?> impl = Class.forName("android.app.ApplicationPackageManager", false, classLoader);
            hookFeatureMethod(impl, "hasSystemFeature", String.class);
            hookFeatureMethod(impl, "hasSystemFeature", String.class, int.class);
            log(Log.INFO, TAG, "event=hook_installed target=" + impl.getName() + ".hasSystemFeature");
        } catch (Throwable t) {
            log(Log.WARN, TAG, "event=feature_hook_failed target=ApplicationPackageManager", t);
        }
        try {
            Class<?> base = Class.forName("android.content.pm.PackageManager", false, classLoader);
            hookFeatureMethod(base, "hasSystemFeature", String.class);
            log(Log.INFO, TAG, "event=hook_installed target=" + base.getName() + ".hasSystemFeature");
        } catch (Throwable t) {
            log(Log.WARN, TAG, "event=feature_hook_failed target=PackageManager", t);
        }
    }

    private void hookFeatureMethod(Class<?> owner, String name, Class<?>... parameterTypes) {
        try {
            Method method = owner.getDeclaredMethod(name, parameterTypes);
            if (Modifier.isAbstract(method.getModifiers())) {
                log(Log.INFO, TAG, "event=feature_method_skipped reason=abstract method="
                        + owner.getName() + "." + name);
                return;
            }
            method.setAccessible(true);
            hook(method)
                    .setId("scrolltranslate_feature_" + owner.getSimpleName() + "_" + parameterTypes.length)
                    .setExceptionMode(XposedInterface.ExceptionMode.DEFAULT)
                    .intercept(chain -> {
                        Object feature = chain.getArg(0);
                        if (LIVE_TRANSLATE_SYSTEM_FEATURE.equals(feature)) {
                            if (FEATURE_HIT_LOGGED.compareAndSet(false, true)) {
                                log(Log.INFO, TAG, "event=feature_hit feature=" + feature
                                        + " forced=true");
                            }
                            return Boolean.TRUE;
                        }
                        return chain.proceed();
                    });
        } catch (Throwable t) {
            log(Log.WARN, TAG, "event=feature_method_hook_failed method=" + name, t);
        }
    }

    // ---------------------------------------------------------------------
    // Gate 2: Phenotype/GServices flag getters (obfuscated, located via DEX scan)
    // ---------------------------------------------------------------------

    private void installFlagHooks(XposedModuleInterface.PackageReadyParam param) {
        if (!FLAG_HOOKS_DONE.compareAndSet(false, true)) {
            return;
        }
        try {
            List<File> apks = listApks(param.getApplicationInfo());
            long startedAt = System.currentTimeMillis();
            DexFlagScanner.ScanReport report = DexFlagScanner.scan(apks, LIVE_TRANSLATE_FLAG_IDS);
            long elapsed = System.currentTimeMillis() - startedAt;
            log(Log.INFO, TAG, "event=flag_scan_done apks=" + apks.size()
                    + " hits=" + report.hits.size() + " ms=" + elapsed);
            for (String note : report.notes) {
                log(Log.WARN, TAG, "event=flag_scan_note " + note);
            }
            for (DexFlagScanner.FlagMethod hit : report.hits) {
                hookFlagAccessor(param.getClassLoader(), hit);
            }
        } catch (Throwable t) {
            log(Log.ERROR, TAG, "event=flag_hook_install_failed", t);
        }
    }

    // ---------------------------------------------------------------------
    // Gate 3: the "Scroll and translate" action must report itself visible.
    //
    // The omnibox controller inflates the live translate button (a ViewStub)
    // only when the action's i() returns true, and the action caches
    // "surfaceIsOmni && liveTranslateAvailable" at construction time. CTS
    // sessions on non-Pixel devices do not satisfy that availability check, so
    // the button is never inflated even with the flags forced. Locate the
    // action class through its label resource id and force i() to true.
    // ---------------------------------------------------------------------

    private void installAppContextHook(ClassLoader classLoader) {
        if (!APP_CONTEXT_HOOK_DONE.compareAndSet(false, true)) {
            return;
        }
        try {
            Class<?> application = Class.forName("android.app.Application", false, classLoader);
            Method onCreate = application.getDeclaredMethod("onCreate");
            onCreate.setAccessible(true);
            hook(onCreate)
                    .setId("scrolltranslate_app_oncreate")
                    .setExceptionMode(XposedInterface.ExceptionMode.DEFAULT)
                    .intercept(chain -> {
                        Object result = chain.proceed();
                        try {
                            Context context = (Context) chain.getThisObject();
                            installLiveTranslateActionHook(context);
                        } catch (Throwable t) {
                            log(Log.WARN, TAG, "event=action_hook_failed", t);
                        }
                        return result;
                    });
            log(Log.INFO, TAG, "event=hook_installed target=android.app.Application.onCreate");
        } catch (Throwable t) {
            log(Log.WARN, TAG, "event=app_context_hook_failed", t);
        }
    }

    private void installLiveTranslateActionHook(Context context) {
        if (!ACTION_HOOKS_DONE.compareAndSet(false, true)) {
            return;
        }
        try {
            int labelId = context.getResources()
                    .getIdentifier("lens_live_translate_action_text", "string", TARGET_PACKAGE);
            log(Log.INFO, TAG, "event=action_label_id id=0x" + Integer.toHexString(labelId));
            if (labelId == 0) {
                return;
            }
            List<File> apks = listApks(context.getApplicationInfo());
            long startedAt = System.currentTimeMillis();
            DexFlagScanner.ScanReport report = DexFlagScanner.findZeroArgIntMethods(apks, labelId);
            long elapsed = System.currentTimeMillis() - startedAt;
            log(Log.INFO, TAG, "event=action_scan_done candidates=" + report.hits.size()
                    + " ms=" + elapsed);
            for (String note : report.notes) {
                log(Log.WARN, TAG, "event=action_scan_note " + note);
            }
            for (DexFlagScanner.FlagMethod hit : report.hits) {
                hookActionVisibility(hit);
            }
        } catch (Throwable t) {
            log(Log.ERROR, TAG, "event=action_hook_install_failed", t);
        }
    }

    private void hookActionVisibility(DexFlagScanner.FlagMethod hit) {
        Class<?> owner;
        try {
            owner = Class.forName(hit.className, false, appClassLoader);
        } catch (Throwable t) {
            log(Log.WARN, TAG, "event=action_class_load_failed target=" + hit.className, t);
            return;
        }

        // 1) Visibility getter: drives ViewStub inflation and view visibility.
        try {
            Method method = owner.getDeclaredMethod(VISIBILITY_METHOD);
            if (method.getReturnType() != boolean.class || method.getParameterCount() != 0
                    || Modifier.isAbstract(method.getModifiers())) {
                log(Log.WARN, TAG, "event=action_visibility_signature_mismatch target="
                        + hit.className + "." + VISIBILITY_METHOD);
            } else {
                method.setAccessible(true);
                hook(method)
                        .setId("scrolltranslate_action_visible_" + hit.className)
                        .setExceptionMode(XposedInterface.ExceptionMode.DEFAULT)
                        .intercept(chain -> {
                            Object original = chain.proceed();
                            log(Log.INFO, TAG, "event=action_visibility class=" + hit.className
                                    + "." + VISIBILITY_METHOD + " original=" + original + " forced=true");
                            return Boolean.TRUE;
                        });
                log(Log.INFO, TAG, "event=hook_installed target=" + hit.className + "."
                        + VISIBILITY_METHOD + "() action=live_translate");
            }
        } catch (Throwable t) {
            log(Log.WARN, TAG, "event=action_visibility_hook_failed target=" + hit.className, t);
        }

        // 2) The click handler is only attached when the action's cached boolean
        //    (surface && availability) is true, and that value is frozen in the
        //    constructor. Force it after construction too.
        try {
            for (Constructor<?> constructor : owner.getDeclaredConstructors()) {
                constructor.setAccessible(true);
                hook(constructor)
                        .setId("scrolltranslate_action_ctor_" + hit.className + "_"
                                + constructor.getParameterCount())
                        .setExceptionMode(XposedInterface.ExceptionMode.DEFAULT)
                        .intercept(chain -> {
                            Object self = chain.getThisObject();
                            Object result = chain.proceed();
                            Object instance = self != null ? self : result;
                            if (instance != null) {
                                forceBooleanFields(instance, hit.className);
                            }
                            return result;
                        });
            }
            log(Log.INFO, TAG, "event=hook_installed target=" + hit.className
                    + ".<init> action=live_translate cache_forced=true");
        } catch (Throwable t) {
            log(Log.WARN, TAG, "event=action_ctor_hook_failed target=" + hit.className, t);
        }

        // 3) Availability object (field whose type exposes a()Z): the action
        //    constructor combines the surface check with it, and the live
        //    translate session start path reads the same gate.
        for (Field field : owner.getDeclaredFields()) {
            Class<?> type = field.getType();
            if (type.isPrimitive()) {
                continue;
            }
            try {
                Method method = type.getDeclaredMethod("a");
                if (method.getReturnType() != boolean.class || method.getParameterCount() != 0
                        || Modifier.isAbstract(method.getModifiers())) {
                    continue;
                }
                method.setAccessible(true);
                hook(method)
                        .setId("scrolltranslate_availability_" + type.getName())
                        .setExceptionMode(XposedInterface.ExceptionMode.DEFAULT)
                        .intercept(chain -> {
                            Object original = chain.proceed();
                            log(Log.INFO, TAG, "event=availability class=" + type.getName()
                                    + ".a original=" + original + " forced=true");
                            return Boolean.TRUE;
                        });
                log(Log.INFO, TAG, "event=hook_installed target=" + type.getName()
                        + ".a() action=availability");
            } catch (NoSuchMethodException ignored) {
                // not the availability type
            } catch (Throwable t) {
                log(Log.WARN, TAG, "event=availability_hook_failed type=" + type.getName(), t);
            }
        }
    }

    private void forceBooleanFields(Object instance, String ownerName) {
        for (Field field : instance.getClass().getDeclaredFields()) {
            if (field.getType() != boolean.class || Modifier.isStatic(field.getModifiers())) {
                continue;
            }
            try {
                field.setAccessible(true);
                boolean before = field.getBoolean(instance);
                if (!before) {
                    field.setBoolean(instance, true);
                    log(Log.INFO, TAG, "event=action_cache_forced target=" + ownerName
                            + "." + field.getName() + " " + before + "->true");
                }
            } catch (Throwable t) {
                log(Log.WARN, TAG, "event=action_cache_force_failed target=" + ownerName
                        + "." + field.getName(), t);
            }
        }
    }


    // ---------------------------------------------------------------------
    // System side: silent MediaProjection consent for the Google app.
    //
    // The live translate trampoline fragment calls
    // MediaProjectionManager.createScreenCaptureIntent(), which SystemUI
    // resolves to MediaProjectionPermissionActivity. That activity skips its
    // dialog entirely when IMediaProjectionManager.hasProjectionPermission()
    // returns true -- it then calls createProjection()/getProjection() itself
    // and hands a valid IMediaProjection binder back to the app. The server
    // side check is:
    //     checkPermission(CAPTURE_VIDEO_OUTPUT) || noteOpNoThrow(PROJECT_MEDIA)
    // and the Google app holds neither on this device, so the dialog fires on
    // every new session (the consent it grants is never persisted).
    //
    // Hooking the binder Proxy method inside SystemUI makes the consent path
    // silent for the Google app only; the projection token is still created
    // and returned by the real service, including the
    // requestConsentForInvalidProjection() re-review flow.
    // ---------------------------------------------------------------------

    private void installProjectionConsentHook(ClassLoader classLoader) {
        if (!CONSENT_HOOKS_DONE.compareAndSet(false, true)) {
            return;
        }
        try {
            Class<?> proxy = Class.forName(
                    "android.media.projection.IMediaProjectionManager$Stub$Proxy",
                    false, classLoader);
            Method method = proxy.getDeclaredMethod(
                    "hasProjectionPermission", int.class, String.class);
            method.setAccessible(true);
            hook(method)
                    .setId("scrolltranslate_projection_consent")
                    .setExceptionMode(XposedInterface.ExceptionMode.DEFAULT)
                    .intercept(chain -> {
                        if (TARGET_PACKAGE.equals(chain.getArg(1))) {
                            log(Log.INFO, TAG, "event=consent_silent_grant pkg="
                                    + chain.getArg(1));
                            return Boolean.TRUE;
                        }
                        return chain.proceed();
                    });
            log(Log.INFO, TAG, "event=hook_installed"
                    + " target=IMediaProjectionManager.Stub.Proxy.hasProjectionPermission"
                    + " process=" + processName);
        } catch (Throwable t) {
            log(Log.WARN, TAG, "event=consent_hook_failed", t);
        }
    }

    // ---------------------------------------------------------------------
    // Overlay windows get FLAG_SECURE: the actual capture exclusion is done
    // by SKIP_SCREENSHOT in system_server (see below), but securing the
    // translation overlay additionally keeps it out of ordinary screenshots
    // and marks the input handle SENSITIVE_FOR_PRIVACY. The flag survives
    // esfc.e()/h() because those paths only touch FLAG_NOT_TOUCHABLE on the
    // same LayoutParams object; updateViewLayout is hooked anyway as a
    // safety net.
    // ---------------------------------------------------------------------

    private void installOverlaySecureHooks(ClassLoader classLoader) {
        if (!OVERLAY_HOOKS_DONE.compareAndSet(false, true)) {
            return;
        }
        try {
            Class<?> global = Class.forName("android.view.WindowManagerGlobal",
                    false, classLoader);
            int hooked = 0;
            for (Method method : global.getDeclaredMethods()) {
                String name = method.getName();
                if (!"addView".equals(name) && !"updateViewLayout".equals(name)) {
                    continue;
                }
                Class<?>[] types = method.getParameterTypes();
                if (types.length < 2 || types[1] != ViewGroup.LayoutParams.class) {
                    continue;
                }
                method.setAccessible(true);
                hook(method)
                        .setId("scrolltranslate_overlay_secure_" + name + "_" + types.length)
                        .setExceptionMode(XposedInterface.ExceptionMode.DEFAULT)
                        .intercept(chain -> {
                            Object params = chain.getArg(1);
                            if (params instanceof WindowManager.LayoutParams) {
                                WindowManager.LayoutParams lp =
                                        (WindowManager.LayoutParams) params;
                                if (lp.type == TYPE_APPLICATION_OVERLAY
                                        && (lp.flags & FLAG_SECURE_VALUE) == 0) {
                                    lp.flags |= FLAG_SECURE_VALUE;
                                    log(Log.INFO, TAG, "event=overlay_secured flags=0x"
                                            + Integer.toHexString(lp.flags)
                                            + " process=" + processName);
                                }
                            }
                            return chain.proceed();
                        });
                hooked++;
            }
            log(Log.INFO, TAG, "event=overlay_secure_hooks_installed count=" + hooked
                    + " process=" + processName);
        } catch (Throwable t) {
            log(Log.WARN, TAG, "event=overlay_secure_hook_failed", t);
        }
    }

    // ---------------------------------------------------------------------
    // system_server side. Measured facts on this device:
    //  - The live translate VD ends up FLAG_SECURE (mFlags=0x16): the
    //    DisableFlagSecure module ORs 0x4 onto the adapter arg.
    //  - A *non-secure* VD receives all-black frames (display 0 is a secure
    //    display, so its mirror content is dropped on a non-secure output),
    //    which starves OCR -- the VD must stay secure for translation to work.
    //  - A secure mirror records FLAG_SECURE layers, so securing the overlay
    //    windows cannot break the feedback loop on its own.
    // Instead we mark the overlay *surface* SKIP_SCREENSHOT via a
    // SurfaceControl.Transaction: skip-screenshot layers and their children
    // are excluded from mirroring/screen recording (non-primary displays)
    // but still composite on the physical display. Hook
    // WindowStateAnimator.createSurfaceLocked, identify the Google app's
    // TYPE_APPLICATION_OVERLAY windows, and set the flag once the surface
    // exists.
    // ---------------------------------------------------------------------

    private void installSystemServerHooks(ClassLoader classLoader) {
        if (!SYS_HOOKS_DONE.compareAndSet(false, true)) {
            return;
        }
        int installed = installSkipScreenshotHooks(classLoader);
        installed += installOverlayAlphaHooks(classLoader);
        log(Log.INFO, TAG, "event=ss_hooks_installed count=" + installed);
    }

    /**
     * The live translate fullscreen overlay is FLAG_NOT_TOUCHABLE, so
     * DisplayPolicy.adjustWindowParamsLw clamps its alpha to
     * mMaximumObscuringOpacityForTouch (0.8) as tapjacking protection --
     * which makes the inpainting boxes translucent and lets the original
     * text bleed through. Official devices treat this overlay as trusted
     * so the guard never applies. Undo the clamp for the Google app's
     * overlay windows after each call. The companion touch guard (opaque
     * untrusted overlay drops touches below) is handled separately by
     * marking the overlay surface trusted in skipScreenshotForOverlay.
     */
    private int installOverlayAlphaHooks(ClassLoader classLoader) {
        int installed = 0;
        try {
            Class<?> dp = Class.forName(
                    "com.android.server.wm.DisplayPolicy", false, classLoader);
            for (Method m : dp.getDeclaredMethods()) {
                if (!"adjustWindowParamsLw".equals(m.getName())
                        || m.getParameterCount() != 2) {
                    continue;
                }
                m.setAccessible(true);
                hook(m).intercept(chain -> {
                    Object res = chain.proceed();
                    try {
                        unclampOverlayAlpha(chain.getArg(0), chain.getArg(1));
                    } catch (Throwable t) {
                        log(Log.WARN, TAG, "event=ss_alpha_fix_failed", t);
                    }
                    return res;
                });
                installed++;
            }
            log(Log.INFO, TAG, "event=ss_alpha_hooks_installed count=" + installed);
        } catch (Throwable t) {
            log(Log.WARN, TAG, "event=ss_alpha_hook_failed", t);
        }
        return installed;
    }

    private void unclampOverlayAlpha(Object winState, Object attrs) {
        if (!(attrs instanceof WindowManager.LayoutParams)) {
            return;
        }
        WindowManager.LayoutParams lp = (WindowManager.LayoutParams) attrs;
        if (lp.type != TYPE_APPLICATION_OVERLAY
                || !TARGET_PACKAGE.equals(lp.packageName)
                || lp.alpha >= 1.0f) {
            return;
        }
        log(Log.INFO, TAG, "event=ss_overlay_alpha_fix alpha="
                + lp.alpha + " ->1.0");
        lp.alpha = 1.0f;
        Object animator = getField(winState, "mWinAnimator");
        if (animator != null) {
            setField(animator, "mAlpha", 1.0f);
        }
    }

    private void setField(Object target, String name, float value) {
        for (Class<?> c = target.getClass(); c != null; c = c.getSuperclass()) {
            try {
                Field f = c.getDeclaredField(name);
                f.setAccessible(true);
                f.setFloat(target, value);
                return;
            } catch (NoSuchFieldException ignored) {
            } catch (Throwable t) {
                log(Log.WARN, TAG, "event=set_field_failed " + name, t);
                return;
            }
        }
    }

    /**
     * Marks the Google app's TYPE_APPLICATION_OVERLAY window surfaces
     * SKIP_SCREENSHOT right after WindowStateAnimator creates them, so the
     * overlay subtree is excluded from the virtual-display mirror while
     * remaining visible on the physical display.
     */
    private int installSkipScreenshotHooks(ClassLoader classLoader) {
        int installed = 0;
        try {
            Class<?> wsa = Class.forName(
                    "com.android.server.wm.WindowStateAnimator", false, classLoader);
            for (Method m : wsa.getDeclaredMethods()) {
                if (!"createSurfaceLocked".equals(m.getName())
                        || m.getParameterCount() != 0) {
                    continue;
                }
                m.setAccessible(true);
                hook(m).intercept(chain -> {
                    Object result = chain.proceed();
                    try {
                        skipScreenshotForOverlay(chain.getThisObject());
                    } catch (Throwable t) {
                        log(Log.WARN, TAG, "event=ss_skip_screenshot_failed", t);
                    }
                    return result;
                });
                installed++;
            }
            log(Log.INFO, TAG, "event=ss_skip_screenshot_installed count=" + installed);
        } catch (Throwable t) {
            log(Log.WARN, TAG, "event=ss_skip_screenshot_hook_failed", t);
        }
        return installed;
    }

    @SuppressLint("BlockedPrivateApi") // runs inside system_server, not the app
    private void skipScreenshotForOverlay(Object animator) throws Throwable {
        Object win = getField(animator, "mWin");
        Object attrs = win != null ? getField(win, "mAttrs") : null;
        if (attrs == null) {
            return;
        }
        Object typeObj = getField(attrs, "type");
        if (!(typeObj instanceof Integer)
                || (Integer) typeObj != TYPE_APPLICATION_OVERLAY) {
            return;
        }
        Object pkgObj = getField(attrs, "packageName");
        Object session = getField(animator, "mSession");
        Object uidObj = session != null ? getField(session, "mUid") : null;
        int uid = uidObj instanceof Number ? ((Number) uidObj).intValue() : -1;
        boolean isGsa = TARGET_PACKAGE.equals(pkgObj) || uid == gsaUid(animator);
        if (!isGsa) {
            return;
        }
        Object sc = getField(animator, "mSurfaceControl");
        if (!(sc instanceof SurfaceControl)) {
            return;
        }
        Object title = getField(attrs, "mTitle");
        SurfaceControl.Transaction tx = new SurfaceControl.Transaction();
        Method setSkip = SurfaceControl.Transaction.class.getDeclaredMethod(
                "setSkipScreenshot", SurfaceControl.class, boolean.class);
        setSkip.setAccessible(true);
        setSkip.invoke(tx, sc, true);
        // Mark the surface trusted on the input side. The privateFlags
        // route is gated behind mCanAddInternalSystemWindow, which GSA
        // lacks, so apply the SurfaceControl flag directly. Without it,
        // an opaque fullscreen overlay occludes every touch below and
        // InputDispatcher drops them (BLOCK_UNTRUSTED).
        Method setTrusted = SurfaceControl.Transaction.class.getDeclaredMethod(
                "setTrustedOverlay", SurfaceControl.class, boolean.class);
        setTrusted.setAccessible(true);
        setTrusted.invoke(tx, sc, true);
        tx.apply();
        tx.close();
        log(Log.INFO, TAG, "event=ss_overlay_skip_screenshot title=" + title
                + " uid=" + uid + " pkg=" + pkgObj + " trusted");
    }

    private int gsaUid(Object animator) {
        int cached = gsaUid;
        if (cached >= 0) {
            return cached;
        }
        try {
            Object service = getField(animator, "mService");
            Object ctx = service != null ? getField(service, "mContext") : null;
            if (ctx instanceof Context) {
                ApplicationInfo info = ((Context) ctx).getPackageManager()
                        .getApplicationInfo(TARGET_PACKAGE, 0);
                gsaUid = info.uid;
            }
        } catch (Throwable t) {
            log(Log.WARN, TAG, "event=gsa_uid_resolve_failed", t);
        }
        return gsaUid;
    }

    private static Object getField(Object target, String name) {
        if (target == null) {
            return null;
        }
        for (Class<?> c = target.getClass(); c != null; c = c.getSuperclass()) {
            try {
                Field f = c.getDeclaredField(name);
                f.setAccessible(true);
                return f.get(target);
            } catch (NoSuchFieldException ignored) {
            } catch (Throwable t) {
                return null;
            }
        }
        return null;
    }


    private static List<File> listApks(ApplicationInfo info) {
        List<File> apks = new ArrayList<>();
        if (info.sourceDir != null) {
            apks.add(new File(info.sourceDir));
        }
        if (info.splitSourceDirs != null) {
            for (String split : info.splitSourceDirs) {
                if (split != null) {
                    apks.add(new File(split));
                }
            }
        }
        return apks;
    }

    private void hookFlagAccessor(ClassLoader classLoader, DexFlagScanner.FlagMethod hit) {
        try {
            Class<?> owner = Class.forName(hit.className, false, classLoader);
            Method method = owner.getDeclaredMethod(hit.methodName);
            method.setAccessible(true);
            hook(method)
                    .setId("scrolltranslate_flag_" + hit.flagId)
                    .setExceptionMode(XposedInterface.ExceptionMode.DEFAULT)
                    .intercept(chain -> {
                        log(Log.DEBUG, TAG, "event=flag_hit flag=" + hit.flagId
                                + " method=" + hit.className + "." + hit.methodName + " forced=true");
                        return Boolean.TRUE;
                    });
            log(Log.INFO, TAG, "event=hook_installed target=" + hit.className + "."
                    + hit.methodName + "() flag=" + hit.flagId + " dex=" + hit.dexName);
        } catch (Throwable t) {
            log(Log.WARN, TAG, "event=flag_hook_failed target=" + hit.className + "."
                    + hit.methodName, t);
        }
    }
}
