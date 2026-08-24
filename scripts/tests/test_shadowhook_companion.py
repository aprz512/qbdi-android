import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
HELPER = "libshadowhook_nothing.so"
TRACER = "libqbdi_tracer.so"


class ShadowHookCompanionContractTests(unittest.TestCase):
    def test_android_targets_build_companion_for_apk_and_tracer_aar(self):
        tracer_cmake = (ROOT / "tracer/src/main/cpp/CMakeLists.txt").read_text()
        app_cmake = (ROOT / "app/src/main/cpp/CMakeLists.txt").read_text()

        for source in (tracer_cmake, app_cmake):
            with self.subTest(cmake=source[:40]):
                self.assertIn("add_library(shadowhook_nothing SHARED", source)
                self.assertIn("nothing/sh_nothing.c", source)

    def test_standalone_copy_publishes_tracer_and_companion_together(self):
        gradle = (ROOT / "tracer/build.gradle").read_text()

        self.assertIn('include("libqbdi_tracer.so", "libshadowhook_nothing.so")', gradle)

    def test_standalone_spawn_loads_only_tracer_then_sets_helper_before_configure(self):
        source = (ROOT / "scripts/spawn_trace.js").read_text()

        self.assertIn("shadowhookCompanion: 'libshadowhook_nothing.so'", source)
        self.assertNotIn("loadLibrary(dir + '/' + config.shadowhookCompanion)", source)
        self.assertNotIn("loadLibrary(dir + '/' + config.targetSo)", source)
        self.assertIn("qbdi_tracer_set_shadowhook_helper_path", source)
        self.assertLess(
            source.index("const tracerModule = loadLibrary(dir + '/' + config.tracer)"),
            source.rindex("configureShadowHookHelper"),
        )
        self.assertLess(source.rindex("configureShadowHookHelper"),
                        source.index("configureTracer(encodeConfig"))
        self.assertIn("if (!config.flight.enabled) installModuleObserver", source)
        self.assertIn("failed to configure ShadowHook companion path", source)

        tracer = (ROOT / "tracer/src/main/cpp/tracer_entry.cpp").read_text()
        self.assertIn("static void module_constructor_pre(", tracer)
        self.assertIn("install_hooks_for_module(module, 0, true)", tracer)

    def test_application_injectors_configure_but_never_preload_apk_companion(self):
        for name in ("benchmark_trace.js", "signal_probe.js"):
            source = (ROOT / "scripts" / name).read_text()
            with self.subTest(injector=name):
                self.assertIn("applicationInfo.nativeLibraryDir", source)
                self.assertIn(HELPER, source)
                self.assertNotIn("application.getClass(), companionPath)", source)
                self.assertNotIn("Module.load(companionPath)", source)
                self.assertNotIn("Module.load(config.targetSo)", source)
                self.assertIn("qbdi_tracer_set_shadowhook_helper_path", source)
                self.assertIn("failed to configure ShadowHook companion path", source)

    def test_bundled_shadowhook_rejects_invalid_late_or_preloaded_helper(self):
        api = (ROOT / "tracer/src/main/cpp/third_party/android-inline-hook/shadowhook/"
               "src/main/cpp/shadowhook.c").read_text()
        linker = (ROOT / "tracer/src/main/cpp/third_party/android-inline-hook/shadowhook/"
                  "src/main/cpp/sh_linker.c").read_text()

        self.assertIn("shadowhook_set_dl_init_helper_path", api)
        self.assertIn("SHADOWHOOK_ERRNO_UNINIT", api)
        self.assertIn("sh_linker_set_init_helper_path", linker)
        self.assertIn("helper_path[0] != '/'", linker)
        self.assertIn("RTLD_NOLOAD", linker)
        self.assertIn("access(helper_path, R_OK)", linker)
        self.assertIn("dlopen(sh_linker_init_helper_path, RTLD_NOW)", linker)
        self.assertNotIn(
            'SH_LINKER_SHADOWHOOK_NOTHING_BASE_NAME \\\n+  "/data/data/', linker
        )

    def test_deployment_docs_stage_companion_with_standalone_tracer(self):
        readme = (ROOT / "README.md").read_text()

        self.assertIn("out/arm64-v8a/libshadowhook_nothing.so", readme)


if __name__ == "__main__":
    unittest.main()
