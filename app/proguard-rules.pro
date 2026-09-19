-dontwarn io.github.libxposed.annotation.**
-adaptresourcefilecontents META-INF/xposed/java_init.list

# Keep the module's own classes readable: stable class names make log-based
# diagnosis (and java_init.list) unambiguous across builds.
-keep class io.github.miner7222.scrolltranslate.** { *; }