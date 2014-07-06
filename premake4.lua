--
-- Premake 4.x build configuration script
--

--
-- Define the project. Put the release configuration first so it will be the
-- default when folks build using the makefile. That way they don't have to
-- worry about the /scripts argument and all that.
--
	solution "utf8"
		configurations { "Release", "Debug" }
		--location ( _OPTIONS["to"] )
		local build_location = "./build"
		location (build_location)
		configuration "Debug"
			targetdir  (build_location .. "/bin/debug")
			implibdir  (build_location .. "/bin/debug")
			defines     "_DEBUG"
			flags       { "Symbols" }

		configuration "Release"
			targetdir (build_location .. "/bin/release")
			implibdir (build_location .. "/bin/release")
			defines     "NDEBUG"
			flags       { "OptimizeSize" }

		configuration "vs*"
			defines     { "_CRT_SECURE_NO_WARNINGS" }

		configuration "vs2005"
			defines	{"_CRT_SECURE_NO_DEPRECATE" }

		configuration "windows"
			defines { "_WIN32" }
			links { "ole32" }

		configuration "linux or bsd or hurd"
			defines     { "LUA_USE_POSIX", "LUA_USE_DLOPEN" }
			links       { "m" }
			linkoptions { "-rdynamic" }

		configuration "linux"
			links       { "dl" }

		configuration "hurd"
			links       { "dl" }

		configuration "macosx"
			defines     { "LUA_USE_MACOSX" }
			links       { "CoreServices.framework" }

		configuration { "macosx", "gmake" }
			-- toolset "clang"  (not until a 5.0 binary is available)
			buildoptions { "-mmacosx-version-min=10.4" }
			linkoptions  { "-mmacosx-version-min=10.4" }

		configuration { "solaris" }
			linkoptions { "-Wl,--export-dynamic" }		

		configuration "aix"
			defines     { "LUA_USE_POSIX", "LUA_USE_DLOPEN" }
			links       { "m" }
		configuration()

		
        
	project "utf8"
		targetname  "utf8"
		language    "C"
		kind        "SharedLib"
		flags       { "No64BitChecks", "ExtraWarnings", "StaticRuntime" }

		includedirs { "F:/3rdParty/lua/lua-5.2.3/src" }
		libdirs { "F:/3rdParty/lua/lua-5.2.3/build/bin/release" }

		files {"lutf8lib.c", "utf8conv.h", "utf8conv.c"}

		configuration "windows"
			defines { "WIN32", "LUA_BUILD_AS_DLL" }
		configuration()
		links { "lua52" }	
	
