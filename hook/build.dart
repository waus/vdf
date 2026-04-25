import 'dart:io';

import 'package:code_assets/code_assets.dart';
import 'package:hooks/hooks.dart';
import 'package:native_toolchain_c/native_toolchain_c.dart';

const _libraryName = 'vdfrsa_native';
const _assetName = 'src/native/openssl_vdf_backend.dart';

void main(List<String> args) async {
  await build(args, (input, output) async {
    if (!input.config.buildCodeAssets) {
      return;
    }

    final code = input.config.code;
    if (code.targetOS != OS.macOS &&
        code.targetOS != OS.linux &&
        code.targetOS != OS.windows) {
      return;
    }

    if (code.targetOS == OS.macOS &&
        code.targetArchitecture != Architecture.arm64) {
      throw UnsupportedError(
        'vdfrsa native backend supports macOS arm64, got '
        '${code.targetArchitecture.name}.',
      );
    }

    final openssl = await _discoverOpenSsl(code.targetOS);
    final builder = CBuilder.library(
      name: _libraryName,
      assetName: _assetName,
      sources: ['native/openssl_vdf.c', ...openssl.extraSources],
      includes: ['native', ...openssl.includeDirectories],
      libraries: openssl.libraries,
      libraryDirectories: openssl.libraryDirectories,
      flags: openssl.flags,
      linkModePreference: LinkModePreference.dynamic,
      std: 'c11',
    );

    await builder.run(input: input, output: output);
  });
}

Future<_OpenSslConfig> _discoverOpenSsl(OS targetOS) async {
  if (targetOS == OS.windows) {
    final pkgConfig = await _pkgConfigOpenSsl(targetOS);
    if (pkgConfig != null) {
      return pkgConfig;
    }

    final config = _discoverWindowsOpenSsl();
    if (config != null) {
      return config;
    }

    return const _OpenSslConfig(libraries: ['libcrypto']);
  }

  if (targetOS == OS.macOS) {
    for (final prefix in const [
      '/opt/homebrew/opt/openssl@3',
      '/usr/local/opt/openssl@3',
    ]) {
      final includeDir = Directory('$prefix/include');
      final libDir = Directory('$prefix/lib');
      final staticCrypto = File('${libDir.path}/libcrypto.a');
      if (includeDir.existsSync() && staticCrypto.existsSync()) {
        return _OpenSslConfig(
          includeDirectories: [includeDir.path],
          extraSources: [staticCrypto.path],
          libraries: const [],
        );
      }
    }
  }

  final pkgConfig = await _pkgConfigOpenSsl(targetOS);
  if (pkgConfig != null) {
    return pkgConfig;
  }

  return const _OpenSslConfig(libraries: ['crypto']);
}

_OpenSslConfig? _discoverWindowsOpenSsl() {
  final roots = <String>[
    if (Platform.environment['OPENSSL_ROOT'] case final root?)
      if (root.isNotEmpty) root,
    r'C:\Program Files\OpenSSL',
    r'C:\Program Files\OpenSSL-Win64',
    r'C:\OpenSSL',
    r'C:\OpenSSL-Win64',
    r'C:\tools\OpenSSL',
    r'C:\tools\OpenSSL-Win64',
  ];

  for (final root in roots) {
    final includeDir = Directory('$root\\include');
    final header = File('${includeDir.path}\\openssl\\bn.h');
    final importLibrary = _findWindowsImportLibrary(root);
    if (header.existsSync() && importLibrary != null) {
      return _OpenSslConfig(
        includeDirectories: [includeDir.path],
        libraryDirectories: [importLibrary.parent.path],
        libraries: const ['libcrypto'],
        flags: ['/I${includeDir.path}'],
      );
    }
  }

  return null;
}

File? _findWindowsImportLibrary(String root) {
  final libDir = Directory('$root\\lib');
  if (!libDir.existsSync()) {
    return null;
  }

  final direct = File('${libDir.path}\\libcrypto.lib');
  if (direct.existsSync()) {
    return direct;
  }

  return libDir
      .listSync(recursive: true, followLinks: false)
      .whereType<File>()
      .where((file) => file.path.toLowerCase().endsWith('\\libcrypto.lib'))
      .cast<File?>()
      .firstWhere((file) => file != null, orElse: () => null);
}

Future<_OpenSslConfig?> _pkgConfigOpenSsl(OS targetOS) async {
  final ProcessResult result;
  try {
    result = await Process.run('pkg-config', const [
      '--cflags',
      '--libs',
      'openssl',
    ]);
  } on ProcessException {
    return null;
  }
  if (result.exitCode != 0) {
    return null;
  }

  final tokens = _splitShellWords('${result.stdout}'.trim());
  final includes = <String>[];
  final libraryDirectories = <String>[];
  final libraries = <String>[];
  final flags = <String>[];

  for (var i = 0; i < tokens.length; i++) {
    final token = tokens[i];
    if (token == '-I' && i + 1 < tokens.length) {
      includes.add(tokens[++i]);
    } else if (token.startsWith('-I') && token.length > 2) {
      includes.add(token.substring(2));
    } else if (token == '/I' && i + 1 < tokens.length) {
      includes.add(tokens[++i]);
    } else if (token.startsWith('/I') && token.length > 2) {
      includes.add(token.substring(2));
    } else if (token == '-L' && i + 1 < tokens.length) {
      libraryDirectories.add(tokens[++i]);
    } else if (token.startsWith('-L') && token.length > 2) {
      libraryDirectories.add(token.substring(2));
    } else if (token == '-l' && i + 1 < tokens.length) {
      final library = tokens[++i];
      final normalizedLibrary = _normalizeLibraryName(targetOS, library);
      if (_isOpenSslCryptoLibrary(normalizedLibrary)) {
        libraries.add(normalizedLibrary);
      }
    } else if (token.startsWith('-l') && token.length > 2) {
      final library = token.substring(2);
      final normalizedLibrary = _normalizeLibraryName(targetOS, library);
      if (_isOpenSslCryptoLibrary(normalizedLibrary)) {
        libraries.add(normalizedLibrary);
      }
    } else if (token.isNotEmpty) {
      flags.add(token);
    }
  }

  final defaultLibrary = targetOS == OS.windows ? 'libcrypto' : 'crypto';
  if (!libraries.contains(defaultLibrary)) {
    libraries.add(defaultLibrary);
  }

  return _OpenSslConfig(
    includeDirectories: includes,
    libraryDirectories: libraryDirectories,
    libraries: libraries,
    flags: flags,
  );
}

String _normalizeLibraryName(OS targetOS, String library) {
  if (targetOS == OS.windows && library == 'crypto') {
    return 'libcrypto';
  }
  return library;
}

bool _isOpenSslCryptoLibrary(String library) {
  return library == 'crypto' || library == 'libcrypto';
}

List<String> _splitShellWords(String input) {
  if (input.isEmpty) {
    return const [];
  }

  final words = <String>[];
  final current = StringBuffer();
  var inSingle = false;
  var inDouble = false;
  var escaping = false;

  for (final rune in input.runes) {
    final char = String.fromCharCode(rune);
    if (escaping) {
      current.write(char);
      escaping = false;
      continue;
    }
    if (char == r'\') {
      escaping = true;
      continue;
    }
    if (char == "'" && !inDouble) {
      inSingle = !inSingle;
      continue;
    }
    if (char == '"' && !inSingle) {
      inDouble = !inDouble;
      continue;
    }
    if (!inSingle && !inDouble && char.trim().isEmpty) {
      if (current.isNotEmpty) {
        words.add(current.toString());
        current.clear();
      }
      continue;
    }
    current.write(char);
  }

  if (current.isNotEmpty) {
    words.add(current.toString());
  }
  return words;
}

final class _OpenSslConfig {
  const _OpenSslConfig({
    this.includeDirectories = const [],
    this.libraryDirectories = const [],
    this.libraries = const ['crypto'],
    this.flags = const [],
    this.extraSources = const [],
  });

  final List<String> includeDirectories;
  final List<String> libraryDirectories;
  final List<String> libraries;
  final List<String> flags;
  final List<String> extraSources;
}
