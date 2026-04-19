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

  final pkgConfig = await _pkgConfigOpenSsl();
  if (pkgConfig != null) {
    return pkgConfig;
  }

  if (targetOS == OS.windows) {
    return const _OpenSslConfig(libraries: ['libcrypto']);
  }

  return const _OpenSslConfig(libraries: ['crypto']);
}

Future<_OpenSslConfig?> _pkgConfigOpenSsl() async {
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
    } else if (token == '-L' && i + 1 < tokens.length) {
      libraryDirectories.add(tokens[++i]);
    } else if (token.startsWith('-L') && token.length > 2) {
      libraryDirectories.add(token.substring(2));
    } else if (token == '-l' && i + 1 < tokens.length) {
      final library = tokens[++i];
      if (library == 'crypto') {
        libraries.add(library);
      }
    } else if (token.startsWith('-l') && token.length > 2) {
      final library = token.substring(2);
      if (library == 'crypto') {
        libraries.add(library);
      }
    } else if (token.isNotEmpty) {
      flags.add(token);
    }
  }

  if (!libraries.contains('crypto')) {
    libraries.add('crypto');
  }

  return _OpenSslConfig(
    includeDirectories: includes,
    libraryDirectories: libraryDirectories,
    libraries: libraries,
    flags: flags,
  );
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
