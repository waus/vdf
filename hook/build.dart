import 'dart:io';

import 'package:code_assets/code_assets.dart';
import 'package:hooks/hooks.dart';

const _crateName = 'optimized_vdf';
const _libraryName = 'vdfrsa_native';
const _assetName = 'src/native/rust_vdf_backend.dart';

void main(List<String> args) async {
  await build(args, (input, output) async {
    if (!input.config.buildCodeAssets) {
      return;
    }

    final code = input.config.code;
    final target = _rustTarget(code);
    final targetDir = Directory.fromUri(input.outputDirectory.resolve('cargo/'))
      ..createSync(recursive: true);

    final cargoConfig = _cargoConfig(code, target);
    final environment = _cargoEnvironment(cargoConfig);
    if (cargoConfig != null) {
      stderr.writeln(
        'vdfrsa: building Rust native backend for $target '
        'with linker ${cargoConfig.linker}',
      );
    } else {
      stderr.writeln('vdfrsa: building Rust native backend for $target');
    }
    final result = await Process.run(
      'cargo',
      <String>[
        'build',
        '--release',
        '--lib',
        '--target',
        target,
        '--target-dir',
        targetDir.path,
      ],
      workingDirectory: input.packageRoot.toFilePath(),
      environment: environment,
    );

    if (result.exitCode != 0) {
      throw StateError(
        'Rust native backend build failed for $target\n'
        'stdout:\n${result.stdout}\n'
        'stderr:\n${result.stderr}',
      );
    }

    final source = File(
      _cargoLibraryPath(targetDir.path, target, code.targetOS),
    );
    if (!source.existsSync()) {
      throw StateError('Rust build did not produce ${source.path}');
    }

    final assetFileName = code.targetOS.libraryFileName(
      _libraryName,
      DynamicLoadingBundled(),
    );
    final asset = File.fromUri(input.outputDirectory.resolve(assetFileName));
    asset.parent.createSync(recursive: true);
    source.copySync(asset.path);

    output.dependencies.add(Uri.file('Cargo.toml'));
    output.dependencies.add(Uri.file('Cargo.lock'));
    output.dependencies.add(Uri.file('src/lib.rs'));
    output.assets.code.add(
      CodeAsset(
        package: input.packageName,
        name: _assetName,
        file: asset.uri,
        linkMode: DynamicLoadingBundled(),
      ),
    );
  });
}

String _rustTarget(CodeConfig code) {
  final os = code.targetOS;
  final arch = code.targetArchitecture;

  if (os == OS.macOS) {
    if (arch == Architecture.arm64) return 'aarch64-apple-darwin';
    if (arch == Architecture.x64) return 'x86_64-apple-darwin';
  }
  if (os == OS.windows) {
    if (arch == Architecture.x64) return 'x86_64-pc-windows-msvc';
    if (arch == Architecture.arm64) return 'aarch64-pc-windows-msvc';
  }
  if (os == OS.linux) {
    if (arch == Architecture.x64) return 'x86_64-unknown-linux-gnu';
    if (arch == Architecture.arm64) return 'aarch64-unknown-linux-gnu';
  }
  if (os == OS.android) {
    if (arch == Architecture.arm64) return 'aarch64-linux-android';
    if (arch == Architecture.arm) return 'armv7-linux-androideabi';
    if (arch == Architecture.x64) return 'x86_64-linux-android';
  }
  if (os == OS.iOS) {
    final sdk = code.iOS.targetSdk;
    if (sdk == IOSSdk.iPhoneOS && arch == Architecture.arm64) {
      return 'aarch64-apple-ios';
    }
    if (sdk == IOSSdk.iPhoneSimulator && arch == Architecture.arm64) {
      return 'aarch64-apple-ios-sim';
    }
    if (sdk == IOSSdk.iPhoneSimulator && arch == Architecture.x64) {
      return 'x86_64-apple-ios';
    }
  }

  throw UnsupportedError(
    'Unsupported Rust native target: ${os.name}/${arch.name}',
  );
}

String _cargoLibraryPath(String targetDir, String target, OS os) {
  final fileName = switch (os) {
    OS.windows => '$_crateName.dll',
    OS.macOS || OS.iOS => 'lib$_crateName.dylib',
    _ => 'lib$_crateName.so',
  };
  return '$targetDir/$target/release/$fileName';
}

Map<String, String>? _cargoEnvironment(_CargoConfig? cargoConfig) {
  if (cargoConfig == null) return null;

  final environment = <String, String>{
    'CARGO_HOME': cargoConfig.cargoHome.path,
  };
  environment.addAll(cargoConfig.environment);
  return environment;
}

_CargoConfig? _cargoConfig(CodeConfig code, String target) {
  if (code.targetOS != OS.android) return null;

  final ndk = _androidNdkRoot();
  if (ndk == null || ndk.isEmpty) {
    throw StateError(
      'Android NDK was not found. Set ANDROID_NDK_HOME or ANDROID_NDK_ROOT.',
    );
  }

  final host = switch (OS.current) {
    OS.macOS => 'darwin-x86_64',
    OS.linux => 'linux-x86_64',
    OS.windows => 'windows-x86_64',
    _ => throw UnsupportedError(
      'Android Rust cross-build is not supported from ${OS.current.name}',
    ),
  };
  final bin = '$ndk/toolchains/llvm/prebuilt/$host/bin';
  final api = code.android.targetNdkApi;
  final linker = switch (target) {
    'aarch64-linux-android' => '$bin/aarch64-linux-android$api-clang',
    'armv7-linux-androideabi' => '$bin/armv7a-linux-androideabi$api-clang',
    'x86_64-linux-android' => '$bin/x86_64-linux-android$api-clang',
    _ => null,
  };
  if (linker == null) {
    throw UnsupportedError('Unsupported Android Rust target: $target');
  }
  if (!File(linker).existsSync()) {
    throw StateError('Android Rust linker was not found: $linker');
  }

  final keyTarget = target.toUpperCase().replaceAll('-', '_');
  final cargoHome = Directory.systemTemp.createTempSync('vdfrsa-cargo-home-');
  final cargoConfig = File('${cargoHome.path}/config.toml');
  cargoConfig.writeAsStringSync('''
[target.$target]
linker = "$linker"
''');

  return _CargoConfig(
    cargoHome: cargoHome,
    linker: linker,
    environment: <String, String>{'CARGO_TARGET_${keyTarget}_LINKER': linker},
  );
}

String? _androidNdkRoot() {
  final explicit =
      Platform.environment['ANDROID_NDK_HOME'] ??
      Platform.environment['ANDROID_NDK_ROOT'];
  if (explicit != null &&
      explicit.isNotEmpty &&
      Directory(explicit).existsSync()) {
    return explicit;
  }

  final sdk =
      Platform.environment['ANDROID_HOME'] ??
      Platform.environment['ANDROID_SDK_ROOT'];
  if (sdk == null || sdk.isEmpty) {
    return null;
  }

  final ndkDir = Directory('$sdk/ndk');
  if (!ndkDir.existsSync()) {
    return null;
  }
  final versions =
      ndkDir.listSync().whereType<Directory>().map((dir) => dir.path).toList()
        ..sort(_compareVersionPaths);
  return versions.isEmpty ? null : versions.last;
}

int _compareVersionPaths(String a, String b) {
  return _compareVersions(_lastPathSegment(a), _lastPathSegment(b));
}

int _compareVersions(String a, String b) {
  final aParts = a.split('.').map((part) => int.tryParse(part) ?? 0).toList();
  final bParts = b.split('.').map((part) => int.tryParse(part) ?? 0).toList();
  final length = aParts.length > bParts.length ? aParts.length : bParts.length;
  for (var i = 0; i < length; i++) {
    final aPart = i < aParts.length ? aParts[i] : 0;
    final bPart = i < bParts.length ? bParts[i] : 0;
    if (aPart != bPart) return aPart.compareTo(bPart);
  }
  return a.compareTo(b);
}

String _lastPathSegment(String path) {
  final normalized = path.replaceAll('\\', '/');
  final slash = normalized.lastIndexOf('/');
  return slash == -1 ? normalized : normalized.substring(slash + 1);
}

final class _CargoConfig {
  const _CargoConfig({
    required this.cargoHome,
    required this.linker,
    required this.environment,
  });

  final Directory cargoHome;
  final String linker;
  final Map<String, String> environment;
}
