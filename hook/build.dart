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

    final environment = _cargoEnvironment(code, target);
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

Map<String, String>? _cargoEnvironment(CodeConfig code, String target) {
  if (code.targetOS != OS.android) {
    return null;
  }

  final ndk =
      Platform.environment['ANDROID_NDK_HOME'] ??
      Platform.environment['ANDROID_NDK_ROOT'];
  if (ndk == null || ndk.isEmpty) {
    return null;
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
    return null;
  }

  final keyTarget = target.toUpperCase().replaceAll('-', '_');
  return <String, String>{'CARGO_TARGET_${keyTarget}_LINKER': linker};
}
