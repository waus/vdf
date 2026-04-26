import 'dart:ffi';
import 'dart:io';
import 'dart:typed_data';

typedef _CtxNewNative = Pointer<Void> Function(Pointer<Uint8>, IntPtr);
typedef _CtxNewDart = Pointer<Void> Function(Pointer<Uint8>, int);

typedef _CtxFreeNative = Void Function(Pointer<Void>);
typedef _CtxFreeDart = void Function(Pointer<Void>);

typedef _ModPowNative =
    Int32 Function(
      Pointer<Void>,
      Pointer<Uint8>,
      IntPtr,
      Pointer<Uint8>,
      IntPtr,
      Pointer<Pointer<Uint8>>,
      Pointer<IntPtr>,
    );
typedef _ModPowDart =
    int Function(
      Pointer<Void>,
      Pointer<Uint8>,
      int,
      Pointer<Uint8>,
      int,
      Pointer<Pointer<Uint8>>,
      Pointer<IntPtr>,
    );

typedef _CtxProveNative =
    Int32 Function(
      Pointer<Void>,
      Int32,
      Pointer<Uint8>,
      IntPtr,
      Int64,
      Pointer<Pointer<Uint8>>,
      Pointer<IntPtr>,
      Pointer<Pointer<Uint8>>,
      Pointer<IntPtr>,
    );
typedef _CtxProveDart =
    int Function(
      Pointer<Void>,
      int,
      Pointer<Uint8>,
      int,
      int,
      Pointer<Pointer<Uint8>>,
      Pointer<IntPtr>,
      Pointer<Pointer<Uint8>>,
      Pointer<IntPtr>,
    );

typedef _CtxProveStage1Native =
    Int32 Function(
      Pointer<Void>,
      Int32,
      Pointer<Uint8>,
      IntPtr,
      Int64,
      Pointer<Pointer<Void>>,
      Pointer<Pointer<Uint8>>,
      Pointer<IntPtr>,
      Pointer<Int64>,
    );
typedef _CtxProveStage1Dart =
    int Function(
      Pointer<Void>,
      int,
      Pointer<Uint8>,
      int,
      int,
      Pointer<Pointer<Void>>,
      Pointer<Pointer<Uint8>>,
      Pointer<IntPtr>,
      Pointer<Int64>,
    );

typedef _ProveSessionFinishNative =
    Int32 Function(Pointer<Void>, Pointer<Pointer<Uint8>>, Pointer<IntPtr>);
typedef _ProveSessionFinishDart =
    int Function(Pointer<Void>, Pointer<Pointer<Uint8>>, Pointer<IntPtr>);

typedef _ProveSessionFreeNative = Void Function(Pointer<Void>);
typedef _ProveSessionFreeDart = void Function(Pointer<Void>);

typedef _QuotientNative =
    Int32 Function(
      Pointer<Uint8>,
      IntPtr,
      Pointer<Uint8>,
      IntPtr,
      Pointer<Pointer<Uint8>>,
      Pointer<IntPtr>,
    );
typedef _QuotientDart =
    int Function(
      Pointer<Uint8>,
      int,
      Pointer<Uint8>,
      int,
      Pointer<Pointer<Uint8>>,
      Pointer<IntPtr>,
    );

typedef _BufferFreeNative = Void Function(Pointer<Uint8>);
typedef _BufferFreeDart = void Function(Pointer<Uint8>);

typedef _LastErrorNative = Pointer<Utf8Native> Function();
typedef _LastErrorDart = Pointer<Utf8Native> Function();

final class Utf8Native extends Struct {
  @Uint8()
  external int value;
}

final class _NativeAllocator {
  _NativeAllocator._()
    : _malloc = _openAllocator()
          .lookupFunction<
            Pointer<Void> Function(IntPtr),
            Pointer<Void> Function(int)
          >('malloc'),
      _free = _openAllocator()
          .lookupFunction<
            Void Function(Pointer<Void>),
            void Function(Pointer<Void>)
          >('free');

  static final _NativeAllocator instance = _NativeAllocator._();

  final Pointer<Void> Function(int size) _malloc;
  final void Function(Pointer<Void> ptr) _free;

  Pointer<Uint8> copyBytes(Uint8List bytes) {
    final ptr = _malloc(bytes.isEmpty ? 1 : bytes.length);
    if (ptr == nullptr) {
      throw StateError('malloc failed while preparing native call');
    }
    if (bytes.isNotEmpty) {
      final out = ptr.cast<Uint8>().asTypedList(bytes.length);
      out.setAll(0, bytes);
    }
    return ptr.cast<Uint8>();
  }

  Pointer<IntPtr> allocateIntPtr() {
    final ptr = _malloc(sizeOf<IntPtr>());
    if (ptr == nullptr) {
      throw StateError('malloc failed while preparing native call');
    }
    return ptr.cast<IntPtr>();
  }

  Pointer<Pointer<Uint8>> allocatePointer() {
    final ptr = _malloc(sizeOf<Pointer<Uint8>>());
    if (ptr == nullptr) {
      throw StateError('malloc failed while preparing native call');
    }
    return ptr.cast<Pointer<Uint8>>();
  }

  Pointer<Pointer<Void>> allocateVoidPointer() {
    final ptr = _malloc(sizeOf<Pointer<Void>>());
    if (ptr == nullptr) {
      throw StateError('malloc failed while preparing native call');
    }
    return ptr.cast<Pointer<Void>>();
  }

  Pointer<Int64> allocateInt64() {
    final ptr = _malloc(sizeOf<Int64>());
    if (ptr == nullptr) {
      throw StateError('malloc failed while preparing native call');
    }
    return ptr.cast<Int64>();
  }

  void freePtr(Pointer<Void> ptr) {
    if (ptr != nullptr) {
      _free(ptr);
    }
  }

  static DynamicLibrary _openAllocator() {
    if (Platform.isMacOS || Platform.isIOS) {
      return DynamicLibrary.process();
    }
    if (Platform.isWindows) {
      return DynamicLibrary.open('msvcrt.dll');
    }
    if (Platform.isAndroid) {
      return DynamicLibrary.open('libc.so');
    }
    return DynamicLibrary.open('libc.so.6');
  }
}

const String _nativeAssetId = 'package:vdfrsa/src/native/rust_vdf_backend.dart';

abstract interface class _NativeBindings {
  _CtxNewDart get ctxNew;
  _CtxFreeDart get ctxFree;
  _ModPowDart get modPow;
  _CtxProveDart get prove;
  _CtxProveStage1Dart get proveStage1;
  _ProveSessionFinishDart get proveSessionFinish;
  _ProveSessionFreeDart get proveSessionFree;
  _QuotientDart get quotient;
  _BufferFreeDart get bufferFree;
  _LastErrorDart get lastError;
}

final class _DynamicLibraryBindings implements _NativeBindings {
  _DynamicLibraryBindings(DynamicLibrary lib)
    : ctxNew = lib.lookupFunction<_CtxNewNative, _CtxNewDart>('vdfrsa_ctx_new'),
      ctxFree = lib.lookupFunction<_CtxFreeNative, _CtxFreeDart>(
        'vdfrsa_ctx_free',
      ),
      modPow = lib.lookupFunction<_ModPowNative, _ModPowDart>(
        'vdfrsa_ctx_mod_pow',
      ),
      prove = lib.lookupFunction<_CtxProveNative, _CtxProveDart>(
        'vdfrsa_ctx_prove',
      ),
      proveStage1 = lib
          .lookupFunction<_CtxProveStage1Native, _CtxProveStage1Dart>(
            'vdfrsa_ctx_prove_stage1',
          ),
      proveSessionFinish = lib
          .lookupFunction<_ProveSessionFinishNative, _ProveSessionFinishDart>(
            'vdfrsa_prove_session_finish',
          ),
      proveSessionFree = lib
          .lookupFunction<_ProveSessionFreeNative, _ProveSessionFreeDart>(
            'vdfrsa_prove_session_free',
          ),
      quotient = lib.lookupFunction<_QuotientNative, _QuotientDart>(
        'vdfrsa_quotient',
      ),
      bufferFree = lib.lookupFunction<_BufferFreeNative, _BufferFreeDart>(
        'vdfrsa_buffer_free',
      ),
      lastError = lib.lookupFunction<_LastErrorNative, _LastErrorDart>(
        'vdfrsa_last_error',
      );

  @override
  final _CtxNewDart ctxNew;
  @override
  final _CtxFreeDart ctxFree;
  @override
  final _ModPowDart modPow;
  @override
  final _CtxProveDart prove;
  @override
  final _CtxProveStage1Dart proveStage1;
  @override
  final _ProveSessionFinishDart proveSessionFinish;
  @override
  final _ProveSessionFreeDart proveSessionFree;
  @override
  final _QuotientDart quotient;
  @override
  final _BufferFreeDart bufferFree;
  @override
  final _LastErrorDart lastError;
}

final class _BundledNativeBindings implements _NativeBindings {
  const _BundledNativeBindings();

  void probe() {
    bundledLastError();
  }

  @override
  _CtxNewDart get ctxNew => bundledCtxNew;
  @override
  _CtxFreeDart get ctxFree => bundledCtxFree;
  @override
  _ModPowDart get modPow => bundledModPow;
  @override
  _CtxProveDart get prove => bundledProve;
  @override
  _CtxProveStage1Dart get proveStage1 => bundledProveStage1;
  @override
  _ProveSessionFinishDart get proveSessionFinish => bundledProveSessionFinish;
  @override
  _ProveSessionFreeDart get proveSessionFree => bundledProveSessionFree;
  @override
  _QuotientDart get quotient => bundledQuotient;
  @override
  _BufferFreeDart get bufferFree => bundledBufferFree;
  @override
  _LastErrorDart get lastError => bundledLastError;
}

@Native<_CtxNewNative>(symbol: 'vdfrsa_ctx_new', assetId: _nativeAssetId)
external Pointer<Void> bundledCtxNew(Pointer<Uint8> modulus, int modulusLen);

@Native<_CtxFreeNative>(symbol: 'vdfrsa_ctx_free', assetId: _nativeAssetId)
external void bundledCtxFree(Pointer<Void> ctx);

@Native<_ModPowNative>(symbol: 'vdfrsa_ctx_mod_pow', assetId: _nativeAssetId)
external int bundledModPow(
  Pointer<Void> ctx,
  Pointer<Uint8> base,
  int baseLen,
  Pointer<Uint8> exponent,
  int exponentLen,
  Pointer<Pointer<Uint8>> out,
  Pointer<IntPtr> outLen,
);

@Native<_CtxProveNative>(symbol: 'vdfrsa_ctx_prove', assetId: _nativeAssetId)
external int bundledProve(
  Pointer<Void> ctx,
  int k,
  Pointer<Uint8> payload,
  int payloadLen,
  int difficulty,
  Pointer<Pointer<Uint8>> y,
  Pointer<IntPtr> yLen,
  Pointer<Pointer<Uint8>> pi,
  Pointer<IntPtr> piLen,
);

@Native<_CtxProveStage1Native>(
  symbol: 'vdfrsa_ctx_prove_stage1',
  assetId: _nativeAssetId,
)
external int bundledProveStage1(
  Pointer<Void> ctx,
  int k,
  Pointer<Uint8> payload,
  int payloadLen,
  int difficulty,
  Pointer<Pointer<Void>> session,
  Pointer<Pointer<Uint8>> y,
  Pointer<IntPtr> yLen,
  Pointer<Int64> secondWork,
);

@Native<_ProveSessionFinishNative>(
  symbol: 'vdfrsa_prove_session_finish',
  assetId: _nativeAssetId,
)
external int bundledProveSessionFinish(
  Pointer<Void> session,
  Pointer<Pointer<Uint8>> pi,
  Pointer<IntPtr> piLen,
);

@Native<_ProveSessionFreeNative>(
  symbol: 'vdfrsa_prove_session_free',
  assetId: _nativeAssetId,
)
external void bundledProveSessionFree(Pointer<Void> session);

@Native<_QuotientNative>(symbol: 'vdfrsa_quotient', assetId: _nativeAssetId)
external int bundledQuotient(
  Pointer<Uint8> dividend,
  int dividendLen,
  Pointer<Uint8> divisor,
  int divisorLen,
  Pointer<Pointer<Uint8>> out,
  Pointer<IntPtr> outLen,
);

@Native<_BufferFreeNative>(
  symbol: 'vdfrsa_buffer_free',
  assetId: _nativeAssetId,
)
external void bundledBufferFree(Pointer<Uint8> buffer);

@Native<_LastErrorNative>(symbol: 'vdfrsa_last_error', assetId: _nativeAssetId)
external Pointer<Utf8Native> bundledLastError();

final class VdfNativeBackend {
  VdfNativeBackend._(_NativeBindings bindings)
    : _ctxNew = bindings.ctxNew,
      _ctxFree = bindings.ctxFree,
      _modPow = bindings.modPow,
      _prove = bindings.prove,
      _proveStage1 = bindings.proveStage1,
      _proveSessionFinish = bindings.proveSessionFinish,
      _proveSessionFree = bindings.proveSessionFree,
      _quotient = bindings.quotient,
      _bufferFree = bindings.bufferFree,
      _lastError = bindings.lastError;

  final _CtxNewDart _ctxNew;
  final _CtxFreeDart _ctxFree;
  final _ModPowDart _modPow;
  final _CtxProveDart _prove;
  final _CtxProveStage1Dart _proveStage1;
  final _ProveSessionFinishDart _proveSessionFinish;
  final _ProveSessionFreeDart _proveSessionFree;
  final _QuotientDart _quotient;
  final _BufferFreeDart _bufferFree;
  final _LastErrorDart _lastError;

  static VdfNativeBackend? get instance {
    _loadError;
    return _instance;
  }

  static Object? get loadError => _loadError;

  static final Object? _loadError = () {
    try {
      _instance = VdfNativeBackend._(_openBindings());
      return null;
    } catch (e) {
      return e;
    }
  }();
  static VdfNativeBackend? _instance;

  static _NativeBindings _openBindings() {
    final override = Platform.environment['VDFRSA_NATIVE_LIB'];
    if (override != null && override.isNotEmpty) {
      return _DynamicLibraryBindings(DynamicLibrary.open(override));
    }

    final errors = <Object>[];
    try {
      const bundled = _BundledNativeBindings();
      bundled.probe();
      return bundled;
    } catch (e) {
      errors.add(e);
    }

    final names = <String>[
      if (Platform.isMacOS || Platform.isIOS) 'libvdfrsa_native.dylib',
      if (Platform.isLinux || Platform.isAndroid) 'libvdfrsa_native.so',
      if (Platform.isWindows) 'vdfrsa_native.dll',
    ];

    Object? lastError;
    for (final name in names) {
      try {
        return _DynamicLibraryBindings(DynamicLibrary.open(name));
      } catch (e) {
        lastError = e;
      }
    }
    if (lastError != null) {
      errors.add(lastError);
    }

    throw StateError('failed to load native backend: ${errors.join('; ')}');
  }

  NativeModulusContext createModulusContext(Uint8List modulus) {
    final allocator = _NativeAllocator.instance;
    final modulusPtr = allocator.copyBytes(modulus);
    try {
      final ctx = _ctxNew(modulusPtr, modulus.length);
      if (ctx == nullptr) {
        throw StateError(_readLastError());
      }
      return NativeModulusContext._(this, ctx);
    } finally {
      allocator.freePtr(modulusPtr.cast<Void>());
    }
  }

  BigInt quotient(BigInt dividend, BigInt divisor) {
    final dividendBytes = _encodeBigInt(dividend);
    final divisorBytes = _encodeBigInt(divisor);
    final allocator = _NativeAllocator.instance;
    final dividendPtr = allocator.copyBytes(dividendBytes);
    final divisorPtr = allocator.copyBytes(divisorBytes);
    final outPtr = allocator.allocatePointer();
    final outLen = allocator.allocateIntPtr();

    try {
      final rc = _quotient(
        dividendPtr,
        dividendBytes.length,
        divisorPtr,
        divisorBytes.length,
        outPtr,
        outLen,
      );
      if (rc != 0) {
        throw StateError(_readLastError());
      }
      return _decodeBigIntAndFree(outPtr.value, outLen.value);
    } finally {
      allocator.freePtr(dividendPtr.cast<Void>());
      allocator.freePtr(divisorPtr.cast<Void>());
      allocator.freePtr(outPtr.cast<Void>());
      allocator.freePtr(outLen.cast<Void>());
    }
  }

  BigInt modPow(Pointer<Void> ctx, BigInt base, BigInt exponent) {
    final baseBytes = _encodeBigInt(base);
    final expBytes = _encodeBigInt(exponent);
    final allocator = _NativeAllocator.instance;
    final basePtr = allocator.copyBytes(baseBytes);
    final expPtr = allocator.copyBytes(expBytes);
    final outPtr = allocator.allocatePointer();
    final outLen = allocator.allocateIntPtr();

    try {
      final rc = _modPow(
        ctx,
        basePtr,
        baseBytes.length,
        expPtr,
        expBytes.length,
        outPtr,
        outLen,
      );
      if (rc != 0) {
        throw StateError(_readLastError());
      }
      return _decodeBigIntAndFree(outPtr.value, outLen.value);
    } finally {
      allocator.freePtr(basePtr.cast<Void>());
      allocator.freePtr(expPtr.cast<Void>());
      allocator.freePtr(outPtr.cast<Void>());
      allocator.freePtr(outLen.cast<Void>());
    }
  }

  NativeProof prove(
    Pointer<Void> ctx,
    Uint8List payload,
    int difficulty,
    int k,
  ) {
    final allocator = _NativeAllocator.instance;
    final payloadPtr = allocator.copyBytes(payload);
    final yPtr = allocator.allocatePointer();
    final yLen = allocator.allocateIntPtr();
    final piPtr = allocator.allocatePointer();
    final piLen = allocator.allocateIntPtr();

    try {
      final rc = _prove(
        ctx,
        k,
        payloadPtr,
        payload.length,
        difficulty,
        yPtr,
        yLen,
        piPtr,
        piLen,
      );
      if (rc != 0) {
        throw StateError(_readLastError());
      }
      return NativeProof(
        y: _copyBytesAndFree(yPtr.value, yLen.value),
        pi: _copyBytesAndFree(piPtr.value, piLen.value),
      );
    } finally {
      allocator.freePtr(payloadPtr.cast<Void>());
      allocator.freePtr(yPtr.cast<Void>());
      allocator.freePtr(yLen.cast<Void>());
      allocator.freePtr(piPtr.cast<Void>());
      allocator.freePtr(piLen.cast<Void>());
    }
  }

  NativeStageOne proveStage1(
    Pointer<Void> ctx,
    Uint8List payload,
    int difficulty,
    int k,
  ) {
    final allocator = _NativeAllocator.instance;
    final payloadPtr = allocator.copyBytes(payload);
    final sessionPtr = allocator.allocateVoidPointer();
    final yPtr = allocator.allocatePointer();
    final yLen = allocator.allocateIntPtr();
    final secondWorkPtr = allocator.allocateInt64();

    try {
      final rc = _proveStage1(
        ctx,
        k,
        payloadPtr,
        payload.length,
        difficulty,
        sessionPtr,
        yPtr,
        yLen,
        secondWorkPtr,
      );
      if (rc != 0) {
        throw StateError(_readLastError());
      }
      return NativeStageOne(
        session: NativeProveSession._(this, sessionPtr.value),
        y: _copyBytesAndFree(yPtr.value, yLen.value),
        secondWork: secondWorkPtr.value,
      );
    } finally {
      allocator.freePtr(payloadPtr.cast<Void>());
      allocator.freePtr(sessionPtr.cast<Void>());
      allocator.freePtr(yPtr.cast<Void>());
      allocator.freePtr(yLen.cast<Void>());
      allocator.freePtr(secondWorkPtr.cast<Void>());
    }
  }

  Uint8List proveSessionFinish(Pointer<Void> session) {
    final allocator = _NativeAllocator.instance;
    final piPtr = allocator.allocatePointer();
    final piLen = allocator.allocateIntPtr();

    try {
      final rc = _proveSessionFinish(session, piPtr, piLen);
      if (rc != 0) {
        throw StateError(_readLastError());
      }
      return _copyBytesAndFree(piPtr.value, piLen.value);
    } finally {
      allocator.freePtr(piPtr.cast<Void>());
      allocator.freePtr(piLen.cast<Void>());
    }
  }

  void freeContext(Pointer<Void> ctx) {
    _ctxFree(ctx);
  }

  void freeProveSession(Pointer<Void> session) {
    _proveSessionFree(session);
  }

  String _readLastError() {
    final ptr = _lastError();
    if (ptr == nullptr) {
      return 'native backend call failed';
    }

    final bytes = <int>[];
    var offset = 0;
    while (true) {
      final value = (ptr + offset).ref.value;
      if (value == 0) {
        break;
      }
      bytes.add(value);
      offset++;
    }
    return String.fromCharCodes(bytes);
  }

  BigInt _decodeBigIntAndFree(Pointer<Uint8> ptr, int length) {
    try {
      final bytes = Uint8List.fromList(ptr.asTypedList(length));
      return _decodeBigInt(bytes);
    } finally {
      _bufferFree(ptr);
    }
  }

  Uint8List _copyBytesAndFree(Pointer<Uint8> ptr, int length) {
    try {
      return Uint8List.fromList(ptr.asTypedList(length));
    } finally {
      _bufferFree(ptr);
    }
  }
}

final class NativeModulusContext {
  NativeModulusContext._(this._backend, this._ctx) {
    _finalizer.attach(this, _NativeContextToken(_backend, _ctx), detach: this);
  }

  final VdfNativeBackend _backend;
  final Pointer<Void> _ctx;

  static final Finalizer<_NativeContextToken> _finalizer =
      Finalizer<_NativeContextToken>((token) {
        token.backend.freeContext(token.ctx);
      });

  bool _closed = false;

  BigInt modPow(BigInt base, BigInt exponent) {
    if (_closed) {
      throw StateError('native modulus context is closed');
    }
    return _backend.modPow(_ctx, base, exponent);
  }

  NativeProof prove(Uint8List payload, int difficulty, int k) {
    if (_closed) {
      throw StateError('native modulus context is closed');
    }
    return _backend.prove(_ctx, payload, difficulty, k);
  }

  NativeStageOne proveStage1(Uint8List payload, int difficulty, int k) {
    if (_closed) {
      throw StateError('native modulus context is closed');
    }
    return _backend.proveStage1(_ctx, payload, difficulty, k);
  }

  void close() {
    if (_closed) {
      return;
    }
    _closed = true;
    _finalizer.detach(this);
    _backend.freeContext(_ctx);
  }
}

final class _NativeContextToken {
  const _NativeContextToken(this.backend, this.ctx);

  final VdfNativeBackend backend;
  final Pointer<Void> ctx;
}

final class NativeProof {
  NativeProof({required Uint8List y, required Uint8List pi})
    : y = Uint8List.fromList(y),
      pi = Uint8List.fromList(pi);

  final Uint8List y;
  final Uint8List pi;
}

final class NativeStageOne {
  NativeStageOne({
    required this.session,
    required Uint8List y,
    required this.secondWork,
  }) : y = Uint8List.fromList(y);

  final NativeProveSession session;
  final Uint8List y;
  final int secondWork;
}

final class NativeProveSession {
  NativeProveSession._(this._backend, this._session);

  final VdfNativeBackend _backend;
  Pointer<Void> _session;
  bool _closed = false;

  Uint8List finish() {
    if (_closed) {
      throw StateError('native prove session is closed');
    }
    return _backend.proveSessionFinish(_session);
  }

  void close() {
    if (_closed) {
      return;
    }
    _closed = true;
    _backend.freeProveSession(_session);
    _session = nullptr;
  }
}

Uint8List _encodeBigInt(BigInt value) {
  if (value < BigInt.zero) {
    throw ArgumentError('native backend only supports non-negative integers');
  }
  if (value == BigInt.zero) {
    return Uint8List.fromList(const <int>[0]);
  }

  final bytes = <int>[];
  var current = value;
  while (current > BigInt.zero) {
    bytes.add((current & BigInt.from(0xff)).toInt());
    current >>= 8;
  }
  return Uint8List.fromList(bytes.reversed.toList(growable: false));
}

BigInt _decodeBigInt(Uint8List bytes) {
  var value = BigInt.zero;
  for (final byte in bytes) {
    value = (value << 8) | BigInt.from(byte);
  }
  return value;
}
