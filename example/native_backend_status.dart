import 'package:vdfrsa/vdf.dart';

void main() {
  final w = Wesolowski.create(128, 32);
  print(w.hasNativeBackend);
  if (!w.hasNativeBackend && VdfNativeBackend.loadError != null) {
    print(VdfNativeBackend.loadError);
  }
}
