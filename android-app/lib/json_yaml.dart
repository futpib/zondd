import 'dart:convert';

// JSON-quoted scalars preserve types and make control characters visible in
// YAML. Escape the additional characters YAML treats as line breaks/controls.
String jsonAsYaml(Object? value) {
  final lines = <String>[];
  final yamlControls = RegExp(
    r'[\x7f-\x9f\u2028\u2029\u202a-\u202e\u2066-\u2069]',
  );
  String scalar(Object? value) => jsonEncode(value).replaceAllMapped(
    yamlControls,
    (m) => r'\u' + m[0]!.codeUnitAt(0).toRadixString(16).padLeft(4, '0'),
  );
  bool collection(Object? value) =>
      (value is Map && value.isNotEmpty) || (value is List && value.isNotEmpty);

  void write(Object? value, int depth) {
    final indent = '  ' * depth;
    if (value is Map && value.isNotEmpty) {
      for (final entry in value.entries) {
        final key = scalar(entry.key);
        if (collection(entry.value)) {
          lines.add('$indent$key:');
          write(entry.value, depth + 1);
        } else {
          lines.add('$indent$key: ${scalar(entry.value)}');
        }
      }
    } else if (value is List && value.isNotEmpty) {
      for (final item in value) {
        if (collection(item)) {
          lines.add('$indent-');
          write(item, depth + 1);
        } else {
          lines.add('$indent- ${scalar(item)}');
        }
      }
    } else {
      lines.add('$indent${scalar(value)}');
    }
  }

  write(value, 0);
  return '${lines.join('\n')}\n';
}
