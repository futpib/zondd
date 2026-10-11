import 'package:yaml/yaml.dart';
import 'package:yaml_edit/yaml_edit.dart';

String jsonAsYaml(Object? value) {
  final controls = RegExp(
    r'[\x00-\x09\x0b-\x1f\x7f-\x9f\u2028-\u202e\u2066-\u2069]',
  );
  Object? styled(Object? value) => switch (value) {
    Map value => {
      for (final entry in value.entries) styled(entry.key): styled(entry.value),
    },
    List value => value.map(styled).toList(),
    String value when controls.hasMatch(value) => wrapAsYamlNode(
      value,
      scalarStyle: ScalarStyle.DOUBLE_QUOTED,
    ),
    String value when value.contains('\n') => wrapAsYamlNode(
      value,
      scalarStyle: ScalarStyle.LITERAL,
    ),
    _ => value,
  };
  final editor = YamlEditor('')..update([], styled(value));
  // yaml_edit handles YAML syntax. Make any remaining invisible controls
  // visible for review; their containing scalars are always double quoted.
  return editor.toString().replaceAllMapped(
    controls,
    (m) => r'\u' + m[0]!.codeUnitAt(0).toRadixString(16).padLeft(4, '0'),
  );
}
